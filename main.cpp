#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_set>

#define DEFAULT_QUEUE_NUM 0

typedef struct {
	std::unordered_set<std::string> *block_hosts;
	uint16_t queue_num;
} app_config;

static long get_rss_kb(void) {
	FILE *fp = fopen("/proc/self/status", "r");
	char line[256];
	long rss_kb = -1;

	if (fp == NULL) {
		return -1;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (sscanf(line, "VmRSS: %ld kB", &rss_kb) == 1) {
			break;
		}
	}

	fclose(fp);
	return rss_kb;
}

static uint32_t get_packet_id(struct nfq_data *nfa) {
	struct nfqnl_msg_packet_hdr *packet_header = nfq_get_msg_packet_hdr(nfa);

	if (packet_header == NULL) {
		return 0;
	}

	return ntohl(packet_header->packet_id);
}

static int is_http_method(const unsigned char *payload, int payload_len) {
	static const char *methods[] = {
		"GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
		"OPTIONS ", "PATCH ", "CONNECT ", "TRACE "
	};
	size_t i;

	for (i = 0; i < sizeof(methods) / sizeof(methods[0]); ++i) {
		size_t method_len = strlen(methods[i]);

		if (payload_len >= (int)method_len &&
		    memcmp(payload, methods[i], method_len) == 0) {
			return 1;
		}
	}

	return 0;
}

static const unsigned char *find_case_insensitive(const unsigned char *buffer,
						  int buffer_len,
						  const char *needle) {
	size_t needle_len;
	int i;

	if (buffer == NULL || needle == NULL) {
		return NULL;
	}

	needle_len = strlen(needle);
	if (needle_len == 0 || buffer_len < (int)needle_len) {
		return NULL;
	}

	for (i = 0; i <= buffer_len - (int)needle_len; ++i) {
		if (strncasecmp((const char *)(buffer + i), needle, needle_len) == 0) {
			return buffer + i;
		}
	}

	return NULL;
}

static int extract_host_header(const unsigned char *payload, int payload_len,
			       char *host, size_t host_len) {
	const char *host_key = "\r\nHost:";
	const unsigned char *payload_end = payload + payload_len;
	const unsigned char *cursor;

	if (payload == NULL || payload_len <= 0 || host == NULL || host_len == 0) {
		return 0;
	}

	host[0] = '\0';

	if (payload_len >= 5 && strncasecmp((const char *)payload, "Host:", 5) == 0) {
		cursor = payload;
	} else {
		cursor = find_case_insensitive(payload, payload_len, host_key);
		if (cursor == NULL) {
			return 0;
		}
		cursor += 2;
	}

	cursor += 5;
	while (cursor < payload_end && (*cursor == ' ' || *cursor == '\t')) {
		++cursor;
	}

	{
		size_t index = 0;

		while (cursor < payload_end && *cursor != '\r' && *cursor != '\n') {
			if (index + 1 >= host_len) {
				return 0;
			}
			host[index++] = (char)*cursor++;
		}
		host[index] = '\0';
	}

	if (host[0] == '\0') {
		return 0;
	}

	return 1;
}

static void normalize_host(char *host) {
	char *port_separator;
	size_t len;

	if (host == NULL) {
		return;
	}

	len = strlen(host);
	while (len > 0 && isspace((unsigned char)host[len - 1])) {
		host[--len] = '\0';
	}

	while (*host == ' ' || *host == '\t') {
		memmove(host, host + 1, strlen(host));
	}

	for (size_t i = 0; host[i] != '\0'; ++i) {
		host[i] = (char)tolower((unsigned char)host[i]);
	}

	port_separator = strchr(host, ':');
	if (port_separator != NULL) {
		*port_separator = '\0';
	}
}

static std::string normalize_line(std::string line) {
	if (!line.empty() && line.back() == '\r') {
		line.pop_back();
	}

	size_t comma_pos = line.find(',');
	if (comma_pos != std::string::npos) {
		line = line.substr(comma_pos + 1);
	}

	while (!line.empty() && isspace((unsigned char)line.front())) {
		line.erase(line.begin());
	}

	while (!line.empty() && isspace((unsigned char)line.back())) {
		line.pop_back();
	}

	if (line.size() >= 2 && line.front() == '"' && line.back() == '"') {
		line = line.substr(1, line.size() - 2);
	}

	std::transform(line.begin(), line.end(), line.begin(),
		       [](unsigned char c) { return (char)tolower(c); });

	size_t port_pos = line.find(':');
	if (port_pos != std::string::npos) {
		line = line.substr(0, port_pos);
	}

	return line;
}

static int load_block_hosts(const char *file_name,
			    std::unordered_set<std::string> *block_hosts) {
	std::ifstream file(file_name);
	std::string line;

	if (!file.is_open()) {
		perror("file open failed");
		return 0;
	}

	block_hosts->reserve(1000000);

	while (std::getline(file, line)) {
		std::string host = normalize_line(line);

		if (!host.empty()) {
			block_hosts->insert(host);
		}
	}

	return 1;
}

static int is_blocked_host(const std::unordered_set<std::string> *block_hosts,
			   const char *host) {
	if (block_hosts->find(host) != block_hosts->end()) {
		return 1;
	}

	if (strncmp(host, "www.", 4) == 0) {
		if (block_hosts->find(host + 4) != block_hosts->end()) {
			return 1;
		}
	}

	return 0;
}

static int should_block_http_host(const unsigned char *packet, int packet_len,
				  const std::unordered_set<std::string> *block_hosts,
				  char *found_host, size_t found_host_len) {
	const struct iphdr *ip_header;
	const struct tcphdr *tcp_header;
	const unsigned char *tcp_payload;
	int ip_header_len;
	int tcp_header_len;
	int tcp_payload_len;
	char host[256];

	if (packet == NULL || packet_len < (int)sizeof(struct iphdr)) {
		return 0;
	}

	ip_header = (const struct iphdr *)packet;
	if (ip_header->version != 4 || ip_header->protocol != IPPROTO_TCP) {
		return 0;
	}

	ip_header_len = ip_header->ihl * 4;
	if (ip_header_len < (int)sizeof(struct iphdr) || packet_len < ip_header_len) {
		return 0;
	}

	tcp_header = (const struct tcphdr *)(packet + ip_header_len);
	if (packet_len < ip_header_len + (int)sizeof(struct tcphdr)) {
		return 0;
	}

	tcp_header_len = tcp_header->doff * 4;
	if (tcp_header_len < (int)sizeof(struct tcphdr) ||
	    packet_len < ip_header_len + tcp_header_len) {
		return 0;
	}

	if (ntohs(tcp_header->dest) != 80) {
		return 0;
	}

	tcp_payload = packet + ip_header_len + tcp_header_len;
	tcp_payload_len = packet_len - ip_header_len - tcp_header_len;
	if (tcp_payload_len <= 0 || !is_http_method(tcp_payload, tcp_payload_len)) {
		return 0;
	}

	if (!extract_host_header(tcp_payload, tcp_payload_len, host, sizeof(host))) {
		return 0;
	}

	normalize_host(host);

	if (found_host != NULL && found_host_len > 0) {
		snprintf(found_host, found_host_len, "%s", host);
	}

	return is_blocked_host(block_hosts, host);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *user_data) {
	app_config *config = (app_config *)user_data;
	unsigned char *packet = NULL;
	uint32_t packet_id = get_packet_id(nfa);
	int payload_len = nfq_get_payload(nfa, &packet);
	uint32_t verdict = NF_ACCEPT;
	char host[256];

	(void)nfmsg;

	host[0] = '\0';

	if (payload_len >= 0 &&
	    should_block_http_host(packet, payload_len, config->block_hosts,
				   host, sizeof(host))) {
		verdict = NF_DROP;
		printf("[DROP] %s packet_id=%u\n", host, packet_id);
	}

	return nfq_set_verdict(qh, packet_id, verdict, 0, NULL);
}

static void print_usage(const char *program_name) {
	fprintf(stderr, "syntax : %s <site list file> [queue-num]\n", program_name);
	fprintf(stderr, "sample : %s top-1m.csv\n", program_name);
}

int main(int argc, char **argv) {
	struct nfq_handle *handle;
	struct nfq_q_handle *queue_handle;
	int fd;
	int received_len;
	char buffer[65536] __attribute__((aligned));
	std::unordered_set<std::string> block_hosts;
	app_config config;

	config.block_hosts = &block_hosts;
	config.queue_num = DEFAULT_QUEUE_NUM;

	if (argc < 2 || argc > 3) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (argc == 3) {
		char *endptr = NULL;
		long parsed_queue = strtol(argv[2], &endptr, 10);

		if (*argv[2] == '\0' || endptr == NULL || *endptr != '\0' ||
		    parsed_queue < 0 || parsed_queue > 65535) {
			print_usage(argv[0]);
			return EXIT_FAILURE;
		}

		config.queue_num = (uint16_t)parsed_queue;
	}

	auto load_start = std::chrono::steady_clock::now();

	if (!load_block_hosts(argv[1], &block_hosts)) {
		return EXIT_FAILURE;
	}

	auto load_end = std::chrono::steady_clock::now();
	auto load_ms =
		std::chrono::duration_cast<std::chrono::milliseconds>(load_end - load_start).count();
	long rss_kb = get_rss_kb();

	printf("site list file : %s\n", argv[1]);
	printf("loaded hosts   : %zu\n", block_hosts.size());
	printf("load time      : %ld ms\n", load_ms);
	if (rss_kb >= 0) {
		printf("memory RSS     : %ld kB\n", rss_kb);
	}
	printf("queue num      : %u\n", config.queue_num);

	auto search_start = std::chrono::steady_clock::now();
	volatile int test_result = is_blocked_host(&block_hosts, "google.com");
	auto search_end = std::chrono::steady_clock::now();
	auto search_ns =
		std::chrono::duration_cast<std::chrono::nanoseconds>(search_end - search_start).count();

	printf("sample search  : google.com result=%d time=%ld ns\n",
	       test_result, search_ns);

	handle = nfq_open();
	if (handle == NULL) {
		fprintf(stderr, "error during nfq_open()\n");
		return EXIT_FAILURE;
	}

	if (nfq_unbind_pf(handle, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		nfq_close(handle);
		return EXIT_FAILURE;
	}

	if (nfq_bind_pf(handle, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		nfq_close(handle);
		return EXIT_FAILURE;
	}

	queue_handle = nfq_create_queue(handle, config.queue_num, &cb, &config);
	if (queue_handle == NULL) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		nfq_close(handle);
		return EXIT_FAILURE;
	}

	if (nfq_set_mode(queue_handle, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		nfq_destroy_queue(queue_handle);
		nfq_close(handle);
		return EXIT_FAILURE;
	}

	printf("waiting for packets...\n");
	fd = nfq_fd(handle);

	for (;;) {
		received_len = recv(fd, buffer, sizeof(buffer), 0);
		if (received_len >= 0) {
			nfq_handle_packet(handle, buffer, received_len);
			continue;
		}

		if (errno == ENOBUFS) {
			fprintf(stderr, "losing packets!\n");
			continue;
		}

		perror("recv failed");
		break;
	}

	nfq_destroy_queue(queue_handle);
	nfq_close(handle);
	return EXIT_SUCCESS;
}
