CXX = /usr/bin/g++
CXXFLAGS = -Wall -Wextra -O2 -std=c++17
LDLIBS = -lnetfilter_queue
TARGET = 1m-block

all: $(TARGET)

$(TARGET): main.cpp
	$(CXX) $(CXXFLAGS) -o $@ main.cpp $(LDLIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
