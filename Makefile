CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2

.PHONY: all clean

all: sender receiver

sender: sender.cpp common.h
	$(CXX) $(CXXFLAGS) -o sender sender.cpp

receiver: receiver.cpp common.h
	$(CXX) $(CXXFLAGS) -o receiver receiver.cpp

clean:
	rm -f sender receiver received_records.txt capture.pcap
