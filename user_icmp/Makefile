CXX      ?= g++
CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++11 -Wall -Wextra
LDLIBS   += -lanl   # getaddrinfo_a()

OBJECTS = main.o daemon.o icmp_socket.o packet_table.o resolver.o common.o protocol.o

user_icmp: $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJECTS) $(LDLIBS)

%.o: %.cpp *.h ../shared/protocol.h
	$(CXX) $(CXXFLAGS) -c $<

protocol.o: ../shared/protocol.cpp ../shared/protocol.h
	$(CXX) $(CXXFLAGS) -c $<

clean:
	rm -f user_icmp $(OBJECTS)

.PHONY: clean
