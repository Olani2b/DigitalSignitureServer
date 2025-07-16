# File: Makefile

CXX       := g++
CXXFLAGS  := -std=c++11 -Wall -O2
LDFLAGS   := -lssl -lcrypto

# All sources for server (dss) and client
SRVSRC    := main.cpp server.cpp crypto.cpp utility.cpp
CLISRC    := client.cpp crypto.cpp utility.cpp

# Object files
SRVOBJ    := $(SRVSRC:.cpp=.o)
CLIOBJ    := $(CLISRC:.cpp=.o)

.PHONY: all clean

all: dss client

# Link the server executable (dss)
dss: $(SRVOBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Link the client executable
client: $(CLIOBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Compile rule
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

clean:
	rm -f *.o dss client
