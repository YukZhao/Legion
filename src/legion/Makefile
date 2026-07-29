CC=g++
CXXSTD ?= gnu++17
TOOLCHAIN_PATH ?= /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CFLAGS=-c -Wall -std=$(CXXSTD)
LDFLAGS=-std=$(CXXSTD) -pthread -lstdc++fs
SOURCES=$(wildcard *.cc)
OBJECTS=$(SOURCES:.cc=.o)
EXECUTABLE=legion

all: $(EXECUTABLE)

$(EXECUTABLE) : $(OBJECTS)
	PATH=$(TOOLCHAIN_PATH) $(CC) $(OBJECTS) $(LDFLAGS) -o $@

# same as .cc.o: 
%.o: %.cc
	PATH=$(TOOLCHAIN_PATH) $(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf *.o $(EXECUTABLE)
