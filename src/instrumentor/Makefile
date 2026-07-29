CC=clang++
AR=ar
CFLAGS=-g -c -Wall -std=gnu++11
ARFLAGS=rcs

all: clean instrument move

instrument:
	$(CC) $(CFLAGS) *.cc
	$(AR) $(ARFLAGS) libinstrumentor.a *.o

move:
	mkdir -p ../../bin
	mv libinstrumentor.a ../../bin/

clean:
	rm -f *.o entry trace libinstrumentor.a
