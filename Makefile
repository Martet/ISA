CC=g++
LDFLAGS=-I/usr/include/libxml2 -lxml2 -g

all: feedreader

clean:
	rm -f feedreader
