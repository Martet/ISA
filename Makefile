XMLLDFLAGS!=pkg-config --libs libxml-2.0
XMLLDFLAGS+=$(shell pkg-config --libs libxml-2.0)
XMLCFLAGS!=pkg-config --cflags libxml-2.0
XMLCFLAGS+=$(shell pkg-config --cflags libxml-2.0)

CXXFLAGS:=$(XMLCFLAGS) -std=c++17 -Wall -Wextra -g
LDLIBS:=$(XMLLDFLAGS) -lssl -lcrypto

feedreader: feedreader.cpp

test: feedreader
	pytest

clean:
	rm -f feedreader

.PHONY: test clean
