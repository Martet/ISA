CXXFLAGS=$(shell pkg-config --cflags libxml-2.0) -std=c++17 -Wall -Wextra -g
LDLIBS=$(shell pkg-config --libs libxml-2.0) -lssl -lcrypto
CXX=c++

feedreader: feedreader.cpp

test: feedreader
	python3 -m pytest

clean:
	rm -f feedreader

.PHONY: test clean
