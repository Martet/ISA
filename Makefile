all: feedreader

feedreader: feedreader.cpp
	g++ `pkg-config --cflags --libs libxml-2.0` -lssl -lcrypto -g -std=c++17 -Wall -Wextra -pedantic $@.cpp -o $@

clean:
	rm -f feedreader
