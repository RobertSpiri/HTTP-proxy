all: build

build: httpproxy.c
	gcc -Wall -g httpproxy.c -o httpproxy

clean: httpproxy
	rm -rf httpproxy
