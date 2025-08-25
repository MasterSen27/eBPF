# Makefile (with latest libbpf from /usr/local)

CLANG ?= clang
CC ?= gcc
ARCH ?= $(shell uname -m)

all: xdp_dns_kern.o loader

xdp_dns_kern.o: xdp_dns_kern.c
	$(CLANG) -O2 -Wall -target bpf \
		-I/usr/include/$(ARCH)-linux-gnu \
		-I/usr/include \
		-c xdp_dns_kern.c -o xdp_dns_kern.o

loader: loader.c
	$(CC) loader.c -o loader \
		-I$(PWD)/libbpf/include \
		$(PWD)/libbpf/src/libbpf.a \
		-lelf -lz


clean:
	rm -f *.o loader
