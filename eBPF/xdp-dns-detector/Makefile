# Makefile
CLANG ?= clang
BPFTOOL ?= bpftool

all: xdp_dns_kern.o loader

xdp_dns_kern.o: xdp_dns_kern.c
	$(CLANG) -O2 -Wall -target bpf -c xdp_dns_kern.c -o xdp_dns_kern.o

loader: loader.c
	$(CC) loader.c -o loader \
		-I./libbpf/include \
		./libbpf/libbpf.a \
		-lelf -lz


clean:
	rm -f *.o loader
