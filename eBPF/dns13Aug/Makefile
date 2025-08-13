BPF_CLANG ?= clang
BPF_CFLAGS = -O2 -g -target bpf

all: dns_filter.bpf.o loader

dns_filter.bpf.o: dns_filter.bpf.c common.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c dns_filter.bpf.c -o dns_filter.bpf.o

loader: loader.c common.h
	gcc loader.c -o loader -lbpf -lelf -lz

clean:
	rm -f dns_filter.bpf.o loader
