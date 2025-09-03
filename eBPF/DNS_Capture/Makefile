BPF_CLANG = clang
BPF_CFLAGS = -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 \
             -I/usr/include/x86_64-linux-gnu -I/usr/include

CFLAGS = -O2 -g -Wall
LDLIBS = -lbpf -lelf -lz -lm

BPF_OBJ = xdp_dns_kern.o
BPF_SKEL = xdp_dns_kern.skel.h
LOADER = loader

all: $(BPF_OBJ) $(BPF_SKEL) $(LOADER)

$(BPF_OBJ): xdp_dns_kern.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BPF_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

$(LOADER): loader.c $(BPF_SKEL)
	$(CC) $(CFLAGS) loader.c -o $@ $(LDLIBS)

clean:
	rm -f $(BPF_OBJ) $(BPF_SKEL) $(LOADER)
