BPF_OBJ = xdp_dns_kern.o
SKEL    = xdp_dns_kern.skel.h
LOADER  = loader

all: $(LOADER)

$(BPF_OBJ): xdp_dns_kern.c
	clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 \
	      -I/usr/include/x86_64-linux-gnu -I/usr/include \
	      -c $< -o $@

$(SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

$(LOADER): loader.c $(SKEL)
	cc -O2 -g -Wall -I/home/iem/ebpf/libbpf/include \
	   loader.c -o $@ /home/iem/ebpf/libbpf/src/libbpf.a -lelf -lz

clean:
	rm -f *.o *.skel.h $(LOADER)
