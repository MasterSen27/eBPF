CLANG ?= clang
BPFTOOL ?= bpftool
KERNEL_HEADERS := /usr/src/linux-headers-$(shell uname -r)

CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I. \
  -I$(KERNEL_HEADERS)/include \
  -I$(KERNEL_HEADERS)/include/uapi \
  -I$(KERNEL_HEADERS)/include/generated \
  -I$(KERNEL_HEADERS)/arch/x86/include \
  -I$(KERNEL_HEADERS)/arch/x86/include/uapi \
  -I$(KERNEL_HEADERS)/arch/x86/include/generated

all: exec_counter.bpf.o loader

exec_counter.bpf.o: exec_counter.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@

loader: loader.c
	gcc -o loader loader.c -lbpf -lelf -lz

clean:
	rm -f *.o loader
