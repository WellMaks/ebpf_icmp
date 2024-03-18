CC := gcc
CLANG := clang
BPFTOOL := bpftool

# Include and library paths
LIBBPF_DIR := /usr/src/linux-headers-$(shell uname -r)/tools/lib/bpf
LIBBPF_INCLUDE := -I$(LIBBPF_DIR)/include
LIB_DIR := /usr/lib64
LIB_FLAGS := -L$(LIB_DIR) -lbpf -lelf -lz

# Compiler flags
CFLAGS := -g -O2 -Wall
CLANG_FLAGS := -g -O2 -target bpf $(LIBBPF_INCLUDE) -I/usr/include/linux

# Target files
BPF_SRC := icmp.bpf.c
BPF_OBJ := icmp.bpf.o
SKELETON_SRC := icmp.skel.h
USER_SRC := icmp.c
USER_BIN := icmp

# Default target
all: $(USER_BIN)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

$(SKELETON_SRC): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(USER_BIN): $(USER_SRC) $(SKELETON_SRC)
	$(CC) $(CFLAGS) -o $@ $(USER_SRC) $(LIB_FLAGS) -Wl,-rpath,$(LIB_DIR)

clean:
	rm -f $(BPF_OBJ) $(USER_BIN) $(SKELETON_SRC)

.PHONY: all clean