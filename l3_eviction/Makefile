CFLAGS:=$(CFLAGS) -g -O0 -Wall # -Werror
LDFLAGS:=$(LDFLAGS) -g -pthread 
OBJS=l3.o asm.o asm_attack.o asm_prime.o asm_test_prime.o
CC=gcc
LD=gcc

all: l3

l3: $(OBJS)
	$(LD) -O0 -o $@ $(LDFLAGS) $^

prepare:
	echo 512 | sudo tee /proc/sys/vm/nr_hugepages

run: l3
	./$^
