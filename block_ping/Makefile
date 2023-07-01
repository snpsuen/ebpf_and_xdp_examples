all: main

main.bpf.o: main.bpf.c
	clang -O2 -g -target bpf -c main.bpf.c -o main.bpf.o

main.skel.h: main.bpf.o
	sudo bpftool gen skeleton main.bpf.o > main.skel.h

main: main.skel.h main.c
	gcc -o main main.c -lbpf

clean:
	rm -f main.bpf.o main.skel.h main

.PHONY: all clean
