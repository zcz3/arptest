
BUILDDIR=build

arptest: arptest.o
	gcc -o arptest arptest.o

arptest.o: arptest.c
	gcc -c arptest.c



