FILE = main.c
PROG = main
all: main.c 
	gcc -std=c99 $(FILE) -o $(PROG)
debug: main.c
	gcc -std=c99 -g $(FILE) -o $(PROG)
