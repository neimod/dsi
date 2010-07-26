CFLAGS=-Wall -Wextra -Werror -pedantic -std=gnu99

all: taddy
taddy: dsi.o aes.o main.o
	$(CC) dsi.o aes.o main.o -o taddy

dsi.o: dsi.c
	$(CC) -c dsi.c $(CFLAGS)

aes.o: aes.c
	$(CC) -c aes.c $(CFLAGS)

main.o: main.cpp
	$(CC) -x c -c main.cpp $(CFLAGS)

clean:
	-/bin/rm dsi.o aes.o main.o taddy 2>/dev/null
