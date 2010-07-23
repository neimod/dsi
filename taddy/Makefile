all: taddy
taddy: dsi.o aes.o main.o
	$(CC) dsi.o aes.o main.o -o taddy

dsi.o: dsi.c
	$(CC) -c dsi.c

aes.o: aes.c
	$(CC) -c aes.c

main.o: main.cpp
	$(CC) -x c -c main.cpp

clean:
	/bin/rm dsi.o aes.o main.o taddy
