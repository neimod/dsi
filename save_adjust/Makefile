CFLAGS=-Wall -Wextra -Werror -pedantic -std=gnu99

all: save_adjust
save_adjust: dsi.o aes.o save_adjust.o bn.o ec.o
	$(CC) dsi.o aes.o save_adjust.o bn.o ec.o -o save_adjust -lcrypto

dsi.o: ../taddy/dsi.c
	$(CC) -c ../taddy/dsi.c $(CFLAGS)

aes.o: ../taddy/aes.c
	$(CC) -c ../taddy/aes.c $(CFLAGS)

ec.o: ec.c
	$(CC) -c ec.c $(CFLAGS)

bn.o: bn.c
	$(CC) -c bn.c $(CFLAGS)

save_adjust.o: save_adjust.c
	$(CC) -c save_adjust.c -I.. $(CFLAGS)

clean:
	-/bin/rm dsi.o aes.o save_adjust.o ec.o bn.o save_adjust 2>/dev/null
