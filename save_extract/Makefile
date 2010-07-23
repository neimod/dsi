all: save_extract
save_extract: dsi.o aes.o save_extract.o
	$(CC) dsi.o aes.o save_extract.o -o save_extract -lcrypto

dsi.o: ../taddy/dsi.c
	$(CC) -c ../taddy/dsi.c

aes.o: ../taddy/aes.c
	$(CC) -c ../taddy/aes.c

save_extract.o: save_extract.c
	$(CC) -c save_extract.c -I..

clean:
	-/bin/rm dsi.o aes.o save_extract.o save_extract 2>/dev/null
