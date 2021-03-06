#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "dsi.h"

void save(const char* path, const unsigned char* buffer, unsigned int size)
{
	FILE* f = fopen(path, "wb");
	if (f)
	{
		fwrite(buffer, 1, size, f);
		fclose(f);
	}
}

int main(int argc, char* argv[])
{
	FILE* f = 0;
	int result = -1;
	dsi_es_context ctx;
	unsigned char metablock[0x20];
	unsigned char header[0xB4];
	unsigned char footer[0x440];
	unsigned char key[16];
	int reencrypt = 0;
	

	fprintf(stdout, "taddy tool by neimod\n");

	if (argc != 3)
	{
		fprintf(stderr, "Usage: <in.bin> <key.bin>\n");
		return result;
	}

	// Read key from file
	f = fopen(argv[2], "rb");
	if (f == 0)
	{
		fprintf(stderr, "Could not open key file\n");
		goto clean;
	}
	if (16 != fread(key, 1, 16, f))
	{
		fprintf(stderr, "Error reading key\n");
		goto clean;
	}

	dsi_es_init(&ctx, key);


	// Read and decrypt header
	f = fopen(argv[1], "rb+");

	if (f == 0)
		goto clean;

	result = 0;

	fseek(f, 0x4020, SEEK_SET);
	if (0xB4 != fread(header, 1, 0xB4, f))
	{
		fprintf(stderr, "Error reading header.\n");
		goto clean;
	}
	if (0x20 != fread(metablock, 1, 0x20, f))
	{
		fprintf(stderr, "Error reading header metablock.\n");
		goto clean;
	}

	if (dsi_es_decrypt(&ctx, header, metablock, sizeof(header)) < 0)
	{
		fprintf(stderr, "Error decrypting header.\n");
		goto clean;
	}

	fseek(f, 0x40F4, SEEK_SET);
	if (0x440 != fread(footer, 1, 0x440, f))
	{
		fprintf(stderr, "Error reading footer.\n");
		goto clean;
	}
	if (0x20 != fread(metablock, 1, 0x20, f))
	{
		fprintf(stderr, "Error reading footer metablock.\n");
		goto clean;
	}

	if (dsi_es_decrypt(&ctx, footer, metablock, sizeof(footer)) < 0)
	{
		fprintf(stderr, "Error decrypting footer.\n");
		goto clean;
	}

	save("header.bin", header, sizeof(header));
	save("footer.bin", footer, sizeof(footer));

	if (reencrypt)
	{
		dsi_es_encrypt(&ctx, header, metablock, sizeof(header));
		fseek(f, 0x4020, SEEK_SET);
		fwrite(header, 1, sizeof(header), f);
		fwrite(metablock, 1, sizeof(metablock), f);
		dsi_es_encrypt(&ctx, footer, metablock, sizeof(footer));
		fseek(f, 0x40F4, SEEK_SET);
		fwrite(footer, 1, sizeof(footer), f);
		fwrite(metablock, 1, sizeof(metablock), f);
	}

 


	fprintf(stdout, "Done - Have a nice day.\n");

clean:
	if (f)
		fclose(f);

	return result;
}

