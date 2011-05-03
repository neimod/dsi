#include <stdio.h>
#include <malloc.h>
#include "bitreg.h"

void bitreg_init(bitreg* reg)
{
	reg->bytesize = 0;
	reg->bitsize = 0;
	reg->offset = 0;
	reg->capacity = 0;
	reg->data = 0;
}

void bitreg_destroy(bitreg* reg)
{
	free(reg->data);
	reg->data = 0;
}

void bitreg_resize(bitreg* reg, unsigned int bitsize)
{
	reg->bytesize = (bitsize+7) / 8;
	reg->bitsize = bitsize;
	reg->offset = (reg->bytesize * 8) - reg->bitsize;

	if (reg->capacity < reg->bytesize)
	{
		if (reg->data)
			free(reg->data);
		reg->capacity = reg->bytesize;
		reg->data = malloc(reg->capacity);
	}

	memset(reg->data, 0, reg->bytesize);
}

unsigned int bitreg_shift(bitreg* reg, unsigned int bit)
{
	unsigned int carry;
	int i = 0;

	carry = reg->data[i]>>7;


	if (reg->bytesize > 1)
	{
		for(i=0; i<reg->bytesize-1; i++)
			reg->data[i] = (reg->data[i] << 1) | (reg->data[i+1]>>7);
	}

	reg->data[i] = (reg->data[i] << 1) | ((bit & 1)<<reg->offset);
	return carry;
}

void bitreg_dump(bitreg* reg)
{
	int i;

	for(i=0; i<reg->bytesize; i++)
		fprintf(stdout, "%02X", reg->data[i]);
	fprintf(stdout, "\n");
}

