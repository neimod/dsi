#ifndef _BITREG_H_
#define _BITREG_H_


typedef struct
{
	unsigned char* data;
	unsigned int bitsize;
	unsigned int bytesize;
	unsigned int offset;
	unsigned int capacity;
} bitreg;

unsigned int bitreg_shift(bitreg* reg, unsigned int bit);
void bitreg_init(bitreg* reg);
void bitreg_resize(bitreg* reg, unsigned int bitsize);
void bitreg_destroy(bitreg* reg);
void bitreg_dump(bitreg* reg);


#endif // _BITREG_H_