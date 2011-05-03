#ifndef _MMC_H_
#define _MMC_H_

#include "bitreg.h"

typedef struct
{
	FILE* f;
	bitreg cmd;
	bitreg dat0;
	bitreg dat1;
	bitreg dat2;
	bitreg dat3;
	bitreg dat;
	unsigned char cmdrecv;
	unsigned char cmdresprecv;
	unsigned int cmdskipbits;
	unsigned int buswidth;
	unsigned int blocksizefbr1;
	unsigned int datcycles;
	unsigned int datstate;
	unsigned int datblocks;
	unsigned int datbytes;
	unsigned int datavailable;
} mmc_context;

typedef struct
{
	unsigned char rw;
	unsigned char fnr;
	unsigned char raw;
	unsigned int address;
	unsigned char data;
} mmc_cmd52;


typedef struct
{
	unsigned char rw;
	unsigned char fnr;
	unsigned char bmode;
	unsigned char opcode;
	unsigned int address;
	unsigned char count;
	unsigned int size;
} mmc_cmd53;

void mmc_init(mmc_context* ctx, FILE* f);
void mmc_destroy(mmc_context* ctx);
void mmc_process(mmc_context* ctx, unsigned char data);
unsigned char mmc_crc7(const unsigned char* in, unsigned int length);
unsigned short mmc_crc16_update(unsigned short crc, unsigned int in);
void mmc_dump(const char* indent, const void* data, unsigned int size);
int mmc_is_cmd_ready(mmc_context* ctx);
int mmc_is_resp_ready(mmc_context* ctx);
int mmc_is_dat_ready(mmc_context* ctx);
unsigned char mmc_get_cmd(mmc_context* ctx);
unsigned int mmc_get_cmd_content(mmc_context* ctx);
void mmc_get_cmd52_content(mmc_context* ctx, mmc_cmd52* d);
void mmc_get_cmd53_content(mmc_context* ctx, mmc_cmd53* d);
void mmc_process_cmd(mmc_context* ctx);
unsigned int mmc_get_dat_size(mmc_context* ctx);
unsigned char* mmc_get_dat_content(mmc_context* ctx);
void mmc_dump_rawdat(mmc_context* ctx);


#endif // _MMC_H_