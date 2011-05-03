#include <stdio.h>
#include <malloc.h>
#include "mmc.h"


void mmc_init(mmc_context* ctx, FILE* f)
{
	ctx->f = f;
	ctx->cmdrecv = 0;
	ctx->cmdresprecv = 0;
	ctx->cmdskipbits = 0;
	ctx->buswidth = 0;
	ctx->blocksizefbr1 = 0;
	ctx->datcycles = 0;
	ctx->datstate = 0;
	ctx->datblocks = 0;
	ctx->datbytes = 0;
	ctx->datavailable = 0;


	bitreg_init(&ctx->cmd);
	bitreg_init(&ctx->dat0);
	bitreg_init(&ctx->dat1);
	bitreg_init(&ctx->dat2);
	bitreg_init(&ctx->dat3);
	bitreg_init(&ctx->dat);
	bitreg_resize(&ctx->cmd, 48);
}

void mmc_destroy(mmc_context* ctx)
{
	bitreg_destroy(&ctx->cmd);
}

unsigned short mmc_crc16_update(unsigned short crc, unsigned int in)
{
	if (in ^ (crc>>15))
		crc = (crc<<1) ^ 0x1021;
	else
		crc = (crc<<1);

	return crc;
}

void mmc_process(mmc_context* ctx, unsigned char data)
{
	unsigned int cmdbit = data & 1;
	unsigned int dat0 = (data >> 1) & 1;
	unsigned int dat1 = (data >> 2) & 1;
	unsigned int dat2 = (data >> 3) & 1;
	unsigned int dat3 = (data >> 4) & 1;
	unsigned char* cmddata = ctx->cmd.data;
	unsigned char checkcrc, gotcrc;
	int i;

	ctx->cmdrecv = 0;
	ctx->cmdresprecv = 0;
	ctx->datavailable = 0;

	bitreg_shift(&ctx->cmd, cmdbit);

	if (ctx->cmdskipbits)
	{
		ctx->cmdskipbits--;
	}
	else
	{
		checkcrc = (mmc_crc7(cmddata, 5)<<1)|1;
		gotcrc = cmddata[5];

		if ( (cmddata[0] & 0xC0) == 0x40 && (checkcrc == gotcrc) )
		{
			ctx->cmdrecv = 1;
			ctx->cmdskipbits = 48;
		}

		if ( (cmddata[0] & 0xC0) == 0 && (checkcrc == gotcrc) )
		{
			ctx->cmdresprecv = 1;
			ctx->cmdskipbits = 48;
		}

		mmc_process_cmd(ctx);
	}

	if (ctx->datstate == 1)
	{
		// Wait dat0 to go ready
		if (dat1 == 0)
			ctx->datstate = 2;

		// Calculate the cycles needed for 1 'block'.
		if (ctx->buswidth == 0)
		{
			if (ctx->datbytes)
				ctx->datcycles = ctx->datbytes * 8 + 16;
			else
				ctx->datcycles = ctx->blocksizefbr1 * 8 + 16;
		}
		else
		{
			if (ctx->datbytes)
				ctx->datcycles = ctx->datbytes * 2 + 16;
			else
				ctx->datcycles = ctx->blocksizefbr1 * 2 + 16;
		}
	}
	else if (ctx->datstate == 2)
	{
		bitreg_shift(&ctx->dat0, dat0);

		if (ctx->buswidth == 2)
		{
			bitreg_shift(&ctx->dat1, dat1);
			bitreg_shift(&ctx->dat2, dat2);
			bitreg_shift(&ctx->dat3, dat3);
		}

		ctx->datcycles--;

		if (ctx->datcycles == 0)
			ctx->datstate = 3;
	}
	else if (ctx->datstate == 3)
	{
		if (ctx->buswidth == 2)
		{
			unsigned short checkcrc0 = 0;
			unsigned short checkcrc1 = 0;
			unsigned short checkcrc2 = 0;
			unsigned short checkcrc3 = 0;
			unsigned short gotcrc0 = 0;
			unsigned short gotcrc1 = 0;
			unsigned short gotcrc2 = 0;
			unsigned short gotcrc3 = 0;

			
			for(i=0; i<ctx->dat0.bitsize - 16; i++)
			{
				dat0 = bitreg_shift(&ctx->dat0, 0);
				dat1 = bitreg_shift(&ctx->dat1, 0);
				dat2 = bitreg_shift(&ctx->dat2, 0);
				dat3 = bitreg_shift(&ctx->dat3, 0);


				bitreg_shift(&ctx->dat, dat3);
				bitreg_shift(&ctx->dat, dat2);
				bitreg_shift(&ctx->dat, dat1);
				bitreg_shift(&ctx->dat, dat0);
				
				checkcrc0 = mmc_crc16_update(checkcrc0, dat0);
				checkcrc1 = mmc_crc16_update(checkcrc1, dat1);
				checkcrc2 = mmc_crc16_update(checkcrc2, dat2);
				checkcrc3 = mmc_crc16_update(checkcrc3, dat3);
			}

			for(i=0; i<16; i++)
			{
				gotcrc0 = (gotcrc0 << 1) | bitreg_shift(&ctx->dat0, 0);
				gotcrc1 = (gotcrc1 << 1) | bitreg_shift(&ctx->dat1, 0);
				gotcrc2 = (gotcrc2 << 1) | bitreg_shift(&ctx->dat2, 0);
				gotcrc3 = (gotcrc3 << 1) | bitreg_shift(&ctx->dat3, 0);
			}

			if (checkcrc0 != gotcrc0 || checkcrc1 != gotcrc1 || checkcrc2 != gotcrc2 || checkcrc3 != gotcrc3)
			{
				bitreg_resize(&ctx->dat, 0);
				printf("CRC mismatch %d!\n", ftell(ctx->f)/2);
				printf("%04X vs %04X\n", checkcrc0, gotcrc0);
				printf("%04X vs %04X\n", checkcrc1, gotcrc1);
				printf("%04X vs %04X\n", checkcrc2, gotcrc2);
				printf("%04X vs %04X\n", checkcrc3, gotcrc3);
			}
		}
		else if (ctx->buswidth == 0)
		{
			unsigned short checkcrc0 = 0;
			unsigned short gotcrc0 = 0;
			
			for(i=0; i<ctx->dat0.bitsize - 16; i++)
			{
				dat0 = bitreg_shift(&ctx->dat0, 0);

				bitreg_shift(&ctx->dat, dat0);
				
				checkcrc0 = mmc_crc16_update(checkcrc0, dat0);
			}

			for(i=0; i<16; i++)
			{
				gotcrc0 = (gotcrc0 << 1) | bitreg_shift(&ctx->dat0, 0);
			}

			if (checkcrc0 != gotcrc0)
				bitreg_resize(&ctx->dat, 0);
		}

		
		//mmc_dump(" >>", ctx->dat.data, ctx->dat.bytesize);

		ctx->datbytes = 0;
		ctx->datstate = 0;
		ctx->datavailable = 1;

		if (ctx->datblocks <= 1)
			ctx->datblocks = 0;
		else
		{
			// More blocks coming, restart statemachine
			ctx->datblocks--;
			ctx->datstate = 1;
			ctx->datavailable = 0;
		}
	}
}

void mmc_process_cmd(mmc_context* ctx)
{
	unsigned char cmd;


	if (!ctx->cmdrecv)
		return;

	cmd = mmc_get_cmd(ctx);

	if (cmd == 52)
	{
		mmc_cmd52 cmd52;

		mmc_get_cmd52_content(ctx, &cmd52);

		if (cmd52.fnr == 0 && cmd52.address == 7 && cmd52.rw)
		{
			ctx->buswidth = cmd52.data & 3;
			printf("Set buswidth to %d\n", ctx->buswidth);
		}
		else if (cmd52.fnr == 0 && cmd52.address == 0x110 && cmd52.rw)
		{
			ctx->blocksizefbr1 = (ctx->blocksizefbr1 & ~0xFF) | cmd52.data;
			printf("Set FBR1 blocksize to %d\n", ctx->blocksizefbr1);
		}
		else if (cmd52.fnr == 0 && cmd52.address == 0x111 && cmd52.rw)
		{
			ctx->blocksizefbr1 = (ctx->blocksizefbr1 & ~0xFF00) | (cmd52.data<<8);
			printf("Set FBR1 blocksize to %d\n", ctx->blocksizefbr1);
		}
	}
	else if (cmd == 53)
	{
		mmc_cmd53 cmd53;

		mmc_get_cmd53_content(ctx, &cmd53);

		if (cmd53.fnr == 1)
		{
			if (cmd53.bmode)
				ctx->datblocks = cmd53.count;
			else
				ctx->datbytes = cmd53.size;

			ctx->datstate = 1;

			if (ctx->buswidth == 0)
			{
				// Data will be sent on 1 dat line, dat0. 
				// Resize the shift register to allow for a single block or the byte size requested, plus CRC bits.
				if (ctx->datblocks)
					bitreg_resize(&ctx->dat0, ctx->blocksizefbr1*8 + 16);
				else
					bitreg_resize(&ctx->dat0, ctx->datbytes*8 + 16);
			}
			else if (ctx->buswidth == 2)
			{
				// Data will be sent on 4 dat lines.
				// Resize each dat0..3 shift register for a single block, or the byte size requested, plus CRC bits.

				if (ctx->datblocks)
				{
					bitreg_resize(&ctx->dat0, ctx->blocksizefbr1*2 + 16);
					bitreg_resize(&ctx->dat1, ctx->blocksizefbr1*2 + 16);
					bitreg_resize(&ctx->dat2, ctx->blocksizefbr1*2 + 16);
					bitreg_resize(&ctx->dat3, ctx->blocksizefbr1*2 + 16);
				}
				else
				{
					bitreg_resize(&ctx->dat0, ctx->datbytes*2 + 16);
					bitreg_resize(&ctx->dat1, ctx->datbytes*2 + 16);
					bitreg_resize(&ctx->dat2, ctx->datbytes*2 + 16);
					bitreg_resize(&ctx->dat3, ctx->datbytes*2 + 16);
				}
			}

			// Final data packet will get stored in the dat shift register.
			bitreg_resize(&ctx->dat, cmd53.size * 8);
		}
	}
}


void mmc_dump(const char* indent, const void* data, unsigned int size)
{
    int j=0;
    int i;
	int lines = (size+15)/16;
    unsigned char* data8 = (unsigned char*)data;


    for(i=0; i<lines; i++)
    {
		int max = size;
		if (max > 16)
			max = 16;

		fprintf(stdout, "%s %04X: ", indent, i*16);

		for(j=0; j<max; j++)
			fprintf(stdout, "%02X ", data8[i*16+j]);

		for(j=max; j<16; j++)
			fprintf(stdout, "   ");

		fprintf(stdout,"| ");
		for(j=0; j<max; j++)
		{
			char c = data8[i*16+j];

			if (c >= 32 && c <= 126)
				fprintf(stdout, "%c", data8[i*16+j]);
			else
				fprintf(stdout, ".");
		}


		fprintf(stdout, "\n");

		size -= max;
    }
}



unsigned char mmc_crc7(const unsigned char* in, unsigned int length)
{
    int i,j;

    unsigned char byte, crc=0;
  
    for(i=0; i < length; i++)
    {
        byte = in[i];

        for(j=0; j<8; j++)
        {
            crc <<= 1;
            if ((crc ^ byte) & 0x80)
                crc ^= 0x09;
            byte<<=1;
        }
         
        crc &= 0x7f; 
    }

  return crc;
}

int mmc_is_cmd_ready(mmc_context* ctx)
{
	return ctx->cmdrecv;
}

int mmc_is_resp_ready(mmc_context* ctx)
{
	return ctx->cmdresprecv;
}

int mmc_is_dat_ready(mmc_context* ctx)
{
	return ctx->datavailable;
}


unsigned char mmc_get_cmd(mmc_context* ctx)
{
	return ctx->cmd.data[0] & 0x3F;
}

unsigned int mmc_get_cmd_content(mmc_context* ctx)
{
	unsigned char* cmddata = ctx->cmd.data;

	return (cmddata[1]<<24) | (cmddata[2]<<16) | (cmddata[3]<<8) | (cmddata[4]<<0);
}

unsigned int mmc_get_dat_size(mmc_context* ctx)
{
	return ctx->dat.bytesize;
}

unsigned char* mmc_get_dat_content(mmc_context* ctx)
{
	return ctx->dat.data;
}

void mmc_get_cmd52_content(mmc_context* ctx, mmc_cmd52* d)
{
	unsigned char* cmddata = ctx->cmd.data;

	d->rw = cmddata[1] & 0x80;
	d->fnr = (cmddata[1] >> 4) & 7;
	d->raw = (cmddata[1] >> 3) & 1;
	d->address = (cmddata[3] >> 1) | (cmddata[2] << 7) | ((cmddata[1]&3) << 15);
	d->data = cmddata[4];
}

void mmc_get_cmd53_content(mmc_context* ctx, mmc_cmd53* d)
{
	unsigned char* cmddata = ctx->cmd.data;

	d->rw = cmddata[1] & 0x80;
	d->fnr = (cmddata[1] >> 4) & 7;
	d->bmode = (cmddata[1] >> 3) & 1;
	d->opcode = (cmddata[1] >> 2) & 1;
	d->address = (cmddata[3] >> 1) | (cmddata[2] << 7) | ((cmddata[1]&3) << 15);
	d->count = cmddata[4] | ((cmddata[3]&1)<<8);

	if (d->bmode)
		d->size = (d->count==0)? (~0) : (d->count * ctx->blocksizefbr1);
	else
		d->size = (d->count==0)? 512 : d->count;
}

void mmc_dump_rawdat(mmc_context* ctx)
{
	unsigned int fsize;
	unsigned char* buffer;
	unsigned char* buffer4a;
	unsigned char* buffer4b;
	unsigned int i;
	FILE* fout;

	fseek(ctx->f, 0, SEEK_END);
	fsize = ftell(ctx->f);
	fseek(ctx->f, 0, SEEK_SET);

	buffer = malloc(fsize);
	buffer4a = malloc(1+fsize/2);
	buffer4b = malloc(1+fsize/2);
	fread(buffer, 1, fsize, ctx->f);
	fseek(ctx->f, 0, SEEK_SET);

	for(i=0; i<(fsize/2); i++)
	{
		unsigned char h = (buffer[i*2+0]>>1) & 0xf;
		unsigned char l = (buffer[i*2+1]>>1) & 0xf;

		buffer4a[i] = (h<<4) | l;

		h = (buffer[i*2+1]>>1) & 0xf;
		l = (buffer[(i+1)*2+0]>>1) & 0xf;

		buffer4b[i] = (h<<4) | l;
	}



	fout = fopen("dat4a.bin", "wb");
	if (fout)
	{		
		fwrite(buffer4a, 1, fsize/2, fout);
		fclose(fout);
	}


	fout = fopen("dat4b.bin", "wb");
	if (fout)
	{		
		fwrite(buffer4b, 1, fsize/2, fout);
		fclose(fout);
	}

	free(buffer);
	free(buffer4a);
	free(buffer4b);
}
