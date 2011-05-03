#include <stdio.h>
#include <malloc.h>
#include "bitreg.h"
#include "mmc.h"

int main(int argc, char* argv[])
{
	FILE* f = 0;
	mmc_context ctx;
	unsigned char cmd;
	unsigned int content;



	if (argc != 2)
	{
		fprintf(stdout, "usage <in.bin>\n");
		return -1;
	}

	f = fopen(argv[1], "rb");
	if (f == 0)
	{
		fprintf(stderr, "could not open %s\n", argv[1]);
		goto clean;
	}




	mmc_init(&ctx, f);


	while(!feof(f))
	{
		unsigned char c = fgetc(f);

		mmc_process(&ctx, c);

		if (mmc_is_cmd_ready(&ctx))
		{
			mmc_cmd53 cmd53;
			mmc_cmd52 cmd52;

			cmd = mmc_get_cmd(&ctx);
			content = mmc_get_cmd_content(&ctx);

			fprintf(stdout, "%02d%08X ", cmd, content);

			if (cmd == 52)
			{
				mmc_get_cmd52_content(&ctx, &cmd52);

				if (cmd52.rw)
					fprintf(stdout, "IO_RW_DIRECT   WRITE FNR=%d ADDR=%08x", cmd52.fnr, cmd52.address);
				else
					fprintf(stdout, "IO_RW_DIRECT   READ  FNR=%d ADDR=%08x RAW=%d DATA=%02X", cmd52.fnr, cmd52.address, cmd52.raw, cmd52.data);
			}
			else if (cmd == 53)
			{
				mmc_get_cmd53_content(&ctx, &cmd53);

				fprintf(stdout, "IO_RW_EXTENDED %s FNR=%d ADDR=%08x SIZE=%03d OP=%d BM=%d C=%d", cmd53.rw? "WRITE":"READ ", cmd53.fnr, cmd53.address, cmd53.size, cmd53.opcode, cmd53.bmode, cmd53.count);
			}
			fprintf(stdout, "\n");
		}

		if (mmc_is_resp_ready(&ctx))
		{
			cmd = mmc_get_cmd(&ctx);
			content = mmc_get_cmd_content(&ctx);

			fprintf(stdout, " > %02d%08X ", cmd, content);

			if (cmd == 52)
			{
				fprintf(stdout, "FLAGS=%02X DATA=%02X", (content>>8)&0xFF, content&0xFF);
			}
			else if (cmd == 53)
			{
				fprintf(stdout, "FLAGS=%02X", (content>>8)&0xFF);
			}
			fprintf(stdout, "\n");
		}

		if (mmc_is_dat_ready(&ctx))
		{
			unsigned int size = mmc_get_dat_size(&ctx);
			unsigned char* data = mmc_get_dat_content(&ctx);

			mmc_dump(" >>", data, size);
		}
	}
	

clean:
	if (f)
		fclose(f);



	return 0;
}