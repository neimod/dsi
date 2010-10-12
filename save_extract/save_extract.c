// Copyright 2010  booto 
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <taddy/dsi.h>
#include <endian.h>
#include <openssl/sha.h>

typedef struct tna4_t
{
	uint32_t magic;
	uint16_t group_id;
	uint16_t version;
	uint8_t mac[8];
	uint8_t hwinfo_n[0x10];
	uint32_t titleid_2;
	uint32_t titleid_1;
	int32_t tmd_elength;
	int32_t content_elength[8];
	int32_t savedata_elength;
	int32_t bannersav_elength;
	uint32_t content_id[8];
	uint32_t savedata_length;
	uint8_t reserved[0x3c];
} tna4_t;

typedef uint8_t sha1_hash[0x14];

typedef struct footer_t
{
	sha1_hash banner_hash;
	sha1_hash tna4_hash;
	sha1_hash tmd_hash;
	sha1_hash content_hash[8];
	sha1_hash savedata_hash;
	sha1_hash bannersav_hash;
	uint8_t ecc_sig[0x3c];
	uint8_t ap_cert[0x180];
	uint8_t tw_cert[0x180];
} footer_t;

//#define CI_TMD 0
#define CI_CONTENT_FIRST 0
#define CI_CONTENT_LAST 7
#define CI_CONTENT_COUNT 8
//#define CI_SAVEDATA 9
//#define CI_BANNERSAV 10

#define EOFF_BANNER 0
#define ESIZE_BANNER 0x4020
#define EOFF_TNA4 (EOFF_BANNER+ESIZE_BANNER)
#define ESIZE_TNA4 0xd4
#define EOFF_FOOTER (EOFF_TNA4 + ESIZE_TNA4)
#define ESIZE_FOOTER 0x460
#define EOFF_TMD (EOFF_FOOTER + ESIZE_FOOTER)

uint8_t buffer[0x20020];
int decrypt_to_buffer(uint8_t *key, uint8_t *src, uint8_t *dst, uint32_t enc_size, uint32_t *dec_size)
{
	uint32_t bytes_to_dec = 0;
	uint32_t total_dec_bytes = 0;

	dsi_es_context dec;
	dsi_es_init(&dec, key);
	while(enc_size > 0)
	{
		bytes_to_dec = 0x20000;
		if(bytes_to_dec > enc_size - 0x20)
		{
			bytes_to_dec = enc_size - 0x20;
		}
		if(dec_size)
		{
			if(total_dec_bytes + bytes_to_dec > *dec_size)
			{
				return -2;
			}
		}
		memcpy(buffer, src, bytes_to_dec + 0x20);

		if(dsi_es_decrypt(&dec, buffer, buffer + bytes_to_dec, bytes_to_dec) != 0)
		{
			printf("total_dec_bytes: 0x%08x, bytes_to_dec: 0x%08x\n",
				total_dec_bytes, bytes_to_dec);
			return -3;
		}

		memcpy(dst, buffer, bytes_to_dec);

		total_dec_bytes += bytes_to_dec;
		src += bytes_to_dec + 0x20;
		dst += bytes_to_dec;
		enc_size -= bytes_to_dec + 0x20;
	}

	if(dec_size)
	{
		*dec_size = total_dec_bytes;
	}

	return 0;
}

int save_section(const char *filebase, const char *extension, uint8_t *buffer, int len)
{
	char filename[512];

	snprintf(filename, sizeof(filename), "%s.%s", filebase, extension);
	FILE *out = fopen(filename, "wb");
	if(out == NULL)
	{
		return -1;
	}
	fwrite(buffer, len, 1, out);
		
	fclose(out);

	return 0;

}


uint32_t tna4_magic = 0x544e4134;


uint8_t tna4_buffer[0xb4];
uint8_t footer_buffer[0x440];
uint8_t banner_buffer[0x4000];

sha1_hash temp_hash;


int get_key(const char *name, uint8_t *key, uint32_t len)
{
	char path[256];

	char *home = getenv("HOME");
	if (home == NULL)
	{
		return -1;
	}
	snprintf(path, sizeof(path), "%s/.dsi/%s", home, name);

	FILE *fp = fopen(path, "rb");
	if (fp == 0)
	{
		return -1;
	}

	if (fread(key, len, 1, fp) != 1)
	{
		fclose(fp);
		return -1;
	}
	fclose(fp);

	return 0;
}

int main(int argc, char *argv[])
{
	int rv;
	int i;
	printf("%s for dsi by booto\n", argv[0]);
	if(argc != 3)
	{
		printf("usage: %s sd_save.bin base_for_output\n"
			"    files will be created by appending extensions to base_for_output\n"
			"    e.g. if base_for_output is 'test' the banner will be in 'test.banner'\n", argv[0]);
		return 1;
	}

	uint8_t key[0x10];
	rv = get_key("sd_key", key, sizeof(key));
	if(rv != 0)
	{
		printf("error loading sd_key\n");
		return 1;
	}

	int input_fd = open(argv[1],  O_RDONLY);

	if(input_fd < 0)
	{
		perror("open");
		return 1;
	}

	struct stat st;
	fstat(input_fd, &st);

	uint8_t *mapped_file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, input_fd, 0);

	if(mapped_file == MAP_FAILED)
	{
		perror("mmap");
		close(input_fd);
		return 1;
	}
	
	printf("decrypting tna4\n");
	
	rv = decrypt_to_buffer(key, mapped_file+EOFF_TNA4, tna4_buffer,
			ESIZE_TNA4, NULL); 
	if(rv < 0)
	{
		printf("error decrypting tna4: %d\n", rv);
		munmap(mapped_file, st.st_size);
		close(input_fd);

		return 1;
	}

	tna4_t *tna4 = (tna4_t*)tna4_buffer;
	if(tna4_magic != le32toh(tna4->magic))
	{
		printf("error: magic is incorrect\n");
		munmap(mapped_file, st.st_size);
		close(input_fd);
		return 1;
	}



	printf("tna4:\n");
	printf("magic:    %08x\n", le32toh(tna4->magic));
	printf("group_id: %04hx\n", le16toh(tna4->group_id));
	printf("version:  %04hx\n", le16toh(tna4->version));
	printf("mac:      %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
		tna4->mac[5], tna4->mac[4], tna4->mac[3], tna4->mac[2],
		tna4->mac[1], tna4->mac[0]);
	printf("titleid:  %08x-%08x\n", le32toh(tna4->titleid_1),
		le32toh(tna4->titleid_2));
	printf("contents:\n");
	if(le32toh(tna4->tmd_elength) != 0)
	{
		printf(" tmd: 0x%08x ebytes\n",
			le32toh(tna4->tmd_elength));
	}
	for(i=0; i<CI_CONTENT_COUNT; i++)
	{
		if(le32toh(tna4->content_elength[i]) != 0)
		{
			printf(" content(index:0x%02hhx, id:0x%08x): 0x%08x ebytes\n",
				i,
				le32toh(tna4->content_id[i]),
				le32toh(tna4->content_elength[i]));
		}
	}
	if(le32toh(tna4->savedata_elength) != 0)
	{
		printf(" savedata: 0x%08x ebytes [0x%08x bytes]\n",
			le32toh(tna4->savedata_elength),
			le32toh(tna4->savedata_length));
	}
	if(le32toh(tna4->bannersav_elength) != 0)
	{
		printf(" bannersav: 0x%08x ebytes\n",
			le32toh(tna4->bannersav_elength));
	}

	printf("decrypting footer\n");
	
	rv = decrypt_to_buffer(key, mapped_file+EOFF_FOOTER, footer_buffer,
			ESIZE_FOOTER, NULL); 
	if(rv < 0)
	{
		printf("error decrypting footer: %d\n", rv);
		munmap(mapped_file, st.st_size);
		close(input_fd);

		return 1;
	}

	footer_t *footer = (footer_t*)footer_buffer;

	printf("saving footer\n");
	rv = save_section(argv[2], "footer", footer_buffer, sizeof(footer_buffer));
	if(rv < 0)
	{
		printf("error saving footer: %d\n", rv);
		munmap(mapped_file, st.st_size);
		close(input_fd);
		return 1;
	}

	printf("checking tna4 sha1... ");
	SHA1(tna4_buffer, sizeof(tna4_buffer), temp_hash);

	if(memcmp(temp_hash, footer->tna4_hash, sizeof(sha1_hash))==0)
	{
		printf("GOOD!\n");
		printf("saving tna4\n");
		rv = save_section(argv[2], "tna4", tna4_buffer, sizeof(tna4_buffer));
		if(rv < 0)
		{
			printf("error saving tna4: %d\n", rv);
			munmap(mapped_file, st.st_size);
			close(input_fd);
			return 1;
		}
	}
	else
	{
		printf("BAD!\n");
	}


	printf("decrypting banner\n");
	
	rv = decrypt_to_buffer(key, mapped_file+EOFF_BANNER, banner_buffer,
			ESIZE_BANNER, NULL); 
	if(rv < 0)
	{
		printf("error decrypting banner: %d\n", rv);
		munmap(mapped_file, st.st_size);
		close(input_fd);

		return 1;
	}


	printf("checking banner sha1... ");
	SHA1(banner_buffer, sizeof(banner_buffer), temp_hash);
	if(memcmp(temp_hash, footer->banner_hash, sizeof(sha1_hash))==0)
	{
		printf("GOOD!\n");
		printf("saving banner\n");
		rv = save_section(argv[2], "banner", banner_buffer, sizeof(banner_buffer));
		if(rv < 0)
		{
			printf("error saving banner: %d\n", rv);
			munmap(mapped_file, st.st_size);
			close(input_fd);
			return 1;
		}
	}
	else
	{
		printf("BAD!\n");
	}

// skip tmd and contents - different key
	int32_t offset_to_savedata = EOFF_TMD + le32toh(tna4->tmd_elength);
	for(i=0; i<CI_CONTENT_COUNT; i++)
	{
		offset_to_savedata += le32toh(tna4->content_elength[i]);
	}

	if(le32toh(tna4->savedata_elength) != 0)
	{
		printf("decrypting savedata\n");

		uint32_t savedata_length = le32toh(tna4->savedata_length);
		uint8_t *savedata_buffer = malloc(savedata_length);

		if(savedata_buffer == NULL)
		{
			printf("error allocating buffer for savedata\n");
			munmap(mapped_file, st.st_size);
			close(input_fd);
			return 1;
		}

	
		uint32_t old_savedata_length = savedata_length;
		rv = decrypt_to_buffer(key, mapped_file + offset_to_savedata,
			savedata_buffer, le32toh(tna4->savedata_elength),
			&savedata_length); 
		if(rv < 0)
		{
			printf("error decrypting savedata: %d\n", rv);
			munmap(mapped_file, st.st_size);
			close(input_fd);
			return 1;
		}
	
		if(savedata_length != old_savedata_length)
		{
			printf("savedata length discrepency: 0x%08x != 0x%08x\n",
				savedata_length,
				old_savedata_length);
			munmap(mapped_file, st.st_size);
			close(input_fd);
			return 1;
		}

		printf("checking savedata sha1... ");
		SHA1(savedata_buffer, savedata_length, temp_hash);
		if(memcmp(temp_hash, footer->savedata_hash, sizeof(sha1_hash))==0)
		{
			printf("GOOD!\n");
			rv = save_section(argv[2], "savedata", savedata_buffer, savedata_length);
			if(rv < 0)
			{
				printf("error saving savedata: %d\n", rv);
				munmap(mapped_file, st.st_size);
				close(input_fd);
				return 1;
			}
		}
		else
		{
			printf("BAD!\n");
		}
		free(savedata_buffer);
	}

	if(offset_to_savedata + le32toh(tna4->savedata_elength) +
		le32toh(tna4->bannersav_elength) > st.st_size)
	{
		printf("used up too many bytes ?!\n");
	}
	else if(offset_to_savedata + le32toh(tna4->savedata_elength) +
		le32toh(tna4->bannersav_elength) != st.st_size)
	{
		printf("unused trailer of %ld bytes\n", st.st_size -
			(offset_to_savedata + le32toh(tna4->savedata_elength) +
			le32toh(tna4->bannersav_elength)));
	}

	munmap(mapped_file, st.st_size);
	close(input_fd);

	return 0;

}
