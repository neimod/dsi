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
#include <assert.h>
#include "ec.h"

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
	int32_t content_id[8];
	int32_t savedata_length;
	uint8_t reserved[0x3c];
} tna4_t;

typedef uint8_t sha1_hash[0x14];

typedef struct ecc_point_t
{
	uint8_t r[0x1e];
	uint8_t s[0x1e];
} __attribute__((packed)) ecc_point_t;

typedef struct ecc_cert_t
{
	struct {
		uint32_t type;
		ecc_point_t val;
		uint8_t padding[0x40];
	} sig;
	char issuer[0x40];
	uint32_t key_type;
	char key_id[0x40];
	uint32_t unk;
	ecc_point_t pubkey;
	uint8_t padding2[0x3c];
} __attribute__((packed)) ecc_cert_t;

typedef struct footer_t
{
	sha1_hash banner_hash;
	sha1_hash tna4_hash;
	sha1_hash tmd_hash;
	sha1_hash content_hash[8];
	sha1_hash savedata_hash;
	sha1_hash bannersav_hash;
	ecc_point_t sig;
	ecc_cert_t ap;
	ecc_cert_t tw;
} footer_t;

#define CI_CONTENT_COUNT 8
#define CI_CONTENT_FIRST 0
#define CI_CONTENT_LAST 7

// old values
//#define CI_TMD 0
//#define CI_CONTENT_FIRST 1
//#define CI_CONTENT_LAST 8
//#define CI_SAVEDATA 9
//#define CI_BANNERSAV 10

#define SIZE_TNA4 0xb4
#define ESIZE_TNA4 0xd4
#define SIZE_FOOTER 0x440
#define ESIZE_FOOTER 0x460
#define EOFF_BANNER 0
#define SIZE_BANNER 0x4000
#define ESIZE_BANNER 0x4020
#define EOFF_TNA4 (EOFF_BANNER+ESIZE_BANNER)
#define ESIZE_TNA4 0xd4
#define EOFF_FOOTER (EOFF_TNA4 + ESIZE_TNA4)
#define ESIZE_FOOTER 0x460
#define EOFF_TMD (EOFF_FOOTER + ESIZE_FOOTER)


int get_encrypted_size(int normal_size)
{
	int extra = normal_size % 0x20000;
	int normal_blocks = normal_size / 0x20000;

	int rv =  normal_blocks*0x20020;
	if(extra > 0)
	{
		rv += extra + 0x20;
	}

	return rv;
}

int load_file_to_buffer(char *filename, uint8_t *buffer, int32_t expected_length)
{
	struct stat st;
	int fd = open(filename, O_RDONLY);
	if(fd == -1)
	{
		return -1;
	}

	if(fstat(fd, &st) != 0)
	{
		close(fd);
		return -2;
	}

	if(expected_length != st.st_size)
	{
		close(fd);
		return -2;
	}
	
	FILE *infile = fdopen(fd, "rb");
	if(infile == NULL)
	{
		close(fd);
		return -3;
	}

	fread(buffer, expected_length, 1, infile);

	fclose(infile);

	return 0;
}

uint8_t buffer[0x20020];
int encrypt_to_file(uint8_t *key, FILE *output, uint8_t *src, int32_t length)
{
	int32_t bytes_to_enc = 0;
	int32_t total_enc_bytes = 0;
	dsi_es_context dec;
	dsi_es_init(&dec, key);
	while(length > 0)
	{
		bytes_to_enc = 0x20000;
		if(bytes_to_enc > length)
		{
			bytes_to_enc = length;
		}

		memcpy(buffer, src, bytes_to_enc);

		dsi_es_encrypt(&dec, buffer, buffer + bytes_to_enc, bytes_to_enc);

		fwrite(buffer, bytes_to_enc + 0x20, 1, output);

		total_enc_bytes += bytes_to_enc;
		src += bytes_to_enc;
		length -= bytes_to_enc;
	}

	return 0;
}
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


uint32_t tna4_magic = 0x544e4134;


uint8_t tna4_buffer[SIZE_TNA4];
uint8_t footer_buffer[SIZE_FOOTER];


char *banner_path = NULL;
uint8_t banner_buffer[SIZE_BANNER];

char *savedata_path = NULL;
uint8_t *savedata_buffer = NULL;

uint8_t *content_buffer[8] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, };

uint8_t *tmd_buffer = NULL;
uint8_t *bannersav_buffer = NULL;

int need_to_resign = 0;


sha1_hash temp_hash;


int get_key(const char *keyring, const char *name, uint8_t *key, uint32_t len)
{
	char path[256];

	char *home = getenv("HOME");
	if (home == NULL)
	{
		return -1;
	}

	if(keyring == NULL)
	{
		snprintf(path, sizeof(path), "%s/.dsi/%s", home, name);
	}
	else
	{
		snprintf(path, sizeof(path), "%s/.dsi/%s/%s", home, keyring, name);
	}

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

int usage(char *progname)
{
	printf("usage: %s input.bin output.bin <options>\n", progname);
	printf("options:\n");
	printf("	-h          print this usage and exit\n");
	printf("	-b FILE     inject FILE as banner\n");
	printf("	-s FILE     inject FILE as savedata\n");
	printf("	-k KEYRING  use KEYRING for DSi-specfic keys\n");
	printf("                [default: 'default']\n");
	return 0;
}

int resign_footer(char *keyring, footer_t *footer, tna4_t *tna4)
{
	uint8_t tw_priv[0x1e];
	uint8_t dev_kp[0x19e];
	int rv;
	ecc_cert_t *tw_cert = &footer->tw;

	uint8_t ap_priv[0x1e] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, };

	ecc_cert_t *ap_cert = &footer->ap;


	rv = get_key(keyring, "dev.kp", dev_kp, sizeof(dev_kp));
	if(rv < 0)
	{
		rv = get_key(keyring, "ecc_priv", tw_priv, sizeof(tw_priv));
		if(rv < 0)
		{
			printf("error loading ecc_priv\n");
			return -1;
		}

		rv = get_key(keyring, "ecc_pubcert", (uint8_t*)tw_cert, sizeof(*tw_cert));
		if(rv < 0)
		{
			printf("error loading ecc_pubcert\n");
			return -1;
		}
	}
	else
	{
		printf("loading keys from dev.kp\n");
		memcpy(tw_cert, dev_kp, 0x180);
		memcpy(tw_priv, dev_kp+0x180, 0x1e);
	}

	uint8_t tmp_pub[0x3c];
	ec_priv_to_pub(tw_priv, tmp_pub);
	if(memcmp(tmp_pub, &tw_cert->pubkey, sizeof(tmp_pub)) != 0)
	{
		printf("error: ecc priv key does not correspond to the cert\n");
		return -1;
	}

	printf("using silly (but good enough) AP privkey to generate AP cert\n");
	memset(ap_cert, 0, sizeof(*ap_cert));

	// cert chain
	snprintf(ap_cert->issuer, sizeof(ap_cert->issuer), "%s-%s", tw_cert->issuer, tw_cert->key_id);

	// key_id
	snprintf(ap_cert->key_id, sizeof(ap_cert->key_id), "AP%08x%08x", tna4->titleid_1, tna4->titleid_2);

	// key type
	ap_cert->key_type = htobe32(0x00000002UL); 

	// pub key
	ec_priv_to_pub(ap_priv, ap_cert->pubkey.r);

	// sig
	ap_cert->sig.type = htobe32(0x00010002UL);
	// actually sign it

	SHA1((uint8_t*)ap_cert->issuer, sizeof(ecc_cert_t) - sizeof(ap_cert->sig), temp_hash);
	printf("signing ap...\n");
	rv = generate_ecdsa(ap_cert->sig.val.r, ap_cert->sig.val.s, tw_priv, temp_hash);
	if(rv < 0)
	{
		printf("error: problem signing AP\n");
		return -1;
	}

	// now sign the actual footer
	printf("signing footer...\n");
	SHA1(footer_buffer, sizeof(footer_buffer) - sizeof(ecc_point_t) - sizeof(ecc_cert_t) - sizeof(ecc_cert_t), temp_hash);
	rv = generate_ecdsa(footer->sig.r, footer->sig.s, ap_priv, temp_hash);
	if(rv < 0)
	{
		printf("error: problem signing footer\n");
		return -1;
	}

	printf("re-verifying footer sig... ");
	fflush(stdout);
	SHA1(footer_buffer, sizeof(footer_t)-sizeof(ecc_cert_t)-sizeof(ecc_cert_t)-sizeof(ecc_point_t), temp_hash);
	rv = check_ecdsa(ap_cert->pubkey.r, footer->sig.r, footer->sig.s, temp_hash);
	if(rv == 1)
	{
		printf("GOOD!\n");
	}
	else
	{
		printf("BAD - resign was not valid :S\n");
		return -1;
	}
	printf("re-verifying ap sig... ");
	fflush(stdout);
	SHA1((uint8_t*)ap_cert->issuer, sizeof(ecc_cert_t)-sizeof(ap_cert->sig), temp_hash);
	rv = check_ecdsa(tw_cert->pubkey.r, ap_cert->sig.val.r, ap_cert->sig.val.s, temp_hash);
	if(rv == 1)
	{
		printf("GOOD!\n");
	}
	else
	{
		printf("BAD - resign didn't work... exiting\n");
		return -1;
	}

	return 0;
}


void cleanup_buffers()
{
	int i;
	free(tmd_buffer);
	tmd_buffer = NULL;
	for(i=0; i<CI_CONTENT_COUNT; i++)
	{
		free(content_buffer[i]);
		content_buffer[i] = NULL;
	}
	free(savedata_buffer);
	savedata_buffer = NULL;
	free(bannersav_buffer);
	bannersav_buffer = NULL;
}

int main(int argc, char *argv[])
{
	int rv;
	int i;
	char *keyring = "default";
	printf("%s for dsi by booto\n", argv[0]);
	if(argc < 3)
	{
		usage(argv[0]);			
		return 1;
	}

	if(argc > 3)
	{
		int opt_char;
		int opt_argc = argc-2;
		char **opt_argv = argv+2;
		
		// getopt still skips one, treating it as argv[0]

		for(opt_char = getopt(opt_argc, opt_argv, "s:b:k:h");
			opt_char != -1;
			opt_char = getopt(opt_argc, opt_argv, "s:b:k:h"))
		{
			switch(opt_char)
			{
				default:
				case 'h':
				{
					usage(argv[0]);
					return 0;
					break;
				}
				case 'b':
				{
					printf("inject banner: %s\n", optarg);
					banner_path = optarg;
					break;
				}
				case 's':
				{
					printf("inject savedata: %s\n", optarg);
					savedata_path = optarg;
					break;
				}
				case 'k':
				{
					printf("keyring: %s\n", optarg);
					keyring = optarg;
					break;
				}
			}
		}
	}


	uint8_t sd_key[0x10];
	rv = get_key(NULL, "sd_key", sd_key, sizeof(sd_key));
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
	
	rv = decrypt_to_buffer(sd_key, mapped_file+EOFF_TNA4, tna4_buffer,
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
	
	rv = decrypt_to_buffer(sd_key, mapped_file+EOFF_FOOTER, footer_buffer,
			ESIZE_FOOTER, NULL); 
	if(rv < 0)
	{
		printf("error decrypting footer: %d\n", rv);
		munmap(mapped_file, st.st_size);
		close(input_fd);

		return 1;
	}

	footer_t *footer = (footer_t*)footer_buffer;


	printf("checking footer signature... ");
	fflush(stdout);
	SHA1(footer_buffer, sizeof(footer_t)-sizeof(ecc_cert_t)-sizeof(ecc_cert_t)-sizeof(ecc_point_t), temp_hash);
	rv = check_ecdsa(footer->ap.pubkey.r, footer->sig.r, footer->sig.s, temp_hash);
	if(rv == 1)
	{
		printf("GOOD!\n");
	}
	else
	{
		printf("BAD - need to resign!\n");
		need_to_resign = 1;
	}

	printf("checking ap signature... ");
	fflush(stdout);
	SHA1((uint8_t*)footer->ap.issuer, sizeof(ecc_cert_t)-sizeof(footer->ap.sig), temp_hash);

	rv = check_ecdsa(footer->tw.pubkey.r, footer->ap.sig.val.r, footer->ap.sig.val.s, temp_hash);
	if(rv == 1)
	{
		printf("GOOD!\n");
	}
	else
	{
		printf("BAD - need to resign!\n");
		need_to_resign = 1;
	}


	printf("checking tna4 sha1... ");
	fflush(stdout);
	SHA1(tna4_buffer, sizeof(tna4_buffer), temp_hash);

	if(memcmp(temp_hash, footer->tna4_hash, sizeof(sha1_hash))==0)
	{
		printf("GOOD!\n");
	}
	else
	{
		printf("BAD!... need to resign?\n");
		SHA1(banner_buffer, SIZE_BANNER,
			footer->banner_hash);
		need_to_resign = 1;
	}

	if(banner_path != NULL)
	{
		printf("injecting %s as banner...\n", banner_path);
		rv = load_file_to_buffer(banner_path, banner_buffer, SIZE_BANNER);
		if(rv != 0)
		{
			printf("error loading banner, fallback to using existing\n");
			banner_path = NULL;
		}
		else
		{
			printf("generating banner sha1\n");
			SHA1(banner_buffer, SIZE_BANNER, footer->banner_hash);
			need_to_resign = 1;
		}
	}

	if(banner_path == NULL)
	{
		printf("decrypting banner\n");
	
		rv = decrypt_to_buffer(sd_key, mapped_file+EOFF_BANNER, banner_buffer,
			ESIZE_BANNER, NULL); 
		if(rv < 0)
		{
			printf("error decrypting banner: %d\n", rv);
			munmap(mapped_file, st.st_size);
			close(input_fd);
			return 1;
		}
		printf("checking existing banner sha1... ");
		fflush(stdout);
		SHA1(banner_buffer, sizeof(banner_buffer), temp_hash);
		if(memcmp(temp_hash, footer->banner_hash, sizeof(sha1_hash))==0)
		{
			printf("GOOD!\n");
		}
		else
		{
			printf("BAD!...wtf... uh, let's regen!\n");
			SHA1(banner_buffer, SIZE_BANNER,
				footer->banner_hash);
			need_to_resign = 1;
		}
	}


	int32_t curr_offset = EOFF_TMD;
	int32_t tmd_elength = 0x204;

	for(i=0; i<CI_CONTENT_COUNT; i++)
	{
		if(le32toh(tna4->content_elength[i]) != 0)
		{
			printf("content[%d] valid!\n", i);
			tmd_elength += 0x24;
		}
	}

	if(tmd_elength != le32toh(tna4->tmd_elength))
	{
		printf(
			"error: calculated tmd length [0x%08x] is not the same as actual length\n"
			"       [0x%08x], bailing...\n",
			tmd_elength, le32toh(tna4->tmd_elength));

		munmap(mapped_file, st.st_size);
		close(input_fd);

		return 1;
	}

	printf("loading encrypted tmd section...\n");

	tmd_buffer = malloc(le32toh(tna4->tmd_elength));

	if(tmd_buffer == NULL)
	{
		printf("error: could not allocate tmd buffer\n");
		munmap(mapped_file, st.st_size);
		close(input_fd);

		return 1;
		
	}

	assert(mapped_file + curr_offset + le32toh(tna4->tmd_elength) <= mapped_file + st.st_size);
	assert(mapped_file + curr_offset >= mapped_file);

	memcpy(tmd_buffer, mapped_file + curr_offset, le32toh(tna4->tmd_elength));

	curr_offset += le32toh(tna4->tmd_elength);
	for(i=0; i<CI_CONTENT_COUNT; i++)
	{
		if(le32toh(tna4->content_elength[i]) != 0)
		{
			printf("loading encrypted content[%d] section...\n", i);

			content_buffer[i] = malloc(le32toh(tna4->content_elength[i]));

			if(content_buffer[i] == NULL)
			{
				printf("error: could not allocate content[%d] buffer\n", i);
				munmap(mapped_file, st.st_size);
				close(input_fd);

				return 1;
			}

			assert(mapped_file + curr_offset + le32toh(tna4->content_elength[i]) <= mapped_file + st.st_size);
			assert(mapped_file + curr_offset >= mapped_file);
			memcpy(content_buffer[i], mapped_file + curr_offset,
				le32toh(tna4->content_elength[i]));
			curr_offset += le32toh(tna4->content_elength[i]);
		}
	}

	if(le32toh(tna4->savedata_elength) != 0)
	{
			printf("[%10.10s] {%08x,%08x,%08x,%08x}\n", "savedata", (uint32_t)mapped_file, curr_offset, (uint32_t)st.st_size, le32toh(tna4->savedata_elength));
		savedata_buffer = malloc(le32toh(tna4->savedata_length));
		if(savedata_buffer == NULL)
		{
			printf("error allocating 0x%08x bytes for savedata buffer, exiting\n",
				le32toh(tna4->savedata_length));
			cleanup_buffers();
			return 1;
		}
	
		if(savedata_path != NULL)
		{
			printf("injecting %s as savedata...\n", savedata_path);
	
			rv = load_file_to_buffer(savedata_path, savedata_buffer,
				le32toh(tna4->savedata_length));
			if(rv != 0)
			{
				printf("error loading savedata, fallback to using existing\n");
				savedata_path = NULL;
			}
			else
			{
				printf("generating savedata sha1\n");
				SHA1(savedata_buffer, le32toh(tna4->savedata_length),
					footer->savedata_hash);
				need_to_resign = 1;
			}
		}
	
		if(savedata_path == NULL)
		{
			printf("decrypting savedata\n");
		
			rv = decrypt_to_buffer(sd_key, mapped_file+curr_offset, savedata_buffer,
				le32toh(tna4->savedata_elength), NULL); 
			if(rv < 0)
			{
				printf("error decrypting savedata: %d\n", rv);
	
				// cleanup
				munmap(mapped_file, st.st_size);
				close(input_fd);
				cleanup_buffers();
				return 1;
			}
			printf("checking existing savedata sha1... ");
			fflush(stdout);
			SHA1(savedata_buffer, le32toh(tna4->savedata_length), temp_hash);
			if(memcmp(temp_hash, footer->savedata_hash, sizeof(sha1_hash))==0)
			{
				printf("GOOD!\n");
			}
			else
			{
				printf("BAD!...wtf... uh, let's regen!\n");
				SHA1(savedata_buffer, le32toh(tna4->savedata_length),
					footer->savedata_hash);
				need_to_resign = 1;
			}
		}
		curr_offset += le32toh(tna4->savedata_elength);
	}

	if(le32toh(tna4->bannersav_elength) != 0)
	{
		// never actually seen this section in an export
		// let me know if you ever see it
		bannersav_buffer = malloc(le32toh(tna4->bannersav_elength));

		if(bannersav_buffer == NULL)
		{
			printf("error: could not allocate bannersav buffer (0x%08x)\n",
				le32toh(tna4->bannersav_elength));
			munmap(mapped_file, st.st_size);
			close(input_fd);
			cleanup_buffers();
			return -1;
		}

		assert(mapped_file + curr_offset + le32toh(tna4->bannersav_elength) <= mapped_file + st.st_size);
		assert(mapped_file + curr_offset >= mapped_file);
		memcpy(bannersav_buffer, mapped_file + curr_offset,
			le32toh(tna4->bannersav_elength));

		curr_offset += le32toh(tna4->bannersav_elength);
	}

	if(curr_offset > st.st_size)
	{
		printf("used up too many bytes ?! at offset 0x%08x should be at 0x%08x\n", (uint32_t)curr_offset, (uint32_t)st.st_size);
	}
	else if(curr_offset < st.st_size)
	{
		printf("unused trailer of %ld bytes\n", st.st_size - curr_offset);
	}

	if(need_to_resign == 1)
	{
		printf("need to resign!\n");
		if(resign_footer(keyring, footer, tna4) < 0)
		{
			munmap(mapped_file, st.st_size);
			close(input_fd);
			cleanup_buffers();
			return -1;
		}
	}


	// now to output...

	printf("writing out to %s\n", argv[2]);
	FILE *output_file = fopen(argv[2], "wb");

	if(output_file == NULL)
	{
		printf("error opening output\n");
		cleanup_buffers();
		return 1;
	}

	printf("encrypting and writing banner...\n");
	rv = encrypt_to_file(sd_key, output_file, banner_buffer, SIZE_BANNER);
	if(rv < 0)
	{
		printf("error writing banner\n");
		fclose(output_file);
		munmap(mapped_file, st.st_size);
		close(input_fd);
		cleanup_buffers();
		return -1;
	}
	printf("encrypting and writing tna4...\n");
	rv = encrypt_to_file(sd_key, output_file, tna4_buffer, SIZE_TNA4);
	if(rv < 0)
	{
		printf("error writing tna4\n");
		fclose(output_file);
		munmap(mapped_file, st.st_size);
		close(input_fd);
		cleanup_buffers();
			
		return -1;
	}
	printf("encrypting and writing footer...\n");
	rv = encrypt_to_file(sd_key, output_file, footer_buffer, SIZE_FOOTER);
	if(rv < 0)
	{
		printf("error writing footer\n");
		fclose(output_file);
		munmap(mapped_file, st.st_size);
		close(input_fd);
		cleanup_buffers();
		return -1;
	}

	printf("writing tmd...\n");
	fwrite(tmd_buffer, le32toh(tna4->tmd_elength), 1, output_file);

	for(i=0; i<CI_CONTENT_COUNT; i++)
	{
		if(le32toh(tna4->content_elength[i]) != 0)
		{
			printf("writing content%d...\n", i);
			fwrite(content_buffer[i], le32toh(tna4->content_elength[i]), 1,
				output_file);
		}
	}

	if(le32toh(tna4->savedata_elength) != 0)
	{
		printf("encrypting and writing savedata...\n");
		rv = encrypt_to_file(sd_key, output_file, savedata_buffer,
			le32toh(tna4->savedata_length));
	}

	if(le32toh(tna4->bannersav_elength) != 0)
	{
		printf("writing bannersav...\n");
		rv = fwrite(bannersav_buffer, le32toh(tna4->bannersav_elength), 1,
			output_file);
	}

	fclose(output_file);



	munmap(mapped_file, st.st_size);
	close(input_fd);
	cleanup_buffers();
		
	return 0;

}
