#include "bip32.h"
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include "bip39.h"
#include "ecdsa.h"
#include "sha3.h"
#include "sha2.h"
#include "curves.h"
#include "secp256k1.h"
#include "ripemd160.h"
#include "segwit_addr.h"

void print_Hex(const char *title, uint8_t * mesg, const uint32_t limit){
    printf("%s", title);
    uint32_t i = 0;
    for(i; i < limit; i++){
        if(mesg[i] <16 )printf("0");
        printf("%x", mesg[i]);
    }
    printf("\n");
}

static uint8_t CONFIDENTIAL sessionSeed[64];

char BASE_58_ALPHABET[] = { '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q',
		'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
		'w', 'x', 'y', 'z' };

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};

static int mod_table[] = {0, 2, 1};

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (size_t i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}

unsigned int encode_base_x(const char * alphabet, const unsigned int alphabet_len, const void * in, const unsigned int in_length, char * out,
		const unsigned int out_length) {
	char tmp[64];
	char buffer[128];
	unsigned char buffer_ix;
	unsigned char startAt;
	unsigned char zeroCount = 0;
	
	memmove(tmp, in, in_length);
	while ((zeroCount < in_length) && (tmp[zeroCount] == 0)) {
		++zeroCount;
	}
	buffer_ix = 2 * in_length;
	

	startAt = zeroCount;
	while (startAt < in_length) {
		unsigned short remainder = 0;
		unsigned char divLoop;
		for (divLoop = startAt; divLoop < in_length; divLoop++) {
			unsigned short digit256 = (unsigned short) (tmp[divLoop] & 0xff);
			unsigned short tmpDiv = remainder * 256 + digit256;
			tmp[divLoop] = (unsigned char) (tmpDiv / alphabet_len);
			remainder = (tmpDiv % alphabet_len);
		}
		if (tmp[startAt] == 0) {
			++startAt;
		}
		buffer[--buffer_ix] = *(alphabet + remainder);
	}
	while ((buffer_ix < (2 * in_length)) && (buffer[buffer_ix] == *(alphabet + 0))) {
		++buffer_ix;
	}
	while (zeroCount-- > 0) {
		buffer[--buffer_ix] = *(alphabet + 0);
	}
	const unsigned int true_out_length = (2 * in_length) - buffer_ix;
	
	memmove(out, (buffer + buffer_ix), true_out_length);
	return out_length;
}

void get_mnemonic_to_seed(char *mnemo,uint8_t *seed){
  mnemonic_to_seed(mnemo, "", seed, NULL);}

void get_node_from_seed(uint8_t *sessionSeed, HDNode *node){
  uint8_t ssSize=64;
  
  hdnode_from_seed(sessionSeed, ssSize, SECP256K1_NAME, node);
}

void get_private_key_from_node(HDNode *inout)
{
uint8_t adress_size=5;
uint32_t address_n[5]={0x80000000+44, 0x80000000+118, 0x80000000+0,0,0};
hdnode_private_ckd_cached(inout, address_n, adress_size, 0);
}

void adress58(uint8_t *address12, uint8_t *address58){
  uint8_t sha[32];
  uint8_t addchecksum[25];
  sha256_Raw(address12,21,sha);
  sha256_Raw(sha,32,sha);
  memmove(addchecksum, address12,21);
  memmove(addchecksum+21, sha, 4); 
  encode_base_x(BASE_58_ALPHABET, sizeof(BASE_58_ALPHABET),addchecksum,25,(char *)address58,34);
}


int convert_bits(uint8_t* out, size_t* outlen, int outbits, const uint8_t* in, size_t inlen, int inbits, int pad) {
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (((uint32_t)1) << outbits) - 1;
    while (inlen--) {
        val = (val << inbits) | *(in++);
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            out[(*outlen)++] = (val >> bits) & maxv;
        }
    }
    if (pad) {
        if (bits) {
            out[(*outlen)++] = (val << (outbits - bits)) & maxv;
        }
    } else if (((val << (outbits - bits)) & maxv) || bits >= inbits) {
        return 0;
    }
    return 1;
}

void string2hexString(char* input, char* output)
{
    int loop;
    int i; 
    
    i=0;
    loop=0;
    
    while(input[loop] != '\0')
    {
        sprintf((char*)(output+i),"%02x", input[loop]);
        loop+=1;
        i+=2;
    }
    //insert NULL at the end of the output string
    output[i++] = '\0';
}

void cosmos_test(){
    printf("\tCOSMOS TEST\n\n");
    int count;
    uint8_t hashAddress[32];
    uint8_t address12[21];
    uint8_t address58[34];  

    HDNode node;    
    char mnemonic[] = {"cluster unveil differ bright define prosper hunt warrior fetch rough host fringe worry mention gospel enlist elder laugh segment funny avoid regular market fortune"};
    get_mnemonic_to_seed(mnemonic,sessionSeed);
    get_node_from_seed(sessionSeed,&node);
    get_private_key_from_node(&node);
    print_Hex("Private_key = ", node.private_key, sizeof(node.private_key));

    ecdsa_get_public_key33(&secp256k1, node.private_key,node.public_key);
    
    print_Hex("Public key = ", node.public_key, sizeof(node.public_key));
    uint8_t adresscosmo[32]={0};
    uint8_t adresscosmo1[20]={0};
    uint8_t adresscosmo2[50]={0};    
    
    sha256_Raw(node.public_key,sizeof(node.public_key),adresscosmo);    
    ripemd160(adresscosmo,sizeof(adresscosmo),adresscosmo1);

    uint8_t ww[32]={0};
    uint8_t qq[32]={0};
    size_t s=0;
    convert_bits(qq,&s,5,adresscosmo1,20,8,1);
    bech32_encode((char *)adresscosmo2,"cosmos",qq,32);
    printf("Adress = ");
    for (size_t i = 0; i <sizeof(adresscosmo2); i++)
    {
      printf("%c",adresscosmo2[i]);
    } 
    printf("\n");   
    
    size_t pp=0;
    char *pub64=base64_encode(node.public_key,33,&pp);
    printf("Public Key Base64 = %s\n", pub64);

    char text[] = "{\"account_number\":\"";
    char *text01= "35548";                                            
    char text1[] = "\",\"chain_id\":\"";
    char *text11 = "cosmoshub-3";
    char text2[] = "\",\"fee\":{\"amount\":[{\"amount\":\"";     
    char *text21 = "1000";
    char text3[] = "\",\"denom\":\"";
    char *text31 = "uatom";                                                       
    char text4[] = "\"}],\"gas\":\"";
    char *text41 = "40000";
    char text5[] = "\"},\"memo\":\"\",\"msgs\":[{\"type\":\"cosmos-sdk/MsgSend\",\"value\":{\"amount\":[{\"amount\":\"";
    char *text51 = "1";
    char text6[] = "\",\"denom\":\"";
    char *text61 = "uatom";
    char text7[] = "\"}],\"from_address\":\"";
    char *text71 = adresscosmo2;
    char text8[] = "\",\"to_address\":\"";
    char *text81 = "cosmos1mrlrasc996kyp039xz8nq6jc56zkrukuhhhl94";
    char text9[] = "\"}}],\"sequence\":\"";
    char *text91 = "1";
    char text10[] = "\"}";
    char check[1000];
    sprintf(check,"%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",text,text01,text1,text11,text2,text21,text3,text31,text4,text41,text5,text51,text6,text61,text7,text71,text8,text81,text9,text91,text10);
    printf("Checking = %s\n",check);

    int len = strlen(check);
    char hex_str[(len*2)+1];
    string2hexString(check, hex_str);
    size_t length = sizeof(hex_str);
    unsigned char bytearray[length / 2];

    for (size_t i = 0, j = 0; i < (length / 2); i++, j += 2)
	    bytearray[i] = (hex_str[j] % 32 + 9) % 25 * 16 + (hex_str[j+1] % 32 + 9) % 25;
    // print_Hex("check = ",bytearray,sizeof(bytearray));

    uint8_t tx[32]={0};
    sha256_Raw(bytearray,sizeof(bytearray),tx);    
    // print_Hex("tx_id = ",tx1,sizeof(tx));

    uint8_t signature[64]={0};
    ecdsa_sign_digest(&secp256k1, node.private_key, tx, signature, NULL,NULL);    
    // print_Hex("Signature = ",signature1,sizeof(signature1));

    size_t tt=0;
    char *sig64=base64_encode(signature,64,&tt);
    // printf("size of sig64 = %ld",strlen(sig64));
    printf("Signature Base 64 = %s\n", sig64);
    printf("\n\n\tCOSMOS TEST end\n\n");
}