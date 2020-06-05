/*
Authored by Hussain Rizvi

Useful Links:

For adress generation and private key generation
path used 44'/195'/0'/0/0
https://github.com/TronWallet/trx-ledger

Main link to access raw_tx
https://developers.tron.network/

Python Library for matching generated HASH(trx_id)
https://github.com/iexbase/tron-api-python

Emulator for testing
https://github.com/LedgerHQ/speculos/blob/master/doc/build.md

.ELF file of TRON for emulator of speculos
https://github.com/TronWallet/trx-ledger/releases/download/v0.1.5rc/app.elf

Library link for testing on desktop app
https://www.npmjs.com/package/tronweb

*/

#include "bip32.h"
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "bip39.h"
#include "ecdsa.h"
#include "sha3.h"
#include "sha2.h"
#include "curves.h"
#include "secp256k1.h"


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
uint32_t address_n[5]={0x80000000+44, 0x80000000+195, 0x80000000+0,0,0};
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

void tron_test(){
    printf("\tTRON TEST\n\n");
    int count;
    uint8_t hashAddress[32];
    uint8_t address12[21];
    uint8_t address58[34];  

    HDNode node;    
    char mnemonic[] = {"cluster unveil differ bright define prosper hunt warrior fetch rough host fringe worry mention gospel enlist elder laugh segment funny avoid regular market fortune"};
    get_mnemonic_to_seed(mnemonic,sessionSeed);    
    get_node_from_seed(sessionSeed,&node);
    get_private_key_from_node(&node);
    print_Hex("Private_key = ", node.private_key, 32);
    ecdsa_get_public_key65(&secp256k1, node.private_key,node.public_key);
    uint8_t publick[65]={0};
    memcpy(publick,node.public_key,65);
    print_Hex("Public key = ", publick, 65);
    keccak_256(publick+1,64,hashAddress);    
    memmove(address12, hashAddress + 11, 21);    
    address12[0]=0x41;
    print_Hex("Address = ", address12,21);
    adress58(address12,address58);
    printf("Adress58 = ");
    for (size_t i = 0; i < sizeof(address58); i++)
    {
      printf("%c",address58[i]);
    }    
    printf("\n");
    uint8_t raw_tx[]="\x0a\x02\xae\xa5\x22\x08\x19\x13\xa3\xe0\x66\x68\x25\xdb\x40\xc0\xc0\xcc\xdc\x88\x2e\x5a\x65\x08\x01\x12\x61\x0a\x2d\x74\x79\x70\x65\x2e\x67\x6f\x6f\x67\x6c\x65\x61\x70\x69\x73\x2e\x63\x6f\x6d\x2f\x70\x72\x6f\x74\x6f\x63\x6f\x6c\x2e\x54\x72\x61\x6e\x73\x66\x65\x72\x43\x6f\x6e\x74\x72\x61\x63\x74\x12\x30\x0a\x15\x41\x0f\x2b\x05\x7a\x7d\xad\x74\xef\xf9\x54\x50\xa0\x9b\x6c\xce\xa8\xe3\x3c\xcb\x24\x12\x15\x41\x77\xf9\x5a\xf7\x6a\xe3\x0e\x18\xd7\xb2\xb9\x4c\x09\x7f\x85\x6d\x26\xa9\x7f\xfc\x18\x01\x70\xbc\xf9\xc8\xdc\x88\x2e";
    printf("size of raw_tx = ");
    printf("%ld",sizeof(raw_tx));
    printf("\n");
    uint8_t Decodeinadress[60]={0};   
    count=0;
    for (size_t i = sizeof(raw_tx)/2; i <=sizeof(raw_tx); i++)
    {if(raw_tx[i]==0x0a)
    {
      if (raw_tx[i+1]==0x15)      
      {
      for (size_t k = 0; k < 100; k++)
        {if (raw_tx[i]==0x70)
          {break;}
        count=count+1;
        Decodeinadress[k]=raw_tx[i];
        i=i+1;          
        }        
      }
    }
    } 
    print_Hex("data to be decoded = ",Decodeinadress,count);
    print_Hex("raw_tx = ",raw_tx,sizeof(raw_tx)-1);
    uint8_t tx[32]={0};
    sha256_Raw(raw_tx,sizeof(raw_tx)-1,tx);    
    uint8_t signature[65]={0};
    print_Hex("tx_id = ",tx,sizeof(tx));
    ecdsa_sign_digest(&secp256k1, node.private_key, tx, signature, NULL,NULL);    
    print_Hex("Signature = ",signature,sizeof(signature));
    printf("\n\n\tTRON TEST end\n\n");
}