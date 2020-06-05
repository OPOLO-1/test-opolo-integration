#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "sha3.h"
#include "bip32.h"
#include "base58.h"
#include "bip39.h"
#include "memzero.h"
#include "curves.h"
#include "cardano.h"
#include "address.h"
#include "bignum.h"
#include "seed.h"
#include "fsm_iota.h"
#include "hmac.h"
//#define CX_LAST (1 << 0)
#define CX_NO_REINIT (1 << 15)

//#define MAX(a, b) ({ typeof(a) _a = (a); typeof(b) _b = (b); _a > _b ? _a : _b; })


//typedef SHA3_CTX cx_hash_t;
/*void print_hex(const char *title, uint8_t * mesg, const uint32_t limit){
    printf("%s", title);
    uint32_t i = 0;
    for(i; i < limit; i++){
        if(mesg[i] <16 )printf("0");
        printf("%x", mesg[i]);
    }
    printf("\n");
}*/

/*void cx_hash(cx_hash_t *hash, int mode, const unsigned char *in, unsigned int len, unsigned char *out, unsigned int out_len)
{
    //print_hex("input = ", (char *)in, len);
    if (mode != CX_LAST) {
        // if CX_LAST is not set, add input data to add to current hash
        keccak_Update(hash, in, len);
        //printf("nothing \r\n");
    }
    else if (len == 0) {
        // if no input data given, compute and copy the hash
        unsigned char hash_bytes[48];
        keccak_Final(hash, hash_bytes);
        memcpy(out, hash_bytes, MAX(out_len, 48u));
        //print_hex("output = ", hash_bytes, 48);
    }
    else {
        // if CX_LAST is set, compute hash for input
        keccak_Update(hash, in, len);
        unsigned char hash_bytes[48];
        keccak_Final(hash, hash_bytes);
        memcpy(out, hash_bytes, MAX(out_len, 48u));
        //print_hex("output = ", hash_bytes, 48);
    }


}
*/

void monero_get_address(void){
    uint32_t path[5]={0};
    path[0] = 0x8000002C;
    path[1] = 0x80000080;
    path[2] = 0x80000000;
    path[3] = 0x00000000;
    path[4] = 0x00000000;

    uint8_t sessionSeed[64];

    const char mnemonic[] = {"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"};

    mnemonic_to_seed(mnemonic, "", sessionSeed, NULL);

    print_hex("Mnemonic to seed = ", sessionSeed, 64);

    HDNode node;
    hdnode_from_seed(sessionSeed, 64, SECP256K1_NAME, &node);

    hdnode_private_ckd_cached(&node, path, 5, 0);

    print_hex("seed = ", node.private_key, 32);
    print_hex("chain_code = ", node.chain_code, 32);
    uint8_t msg[] = {"Bitcoin seed"};
    print_hex("msg in bytes = ", msg, 12);
    uint8_t hmac[64] = {0};

    hmac_sha512(sessionSeed, 64, msg, 12, hmac);
    print_hex("hmac = ", hmac, 64);

}