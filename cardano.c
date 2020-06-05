#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "sha3.h"
#include "bip32.h"
#include "base58.h"
#include "bip39.h"
#include "memzero.h"
#include "ed25519-donna/ed25519.h"
#include "cardano.h"
#include "coin_info.h"
const unsigned int tinf_crc32tab[16] = {
   0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac, 0x76dc4190,
   0x6b6b51f4, 0x4db26158, 0x5005713c, 0xedb88320, 0xf00f9344,
   0xd6d6a3e8, 0xcb61b38c, 0x9b64c2b0, 0x86d3d2d4, 0xa00ae278,
   0xbdbdf21c
};


#define FROMHEX_MAXLEN 512



const uint8_t *fromhex(const char *str) {
  static uint8_t buf[FROMHEX_MAXLEN];
  size_t len = strlen(str) / 2;
  if (len > FROMHEX_MAXLEN) len = FROMHEX_MAXLEN;
  for (size_t i = 0; i < len; i++) {
    uint8_t c = 0;
    if (str[i * 2] >= '0' && str[i * 2] <= '9') c += (str[i * 2] - '0') << 4;
    if ((str[i * 2] & ~0x20) >= 'A' && (str[i * 2] & ~0x20) <= 'F')
      c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
    if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9')
      c += (str[i * 2 + 1] - '0');
    if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F')
      c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
    buf[i] = c;
  }
  return buf;
}

/* crc is previous value for incremental computation, 0xffffffff initially */
uint32_t uzlib_crc32(const void *data, unsigned int length, uint32_t crc)
{
   const unsigned char *buf = (const unsigned char *)data;
   unsigned int i;

   for (i = 0; i < length; ++i)
   {
      crc ^= buf[i];
      crc = tinf_crc32tab[crc & 0x0f] ^ (crc >> 4);
      crc = tinf_crc32tab[crc & 0x0f] ^ (crc >> 4);
   }

   // return value suitable for passing in next time, for final value invert it
   return crc/* ^ 0xffffffff*/;
}

void hdnode_cardano(HDNode *node, uint32_t i){
     uint32_t fp = hdnode_fingerprint(node);
     int res = 0;
    res = hdnode_private_ckd_cardano(node, i);
    //printf("RES = %d \n", res);
      if (!res) {
        memzero(node, sizeof(node));
        //printf("Failed to derive %d \n", i);
      }
      else{
        //printf("i = %x \n", i);
      }
}
bool cardano_get_public_key(char *mnemonic, uint32_t *path, uint32_t ln_path, HDNode *node){

    if(ln_path != 5) return false;
    uint8_t entropy[64];//Seed
    int entropy_len = mnemonic_to_entropy(mnemonic, entropy);
    const int res = hdnode_from_entropy_cardano_icarus(
              "", 0, entropy, entropy_len / 8,
              node);
    uint8_t i = 0;
    for(i; i < 5; i++){
        hdnode_cardano(node, path[i]);
    }
    hdnode_fill_public_key(node);
    //if public is not currect then uncomment next 2 lines
    //hdnode_fill_public_key(node);
    //hdnode_fill_public_key(node);
    return true;
}

void cardano_get_xpub(HDNode *node, uint8_t *xpub, uint32_t ln_xpub){
    memcpy(xpub, node->public_key+1, sizeof(node->public_key)-1);
    memcpy(xpub+32, node->chain_code, sizeof(node->chain_code));
    //return true;
}

void cardano_get_address(HDNode *node, char * addr, size_t *s){
    uint8_t xpub[71];
    memcpy(xpub, fromhex("830082005840"), 6);
    memcpy(xpub+6, node->public_key+1, sizeof(node->public_key)-1);
    memcpy(xpub+38, node->chain_code, sizeof(node->chain_code));
    xpub[70] = 160;

    unsigned char digest[SHA3_256_DIGEST_LENGTH];
    sha3_256(xpub, 71, digest);//hash genration
    unsigned char address[SHA3_256_DIGEST_LENGTH];
    blake2b(digest, SHA3_256_DIGEST_LENGTH, address, 28);

    uint8_t blake2d_t[33];

    memcpy(blake2d_t, fromhex("83581c"), 3);
    memcpy(blake2d_t+3, address, SHA3_256_DIGEST_LENGTH);
    memcpy(blake2d_t+31, fromhex("a000"),2);

    uint32_t crc = 0;
    crc = (uzlib_crc32(blake2d_t, 33, 0 ^ 0xffffffff)) ^ 0xffffffff;

    size_t siz=60;
    uint8_t final_encod [43];

    memcpy(final_encod, fromhex("82d8185821"), 5);
    memcpy(final_encod+5, blake2d_t, 33);
    memcpy(final_encod+38, fromhex("1a"), 1);
        //memcpy(final_encod+39, (const char *) &crc, sizeof(crc));
    final_encod[39] = crc >> 24;
    final_encod[40] = crc >> 16;
    final_encod[41] = crc >> 8;
    final_encod[42] = crc;
    b58enc(addr, &siz, final_encod,43);
    *s = siz;
}

void print(){
    printf("callback\r\n");
}

void print_chr(const char *title, const char * mesg, const uint32_t limit){
    printf("%s", title);
    uint32_t i = 0;
    for(i; i < limit; i++){
         printf("%c", mesg[i]);
    }
    printf("\n");
}

void print_hex(const char *title, uint8_t * mesg, const uint32_t limit){
    printf("%s", title);
    uint32_t i = 0;
    for(i; i < limit; i++){
        if(mesg[i] <16 )printf("0");
        printf("%x", mesg[i]);
    }
    printf("\n");
}

uint8_t* index_cbor(uint32_t index, uint8_t *ret, uint8_t * size){
    uint8_t * pt_ind = (uint8_t *) &index;
    if(index < 24){
        *size = 1;
        ret[0] = pt_ind[0];
    }
    else if(index < 256){
        *size = 2;
        ret[0] = 24;
        ret[1] = pt_ind[3];
    }
    else if(index < 65536){
        *size = 3;
        ret[0] = 25;
        ret[1] = pt_ind[3];
        ret[2] = pt_ind[2];
    }
    else{
        *size = 5;
        ret[0] = 26;
        ret[1] = pt_ind[3];
        ret[2] = pt_ind[2];
        ret[3] = pt_ind[1];
        ret[4] = pt_ind[0];
    }
    return ret;
}

void signature(HDNode *node, uint64_t protocol_magic, uint8_t *blk2b, uint8_t *xpub){
    uint8_t messages[40], te=0, t[8];
    memcpy(messages, fromhex("01"),1);
    index_cbor(protocol_magic, t, &te);
    memcpy(messages+1, t, te);
    memcpy(messages+1+te, fromhex("5820"),2);
    memcpy(messages+3+te, blk2b, 32);
    print_hex("\nMessage = ", messages, 35+te);
    ed25519_public_key pk;
    ed25519_publickey_ext(node->private_key, node->private_key_extension, pk);
    ed25519_sign_ext(messages, 35+te, node->private_key, node->private_key_extension, pk, xpub);
    print_hex("\nSignrature = ", xpub, 64);

}

void witness(HDNode *node, uint8_t type, uint32_t index, uint64_t protocol_magic, uint8_t *blk2b, uint8_t *wit, uint32_t *siz){
    //char mnemonic[] = {"alcohol woman abuse must during monitor noble actual mixed trade anger aisle"};
    /*HDNode node;
    bool a = cardano_get_public_key(mnemonic, path, 5, &node);
    if(a==0){
        return false;
    }*/
    uint8_t temp;
    uint8_t t[8], xpub[64];
    memcpy(wit, fromhex("82"), 1);
    index_cbor(type, t, &temp);
    memcpy(wit+1, t, temp);
    memcpy(wit+1+temp, fromhex("d8185885825840"),7);
    cardano_get_xpub(node, xpub, 64);
    memcpy(wit+8+temp, xpub, 64);
    memcpy(wit+72+temp, fromhex("5840"), 2);

    signature(node, protocol_magic, blk2b,xpub);
    memcpy(wit+74+temp, xpub, 64);
    /*
    //signature
    {
        uint8_t messages[40], te=0;
        memcpy(messages, fromhex("01"),1);
        index_cbor(protocol_magic, t, &te);
        memcpy(messages+1, t, te);
        memcpy(messages+1+te, fromhex("5820"),2);
        memcpy(messages+3+te, blake2b, 32);
        print_hex("\nMessage = ", messages, 40);
        ed25519_public_key pk;

        ed25519_publickey_ext(node.private_key, node.private_key_extension, pk);
        ed25519_sign_ext(messages, 35+te, node.private_key, node.private_key_extension, pk, xpub);
        print_hex("\nSignrature = ", xpub, 64);
        memcpy(wit+74+temp, xpub, 64);
        //temp += te;
        printf("te = %d\n", te);
    }
    */
    *siz = 138+temp;

    printf("siz = %d\n", *siz);
}

void inputs(const uint8_t * prev_hash, uint32_t prev_index, uint8_t *input, uint32_t *siz){
    uint8_t temp;
    uint8_t t[8];

    memcpy(input + 9, prev_hash, 32);
    memcpy(input, fromhex("8200d8185824825820"), 9);

    index_cbor(prev_index, t, &temp);
    memcpy(input + 41, t, temp);
    *siz = 41 + temp;

}

void outputs(uint8_t *db58, uint32_t amount, uint8_t *output, uint32_t *siz){
    uint8_t temp;
    uint8_t t[8];
    memcpy(output, fromhex("82"),1);
    memcpy(output+1, db58, 43);
    index_cbor(amount, t, &temp);
    memcpy(output+44, t, temp);
    *siz = 44 + temp;
}

//char *mnemonic, uint32_t *prev_index, uint32_t **input_path, char **prev_hash, uint32_t *type, uint8_t number_of_input, char **address, uint32_t *amount, uint32_t **output_path
void cardano_sign_tx(){
    char mnemonic[] = {"alcohol woman abuse must during monitor noble actual mixed trade anger aisle"};
    //output
    //char transaction[]={"839f8200d818582482582008abb575fac4c39d5bf80683f7f0c37e48f4e3d96e37d1f6611919a7241b456600ff9f8282d818582183581cda4da43db3fca93695e71dab839e72271204d28b9d964d306b8800a8a0001a7a6916a51a00305becffa0"};
    char transaction[] = {"839f8200d818582482582008abb575fac4c39d5bf80683f7f0c37e48f4e3d96e37d1f6611919a7241b456600ff9f8282d818582183581cda4da43db3fca93695e71dab839e72271204d28b9d964d306b8800a8a0001a7a6916a51a00305becffa0"};
    uint32_t prev_index[2] = {1,0};
    uint32_t input_path[2][5]={0x80000000+44, 0x80000000+1815, 0x80000000+0, 0, 0,0x80000000+44, 0x80000000+1815, 0x80000000+0, 0, 1};
    char prev_hash[2][65] = {"a368251c4119bef7746402317a02a4117b1dfd4d8492b9fc23f47c430cbdc3ab","a368251c4119bef7746402317a02a4117b1dfd4d8492b9fc23f47c430cbdc3ab"};
    uint32_t type[2] = {0,0};
    uint8_t number_of_input = 2;
    //output parameter
    char address[4][60] = {"Ae2tdPwUPEZ4n7EiZoWzcsXfZx4xw81NDDnh4s7F48B2PUSPxdPc4AP35VQ","Ae2tdPwUPEZ9JvwQscudmSnzvACewyFDzRq5AsTyh3GSfUZFxwNJBQoiGJP", "0", "0"};
    //char ad[] = "Ae2tdPwUPEZ75LeaA68vpPE4iZghxbMcwXbXy8z7v8uYFoFrL1PfXrkdTSX";
    //memcpy(address[0], ad, 60);
    uint32_t amount[4] = {2000000, 2000000, 41034000, 41500000};
    uint32_t output_path[4][5];
    output_path[2][0] = 0x80000000+44;
    output_path[2][1] = 0x80000000+1815;
    output_path[2][2] = 0x80000000+0;
    output_path[2][3] = 0;
    output_path[2][4] = 1;

    output_path[3][0] = 0x80000000+44;
    output_path[3][1] = 0x80000000+1815;
    output_path[3][2] = 0x80000000+0;
    output_path[3][3] = 0;
    output_path[3][4] = 0;

    uint8_t number_of_output = 4;
    uint32_t protocol_magic = 764824073;

    uint8_t tx_aux_cbor[800]={0}, i=0;
    uint32_t siz = 2, ts=0;

    //prepration for output
    HDNode node;
    for(i; i<number_of_output; i++){
        if(!strcmp(address[i], "0")){
            cardano_get_public_key(mnemonic, output_path[i], 5, &node);
            size_t s=60;
            cardano_get_address(&node, address[i], &s);
            printf("address = 0/%d\n", i);
            print_chr("",address[i], s);
        }
        else printf("not work \t");
    }
    /*cardano_get_public_key(mnemonic, output_path[1], 5, &node);
    size_t s=60;
    cardano_get_address(&node, address[1], &s);
    print_chr("output path address = ", address[1], s);
    */
    //encoding

    //inputs
    memcpy(tx_aux_cbor, fromhex("839f"), 2);
    for(i=0; i<number_of_input; i++){
        inputs(fromhex(prev_hash[i]), prev_index[i], tx_aux_cbor + siz, &ts);
        //memcpy(tx_aux_cbor + siz, temp, ts);
        siz += ts;
        printf("\ninput 0/%d\n", i);
        print_hex("", tx_aux_cbor, siz);
    }
    memcpy(tx_aux_cbor + siz, fromhex("ff9f"), 2);

    siz += 2;
    //print_hex("\ntx_aux_cbor input = ", tx_aux_cbor, siz);
    //outpur
    for(i=0; i < number_of_output; i++){
        uint8_t db58[43];
        size_t size=43;
        b58tobin(db58, &size, address[i]);
        outputs(db58, amount[i], tx_aux_cbor + siz, &ts);
        //memcpy(tx_aux_cbor + siz, temp, ts);
        siz += ts;
        //print_hex("\ntx_aux_cbor outputs = ", tx_aux_cbor, siz);
    }
    memcpy(tx_aux_cbor + siz, fromhex("ffa0"), 2);
    siz += 2;
    //hashing
    //print_hex("\nblake2b befor = ", tx_aux_cbor, siz);
    //printf("\nsize = %d\n", siz);
    uint8_t blake_tx_aux_cbor[32];
    blake2b(tx_aux_cbor, siz, blake_tx_aux_cbor, 32);
    //signature
    //print_hex("tx_aux_cbor = ", tx_aux_cbor, siz);
    print_hex("\ntx_hash = ", blake_tx_aux_cbor, 32);
    memcpy(tx_aux_cbor+1, tx_aux_cbor, siz);
    memcpy(tx_aux_cbor, fromhex("82"), 1);
    siz ++;
    i = number_of_input + 128;
    memcpy(tx_aux_cbor + siz, &i, 1);
    siz ++;

    for(i = 0; i < number_of_input; i++){
        cardano_get_public_key(mnemonic, input_path[i], 5, &node);
        witness(&node, type[i], prev_index[i], protocol_magic, blake_tx_aux_cbor, tx_aux_cbor + siz, &ts);
        //memcpy(tx_aux_cbor + siz, temp, ts);
        siz += ts;
        //printf("ts = %d\n", siz);
    }
    print_hex("\ntx_body = ", tx_aux_cbor, siz);
    printf("\nsiz = %d\n", siz);

}

void cordano1(){
    const CoinInfo *coin = &coins[1];
    printf("Coin Name = %s", coin->coin_name);
    HDNode node;
    uint32_t address_n[5]={0x80000000+44, 0x80000000+1815, 0x80000000+0, 0, 0};
    char mnemonic[] = {"voyage slight install cake hybrid female maximum screen time awful media despair matter that olive index push decline fancy impact release behind odor welcome"};
    bool a = cardano_get_public_key(mnemonic, address_n, 5, &node);
    if(a){
    uint8_t i =0;
        printf("\nprivate key = ");
        for(i; i<32;i++){
            if(node.private_key[i]<16){
                    printf("0");
                    }
                    printf("%x", node.private_key[i]);
        }

    printf("\nPublic key = ");
             for(i=0; i<=32;i++){
                 if(node.public_key[i]<16){
                     printf("0");
                 }
                 printf("%x", node.public_key[i]);
             }
     }
     char str[60];
     size_t siz=60;
     cardano_get_address(&node, str, &siz);
     print_chr("\nAddress = ", str, siz);
     printf("\n");
}

 void cordano(){
    const CoinInfo *coin = &coins[1];   //coininfo structure set
    printf("Coin Name = %s", coin->coin_name); // print coin name
    HDNode node; //define node veriable of type HDNode
    uint32_t address_n[5]={0x80000000+44, 0x80000000+1815, 0x80000000+0, 0, 1};//path of cardano is m/44'/1815'/0'/0/0
    char mnemonic[] = {"voyage slight install cake hybrid female maximum screen time awful media despair matter that olive index push decline fancy impact release behind odor welcome"};
    //char mnemonic[] = {"all all all all all all all all all all all all"};
    uint8_t entropy[64];//Seed
    int entropy_len = mnemonic_to_entropy(mnemonic, entropy);
    const int res = hdnode_from_entropy_cardano_icarus(
          "", 0, entropy, entropy_len / 8,
          &node);

    hdnode_cardano(&node, address_n[0]);
    hdnode_cardano(&node, address_n[1]);
    hdnode_cardano(&node, address_n[2]);
    hdnode_cardano(&node, address_n[3]);
    hdnode_cardano(&node, address_n[4]);

    uint8_t i =0;
    printf("\nprivate key = ");
    for(i; i<32;i++){
        if(node.private_key[i]<16){
                printf("0");
                }
                printf("%x", node.private_key[i]);
    }
    hdnode_fill_public_key(&node);
    hdnode_fill_public_key(&node);
    hdnode_fill_public_key(&node);

    printf("\nPublic key = ");
        for(i=0; i<=32;i++){
            if(node.public_key[i]<16){
                printf("0");
            }
            printf("%x", node.public_key[i]);
        }

    printf("\nextpubkey = 0x");
    for(i = 1; i<=32; i++){
        if(node.public_key[i]<16){
            printf("0");
        }
        printf("%x", node.public_key[i]);
    }
    for(i = 0; i<32; i++){
            if(node.chain_code[i]<16){
                printf("0");
            }
            printf("%x", node.chain_code[i]);
        }
    printf("\n");
    i =160;
    uint8_t extpub[71];
    memcpy(extpub, fromhex("830082005840"), 6);
    memcpy(extpub+6, node.public_key+1, sizeof(node.public_key)-1);
    memcpy(extpub+38, node.chain_code, sizeof(node.chain_code));
    extpub[70] = 160;

    unsigned char digest[SHA3_256_DIGEST_LENGTH];

    sha3_256(extpub, 71, digest);//hash genration
    printf("\nsha3_256 = ");
    for(i=0; i<SHA3_256_DIGEST_LENGTH ;i++){
        if(digest[i]<16){
            printf("0");
        }
        printf("%x", digest[i]);
    }
    unsigned char address[SHA3_256_DIGEST_LENGTH];
    printf("\nsize of hash = %ld", sizeof(digest));
    blake2b(digest, SHA3_256_DIGEST_LENGTH, address, 28);

    printf("\nblake2b = ");
    for(i=0; i<28 ;i++){
         printf("%x", address[i]);
    }
    uint8_t blake2d_t[33];

    memcpy(blake2d_t, fromhex("83581c"), 3);
    memcpy(blake2d_t+3, address, SHA3_256_DIGEST_LENGTH);
    memcpy(blake2d_t+31, fromhex("a000"),2);
    uint32_t crc = 0;

    crc = (uzlib_crc32(blake2d_t, 33, 0 ^ 0xffffffff)) ^ 0xffffffff;

    printf("\ncrc = %ld\n", (long)crc);

    char str[60];
    uint32_t siz=0;
    uint8_t final_encod [43];

    memcpy(final_encod, fromhex("82d8185821"), 5);
    memcpy(final_encod+5, blake2d_t, 33);
    memcpy(final_encod+38, fromhex("1a"), 1);
    //memcpy(final_encod+39, (const char *) &crc, sizeof(crc));
    final_encod[39] = crc >> 24;
    final_encod[40] = crc >> 16;
    final_encod[41] = crc >> 8;
    final_encod[42] = crc;

   b58enc(str, (size_t *)&siz, final_encod,43);

    printf("base58 = %d \n", siz);
    for(i =0 ; i<siz; i++){
        printf("%c", str[i]);
    }


}
void cardano_test(){
    printf("\t\tCardano test\n\n");
    char mnemonic[] = {"extra extend academic bishop cricket bundle tofu goat apart victim enlarge program behavior permit course armed jerky faint language modern"};
    uint32_t address_n[5]={0x80000000+44, 0x80000000+1815, 0x80000000+0, 0, 2};
    HDNode node;
    cardano_get_public_key(mnemonic, address_n, 5, &node);
    print_hex("Chain code = ", node.chain_code, 32);
    print_hex("Public key = ", node.public_key, 32);
    print_hex("Private_key = ", node.private_key, 32);
    uint8_t xpub[64];
    cardano_get_xpub(&node, xpub, 64);
    print_hex("Chain_code = ", xpub, 64);
    size_t s=60;
    char addr[60];
    cardano_get_address(&node, addr, &s);
    print_chr("Address = ", addr, 60);
    printf("\t\tCardano test end\n\n");
}

void p_p_address(){
    printf("P_p_address enterer\r\n");
    const CoinInfo *coin = &coins[0];
    printf("coin = %s\r\n", coin->coin_name);
    HDNode node;
    printf("after node = NULL\r\n");                        // 0x80000000
    uint32_t address_n[5]={0x80000000+44, 0x80000000+1815, 0x80000000+0, 0, 0};
    printf("address_n[5]={0x80000000+44, 0x80000000+1815, 0x80000000+0, 0, 0}\r\n");
    //const uint8_t *seed = "37dfe3018e0509572c8f36df9ea32eb740130ca4f044b65719d63fa6374508bf226936fd4391ffa09ee03f5bc9f9a0002ef9d40ae93a11abc3bedd72f564afef";
    char mnemonic[] = {"voyage slight install cake hybrid female maximum screen time awful media despair matter that olive index push decline fancy impact release behind odor welcome"};
    //char mnemonic[150] = {"shine wonder erode oak net pupil filter jar coast cook brain build utility hood indicate forum music rice surround check glue denial service convince"};
    uint8_t sessionSeed[64];
    mnemonic_to_seed(mnemonic, "", sessionSeed, print);

    if(hdnode_from_seed(sessionSeed,64,coin->curve_name,&node)){
        printf("hdnode_from_seed work\r\n");
    }
    printf("after hdnode_from_seed\r\n");
    if(hdnode_private_ckd_cached(&node, address_n, 5, NULL)){
        printf("hdnode_private_ckd_cached work\r\n");
    }
    hdnode_fill_public_key(&node);
    printf("private Key = ");
    uint8_t i =0;
    for(i; i<=32 ;i++){
            printf("%x", node.private_key[i]);
    }
    printf("\nPublic Key = ");
    for(i=0; i<=32 ;i++){
        if(node.public_key[i]<16){
        printf("0");
        }
        printf("%x", node.public_key[i]);
    }
    printf("\r\naddress = ");

    char address[130];

    ecdsa_get_address(node.public_key, coin->address_type, coin->curve->hasher_pubkey, coin->curve->hasher_base58, address, 130);

    printf("%s \r\n",address);
    ecdsa_get_address_segwit_p2sh(node.public_key, coin->address_type_p2sh, coin->curve->hasher_pubkey, coin->curve->hasher_base58, address, 130);
    printf("segwit_p2sh = %s\r\n",address);
}


/*void cardano_signtx (){
    char data[]={"839f8200d818582482582008abb575fac4c39d5bf80683f7f0c37e48f4e3d96e37d1f6611919a7241b456600ff9f8282d818582183581cda4da43db3fca93695e71dab839e72271204d28b9d964d306b8800a8a0001a7a6916a51a00305becffa0"};
    unsigned char address[SHA3_256_DIGEST_LENGTH];
    blake2b(fromhex(data), 97, address, 32);
    printf("\nblake2b of transactiuon = ");
    uint8_t i;


    for(i=0; i<32 ;i++){
        printf("%x", address[i]);
    }
    char input_prev_hash[] = "1af8fa0b754ff99253d983894e63a2b09cbb56c833ba18c3384210163f63dcfc";
    uint32_t input_prev_index = 0;
    uint32_t input_path[5]={0x80000000+44, 0x80000000+1815, 0x80000000+0, 0, 1};//path of cardano is m/44'/1815'/0'/0/0
    char output0_address[] = "Ae2tdPwUPEZCanmBz5g2GEwFqKTKpNJcGYPKfDxoNeKZ8bRHr8366kseiK2";
    uint32_t output0_amount = 3003112;
    uint32_t output1_path[5]={0x80000000+44, 0x80000000+1815, 0x80000000+0, 0, 5};//path of cardano is m/44'/1815'/0'/0/0
    uint32_t output1_amount = 7120787;

    uint8_t db58[43];
    size_t s=43;
    b58tobin(db58, &s, output0_address);

    print_hex("\naddress base58decode = ", db58, 43);

    char output1_address[60];
    char input1_address[60];
    HDNode node_out1, node_input1;
    char mnemonic[] = {"voyage slight install cake hybrid female maximum screen time awful media despair matter that olive index push decline fancy impact release behind odor welcome"};
    cardano_get_public_key(mnemonic, output1_path, 5, &node_out1);
    cardano_get_public_key(mnemonic, input_path, 5, &node_input1);

    size_t siz=60;
    cardano_get_address(&node_out1, output1_address, &siz);
    print_chr("\naddress from path 44'1815'0'05 =", output1_address, siz);
    cardano_get_address(&node_input1, input1_address, &siz);
    print_chr("\naddress from path 44'1815'0'01 =", input1_address, siz);

    uint8_t siz_index = 0;
    uint8_t index_8_t[5];
    index_cbor(input_prev_index, index_8_t, &siz_index);
    printf("\nsize index = %d\n", siz_index);
    uint8_t input_cbor[35 + (const uint8_t) siz_index];
    memcpy(input_cbor, fromhex("825820"), 3);
    memcpy(input_cbor+3, fromhex(input_prev_hash), 32);
    memcpy(input_cbor+35, index_8_t, siz_index);

    print_hex("\ninput_cbor = ", input_cbor, 35 + siz_index);

    //temprary veriables
    uint8_t temp;
    uint8_t t[8];

    //inputs
    uint8_t number_of_inputs = 1;
    uint8_t tx_aux_cbor[145];
    uint32_t protocol_magic = 7120787;
    memcpy(tx_aux_cbor, fromhex("839f"), 2);
//input int the form of encode
        memcpy(tx_aux_cbor+2, fromhex("8200d8185824825820"), 9);
        memcpy(tx_aux_cbor+11, input_prev_hash, 32);
        memcpy(tx_aux_cbor+43, index_cbor(input_prev_index, t, &temp), temp);

        memcpy(tx_aux_cbor+43+temp, fromhex("ff9f"), 2);
//output in the form of encode
        //loop for output_address
        memcpy(tx_aux_cbor+46, fromhex("82"),1);
        memcpy(tx_aux_cbor+47, db58, 43);
        memcpy(tx_aux_cbor+90, index_cbor(output0_amount, t, &temp), temp);

        //change address
        memcpy(tx_aux_cbor+95, fromhex("82"),1);
        b58tobin(db58, &s, output1_address);
        memcpy(tx_aux_cbor+96, db58, 43);
        memcpy(tx_aux_cbor+139, index_cbor(output1_amount, t, &temp), temp);


        memcpy(tx_aux_cbor+144, fromhex("ffa0"), 2);
    uint8_t blake_tx_aux_cbor[32];
    //hash to tx_aux_cbor thruough blake2b
    blake2b(tx_aux_cbor, 146, blake_tx_aux_cbor, 32);

    //_build_witnesses
    uint8_t messages[40];
    memcpy(messages, fromhex("01"),1);
    memcpy(messages+1, index_cbor(protocol_magic, t, &temp), temp);
    memcpy(messages+1+temp, fromhex("5820"),2);
    memcpy(messages+3+temp, blake_tx_aux_cbor, 32);
    //signature of the transaction
    unsigned char signature[64];
    ed25519_sign_ext(messages, 35+temp, node_input1.private_key, node_input1.private_key_extension, ,signature);

    //
    uint32_t amount=0;
    //memcpy(&amount, fromhex(data+182), 4);
    uint8_t *val = fromhex(data+182);
    amount = (val[0]<<24) + (val[1]<<16) +(val[2]<<8)+ val[3];

    print_hex("\ntransaction hex value = ",val, 4);

    printf("\namount = %ld\n", (long)amount);

    uint32_t crc = (uzlib_crc32(fromhex(data), 97, 0 ^ 0xffffffff)) ^ 0xffffffff;
    printf("\nCRC of Trasnsaction = %ld \n", (long) crc);

}*/

