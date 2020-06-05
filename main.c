#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

//#include "crc.h"
// #include "tron.h"
// #include "cosmos.h"
#include "options.h"
#include "address.h"
#include "aes/aes.h"
#include "base32.h"
#include "base58.h"
#include "bignum.h"
#include "bip32.h"
#include "bip39.h"
#include "blake256.h"
#include "blake2b.h"
#include "blake2s.h"
#include "curves.h"
#include "ecdsa.h"
#include "ed25519-donna/ed25519-donna.h"
#include "ed25519-donna/ed25519-keccak.h"
#include "ed25519-donna/ed25519.h"
//#include "modtrezorcrypto-bip32.h"
#include "ed25519-donna/ed25519-donna-32bit-tables.h"
//#include "transaction.h"
#include "hmac_drbg.h"
#include "memzero.h"
// #include "monero/monero.h"
#include "nem.h"
#include "nist256p1.h"
#include "pbkdf2.h"
#include "rand.h"
#include "rc4.h"
#include "rfc6979.h"
#include "script.h"
#include "secp256k1.h"
#include "sha2.h"
#include "sha3.h"
#include "shamir.h"
#include "slip39.h"
//monero
// #include "monero.h"
//#include "messages-crypto.pb.h"
//coininfo
#include "coins.h"
#include "coin_info.h"
#include "cardano.h"

//iota
#include "fsm_iota.h"
#include "neo.h"




/*#define RESP_INIT(TYPE) \
			TYPE *resp = (TYPE *) (void *) msg_resp; \
			_Static_assert(sizeof(msg_resp) >= sizeof(TYPE), #TYPE " is too large"); \
			memset(resp, 0, sizeof(TYPE));



//compute address

typedef enum _InputScriptType {
    InputScriptType_SPENDADDRESS = 0,
    InputScriptType_SPENDMULTISIG = 1,
    InputScriptType_EXTERNAL = 2,
    InputScriptType_SPENDWITNESS = 3,
    InputScriptType_SPENDP2SHWITNESS = 4
} InputScriptType;

*/
/*bool compute_address(const CoinInfo *coin,
					 InputScriptType script_type,
					 const HDNode *node,
					 char address[MAX_ADDR_SIZE]) {

	uint8_t raw[MAX_ADDR_RAW_SIZE];
	uint8_t digest[32];
	size_t prelen;

	if (has_multisig) {
		if (cryptoMultisigPubkeyIndex(coin, multisig, node->public_key) < 0) {
			return 0;
		}
		if (compile_script_multisig_hash(coin, multisig, digest) == 0) {
			return 0;
		}
		if (script_type == InputScriptType_SPENDWITNESS) {
			// segwit p2wsh:  script hash is single sha256
			if (!coin->has_segwit || !coin->bech32_prefix) {
				return 0;
			}
			if (!segwit_addr_encode(address, coin->bech32_prefix, SEGWIT_VERSION_0, digest, 32)) {
				return 0;
			}
		} else if (script_type == InputScriptType_SPENDP2SHWITNESS) {
			// segwit p2wsh encapsuled in p2sh address
			if (!coin->has_segwit) {
				return 0;
			}
			if (!coin->has_address_type_p2sh) {
				return 0;
			}
			raw[0] = 0; // push version
			raw[1] = 32; // push 32 bytes
			memcpy(raw+2, digest, 32); // push hash
			hasher_Raw(coin->curve->hasher_pubkey, raw, 34, digest);
			prelen = address_prefix_bytes_len(coin->address_type_p2sh);
			address_write_prefix_bytes(coin->address_type_p2sh, raw);
			memcpy(raw + prelen, digest, 32);
			if (!base58_encode_check(raw, prelen + 20, coin->curve->hasher_base58, address, MAX_ADDR_SIZE)) {
				return 0;
			}
		} else if (coin->cashaddr_prefix) {
			raw[0] = CASHADDR_P2SH | CASHADDR_160;
			ripemd160(digest, 32, raw + 1);
			if (!cash_addr_encode(address, coin->cashaddr_prefix, raw, 21)) {
				return 0;
			}
		} else {
			// non-segwit p2sh multisig
			prelen = address_prefix_bytes_len(coin->address_type_p2sh);
			address_write_prefix_bytes(coin->address_type_p2sh, raw);
			ripemd160(digest, 32, raw + prelen);
			if (!base58_encode_check(raw, prelen + 20, coin->curve->hasher_base58, address, MAX_ADDR_SIZE)) {
				return 0;
			}
		}
	} else if (script_type == InputScriptType_SPENDWITNESS) {
		// segwit p2wpkh:  pubkey hash is ripemd160 of sha256
		if (!coin->has_segwit || !coin->bech32_prefix) {
			return 0;
		}
		ecdsa_get_pubkeyhash(node->public_key, coin->curve->hasher_pubkey, digest);
		if (!segwit_addr_encode(address, coin->bech32_prefix, SEGWIT_VERSION_0, digest, 20)) {
			return 0;
		}
	} else if (script_type == InputScriptType_SPENDP2SHWITNESS) {
		// segwit p2wpkh embedded in p2sh
		if (!coin->has_segwit) {
			return 0;
		}
		if (!coin->has_address_type_p2sh) {
			return 0;
		}
		ecdsa_get_address_segwit_p2sh(node->public_key, coin->address_type_p2sh, coin->curve->hasher_pubkey, coin->curve->hasher_base58, address, MAX_ADDR_SIZE);
	} else if (coin->cashaddr_prefix) {
		ecdsa_get_address_raw(node->public_key, CASHADDR_P2KH | CASHADDR_160, coin->curve->hasher_pubkey, raw);
		if (!cash_addr_encode(address, coin->cashaddr_prefix, raw, 21)) {
			return 0;
		}
	} else {
		ecdsa_get_address(node->public_key, coin->address_type, coin->curve->hasher_pubkey, coin->curve->hasher_base58, address, MAX_ADDR_SIZE);
	}

	//litecoin new address integration
	if(strncmp(coin->coin_shortcut," LTC",4) == 0)
	{
		#include "base58.h"
		#include "util.h"
		char address2[MAX_ADDR_SIZE];
		litecoinAddressConv(address, address2);

		UART_vPrintfSerial("\r\nLitecoin previous Address ");
		UART_vPrintfSerial(address);
		UART_vPrintfSerial("\r\nLitecoin new Address ");
		UART_vPrintfSerial(address2);
		strlcpy(address, address2, sizeof(address2));
	}
	return 1;
}*/

/*void cordano1(){
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
    printf("after node = NULL\r\n");
                        // 0x80000000
    uint32_t address_n[5]={0x80000000+44, 0x80000000+1815, 0x80000000+0, 0, 0};
    printf("address_n[5]={0x80000000+44, 0x80000000+1815, 0x80000000+0, 0, 0}\r\n");
    //const uint8_t *seed = "37dfe3018e0509572c8f36df9ea32eb740130ca4f044b65719d63fa6374508bf226936fd4391ffa09ee03f5bc9f9a0002ef9d40ae93a11abc3bedd72f564afef";
    //printf();
    char mnemonic[] = {"voyage slight install cake hybrid female maximum screen time awful media despair matter that olive index push decline fancy impact release behind odor welcome"};
    //char mnemonic[150] = {"shine wonder erode oak net pupil filter jar coast cook brain build utility hood indicate forum music rice surround check glue denial service convince"};
    uint8_t sessionSeed[64];
    mnemonic_to_seed(mnemonic, "", sessionSeed, print);
    /*if(hdnode_from_seed(fromhex("37dfe3018e0509572c8f36df9ea32eb740130ca4f044b65719d63fa6374508bf226936fd4391ffa09ee03f5bc9f9a0002ef9d40ae93a11abc3bedd72f564afef"),128,coins->curve_name,&node)){
        printf("hdnode_from_seed work\r\n");
    }*/
  /*  if(hdnode_from_seed(sessionSeed,64,coin->curve_name,&node)){
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
    //RESP_INIT(SignedIdentity);
    char address[130];

    //compute_address(coin, 0, &node, false, false, address);
    ecdsa_get_address(node.public_key, coin->address_type, coin->curve->hasher_pubkey, coin->curve->hasher_base58, address, 130);

    //hdnode_get_address(&node, 0x00, addr, 34);
    //printf("%c \r\n",address);
    /*for(i=0; i<=130 ;i++){
        printf("%c", address[i]);
    }*/

 /*   printf("%s \r\n",address);
    ecdsa_get_address_segwit_p2sh(node.public_key, coin->address_type_p2sh, coin->curve->hasher_pubkey, coin->curve->hasher_base58, address, 130);
    printf("segwit_p2sh = %s\r\n",address);
}


void hashing(){
    static const char *base58_vector[] = {
          "0065a16059864a2fdbc7c99a4723a8395bc6f188eb",
          "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i",
          "0574f209f6ea907e2ea48f74fae05782ae8a665257",
          "3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou",
          "6f53c0307d6851aa0ce7825ba883c6bd9ad242b486",
          "mo9ncXisMeAoXwqcV5EWuyncbmCcQN4rVs",
          "c46349a418fc4578d10a372b54b45c280cc8c4382f",
          "2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br",
          "80eddbdc1168f1daeadbd3e44c1e3f8f5a284c2029f78ad26af98583a499de5b19",
          "5Kd3NBUAdUnhyzenEwVLy9pBKxSwXvE9FMPyR4UKZvpe6E3AgLr",
          "8055c9bccb9ed68446d1b75273bbce89d7fe013a8acd1625514420fb2aca1a21c401",
          "Kz6UJmQACJmLtaQj5A3JAge4kVTNQ8gbvXuwbmCj7bsaabudb3RD",
          "ef36cb93b9ab1bdabf7fb9f2c04f1b9cc879933530ae7842398eef5a63a56800c2",
          "9213qJab2HNEpMpYNBa7wHGFKKbkDn24jpANDs2huN3yi4J11ko",
          "efb9f4892c9e8282028fea1d2667c4dc5213564d41fc5783896a0d843fc15089f301",
          "cTpB4YiyKiBcPxnefsDpbnDxFDffjqJob8wGCEDXxgQ7zQoMXJdH",
          "006d23156cbbdcc82a5a47eee4c2c7c583c18b6bf4",
          "1Ax4gZtb7gAit2TivwejZHYtNNLT18PUXJ",
          "05fcc5460dd6e2487c7d75b1963625da0e8f4c5975",
          "3QjYXhTkvuj8qPaXHTTWb5wjXhdsLAAWVy",
          "6ff1d470f9b02370fdec2e6b708b08ac431bf7a5f7",
          "n3ZddxzLvAY9o7184TB4c6FJasAybsw4HZ",
          "c4c579342c2c4c9220205e2cdc285617040c924a0a",
          "2NBFNJTktNa7GZusGbDbGKRZTxdK9VVez3n",
          "80a326b95ebae30164217d7a7f57d72ab2b54e3be64928a19da0210b9568d4015e",
          "5K494XZwps2bGyeL71pWid4noiSNA2cfCibrvRWqcHSptoFn7rc",
          "807d998b45c219a1e38e99e7cbd312ef67f77a455a9b50c730c27f02c6f730dfb401",
          "L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi",
          "efd6bca256b5abc5602ec2e1c121a08b0da2556587430bcf7e1898af2224885203",
          "93DVKyFYwSN6wEo3E2fCrFPUp17FtrtNi2Lf7n4G3garFb16CRj",
          "efa81ca4e8f90181ec4b61b6a7eb998af17b2cb04de8a03b504b9e34c4c61db7d901",
          "cTDVKtMGVYWTHCb1AFjmVbEbWjvKpKqKgMaR3QJxToMSQAhmCeTN",
          "007987ccaa53d02c8873487ef919677cd3db7a6912",
          "1C5bSj1iEGUgSTbziymG7Cn18ENQuT36vv",
          "0563bcc565f9e68ee0189dd5cc67f1b0e5f02f45cb",
          "3AnNxabYGoTxYiTEZwFEnerUoeFXK2Zoks",
          "6fef66444b5b17f14e8fae6e7e19b045a78c54fd79",
          "n3LnJXCqbPjghuVs8ph9CYsAe4Sh4j97wk",
          "c4c3e55fceceaa4391ed2a9677f4a4d34eacd021a0",
          "2NB72XtkjpnATMggui83aEtPawyyKvnbX2o",
          "80e75d936d56377f432f404aabb406601f892fd49da90eb6ac558a733c93b47252",
          "5KaBW9vNtWNhc3ZEDyNCiXLPdVPHCikRxSBWwV9NrpLLa4LsXi9",
          "808248bd0375f2f75d7e274ae544fb920f51784480866b102384190b1addfbaa5c01",
          "L1axzbSyynNYA8mCAhzxkipKkfHtAXYF4YQnhSKcLV8YXA874fgT",
          "ef44c4f6a096eac5238291a94cc24c01e3b19b8d8cef72874a079e00a242237a52",
          "927CnUkUbasYtDwYwVn2j8GdTuACNnKkjZ1rpZd2yBB1CLcnXpo",
          "efd1de707020a9059d6d3abaf85e17967c6555151143db13dbb06db78df0f15c6901",
          "cUcfCMRjiQf85YMzzQEk9d1s5A4K7xL5SmBCLrezqXFuTVefyhY7",
          "00adc1cc2081a27206fae25792f28bbc55b831549d",
          "1Gqk4Tv79P91Cc1STQtU3s1W6277M2CVWu",
          "05188f91a931947eddd7432d6e614387e32b244709",
          "33vt8ViH5jsr115AGkW6cEmEz9MpvJSwDk",
          "6f1694f5bc1a7295b600f40018a618a6ea48eeb498",
          "mhaMcBxNh5cqXm4aTQ6EcVbKtfL6LGyK2H",
          "c43b9b3fd7a50d4f08d1a5b0f62f644fa7115ae2f3",
          "2MxgPqX1iThW3oZVk9KoFcE5M4JpiETssVN",
          "80091035445ef105fa1bb125eccfb1882f3fe69592265956ade751fd095033d8d0",
          "5HtH6GdcwCJA4ggWEL1B3jzBBUB8HPiBi9SBc5h9i4Wk4PSeApR",
          "80ab2b4bcdfc91d34dee0ae2a8c6b6668dadaeb3a88b9859743156f462325187af01",
          "L2xSYmMeVo3Zek3ZTsv9xUrXVAmrWxJ8Ua4cw8pkfbQhcEFhkXT8",
          "efb4204389cef18bbe2b353623cbf93e8678fbc92a475b664ae98ed594e6cf0856",
          "92xFEve1Z9N8Z641KQQS7ByCSb8kGjsDzw6fAmjHN1LZGKQXyMq",
          "efe7b230133f1b5489843260236b06edca25f66adb1be455fbd38d4010d48faeef01",
          "cVM65tdYu1YK37tNoAyGoJTR13VBYFva1vg9FLuPAsJijGvG6NEA",
          "00c4c1b72491ede1eedaca00618407ee0b772cad0d",
          "1JwMWBVLtiqtscbaRHai4pqHokhFCbtoB4",
          "05f6fe69bcb548a829cce4c57bf6fff8af3a5981f9",
          "3QCzvfL4ZRvmJFiWWBVwxfdaNBT8EtxB5y",
          "6f261f83568a098a8638844bd7aeca039d5f2352c0",
          "mizXiucXRCsEriQCHUkCqef9ph9qtPbZZ6",
          "c4e930e1834a4d234702773951d627cce82fbb5d2e",
          "2NEWDzHWwY5ZZp8CQWbB7ouNMLqCia6YRda",
          "80d1fab7ab7385ad26872237f1eb9789aa25cc986bacc695e07ac571d6cdac8bc0",
          "5KQmDryMNDcisTzRp3zEq9e4awRmJrEVU1j5vFRTKpRNYPqYrMg",
          "80b0bbede33ef254e8376aceb1510253fc3550efd0fcf84dcd0c9998b288f166b301",
          "L39Fy7AC2Hhj95gh3Yb2AU5YHh1mQSAHgpNixvm27poizcJyLtUi",
          "ef037f4192c630f399d9271e26c575269b1d15be553ea1a7217f0cb8513cef41cb",
          "91cTVUcgydqyZLgaANpf1fvL55FH53QMm4BsnCADVNYuWuqdVys",
          "ef6251e205e8ad508bab5596bee086ef16cd4b239e0cc0c5d7c4e6035441e7d5de01",
          "cQspfSzsgLeiJGB2u8vrAiWpCU4MxUT6JseWo2SjXy4Qbzn2fwDw",
          "005eadaf9bb7121f0f192561a5a62f5e5f54210292",
          "19dcawoKcZdQz365WpXWMhX6QCUpR9SY4r",
          "053f210e7277c899c3a155cc1c90f4106cbddeec6e",
          "37Sp6Rv3y4kVd1nQ1JV5pfqXccHNyZm1x3",
          "6fc8a3c2a09a298592c3e180f02487cd91ba3400b5",
          "myoqcgYiehufrsnnkqdqbp69dddVDMopJu",
          "c499b31df7c9068d1481b596578ddbb4d3bd90baeb",
          "2N7FuwuUuoTBrDFdrAZ9KxBmtqMLxce9i1C",
          "80c7666842503db6dc6ea061f092cfb9c388448629a6fe868d068c42a488b478ae",
          "5KL6zEaMtPRXZKo1bbMq7JDjjo1bJuQcsgL33je3oY8uSJCR5b4",
          "8007f0803fc5399e773555ab1e8939907e9badacc17ca129e67a2f5f2ff84351dd01",
          "KwV9KAfwbwt51veZWNscRTeZs9CKpojyu1MsPnaKTF5kz69H1UN2",
          "efea577acfb5d1d14d3b7b195c321566f12f87d2b77ea3a53f68df7ebf8604a801",
          "93N87D6uxSBzwXvpokpzg8FFmfQPmvX4xHoWQe3pLdYpbiwT5YV",
          "ef0b3b34f0958d8a268193a9814da92c3e8b58b4a4378a542863e34ac289cd830c01",
          "cMxXusSihaX58wpJ3tNuuUcZEQGt6DKJ1wEpxys88FFaQCYjku9h",
          "001ed467017f043e91ed4c44b4e8dd674db211c4e6",
          "13p1ijLwsnrcuyqcTvJXkq2ASdXqcnEBLE",
          "055ece0cadddc415b1980f001785947120acdb36fc",
          "3ALJH9Y951VCGcVZYAdpA3KchoP9McEj1G",
          0,
          0,
      };
      const char **raw = base58_vector;
      const char **str = base58_vector + 1;
      uint8_t rawn[34];
      char strn[53];
      int r;

      int len = strlen(*raw +10) / 2;
      memcpy(rawn, fromhex(*raw +10), len);
      r = base58_encode_check(rawn, len, HASHER_SHA3, strn, sizeof(strn));
      printf("r = %ld\r\n", strlen(*str));
      printf("str = %s\r\n",*str);
      printf("stn = %s\r\n",strn);
      /*
      while (*raw && *str) {
        int len = strlen(*raw) / 2;

        memcpy(rawn, fromhex(*raw), len);
        r = base58_encode_check(rawn, len, HASHER_SHA2D, strn, sizeof(strn));
        //ck_assert_int_eq((size_t)r, strlen(*str) + 1);
        if((size_t)r == strlen(*str)+1)
            printf("r = %ld\r\n", strlen(*str));
        //ck_assert_str_eq(strn, *str);
        if(strcmp(strn, *str)){
            printf("str = %s\r\n",*str);
            printf("strn = %s\r\n",strn);
        }
        r = base58_decode_check(strn, HASHER_SHA2D, rawn, len);
        //ck_assert_int_eq(r, len);
        //ck_assert_mem_eq(rawn, fromhex(*raw), len);

        raw += 2;
        str += 2;
      }
      */
/*}

void bip32(){
    HDNode node;
    uint32_t fingerprint;
    char str[112];
    int r;

    hdnode_from_seed(fromhex("37dfe3018e0509572c8f36df9ea32eb740130ca4f044b65719d63fa6374508bf226936fd4391ffa09ee03f5bc9f9a0002ef9d40ae93a11abc3bedd72f564afef"),
                    128, SECP256K1_NAME, &node);
    uint8_t i =0;
    for(i; i<32 ;i++){
        printf("%x", node.private_key[i]);
    }
}
void bitcount(){
    char buffer[50];
    bignum256 a, b;

      bn_zero(&a);
      printf("Number of bits at a=0 are %d\r\n", bn_bitcount(&a));

      bn_one(&a);
      //ck_assert_int_eq(bn_bitcount(&a), 1);
      printf("Number of bits at a=1 are %d\r\n", bn_bitcount(&a));
      // test for 10000 and 11111 when i=5
      for (int i = 2; i <= 256; i++) {
        bn_one(&a);
        bn_one(&b);
        for (int j = 2; j <= i; j++) {
          bn_lshift(&a);
          bn_lshift(&b);
          bn_addi(&b, 1);
        }
        //ck_assert_int_eq(bn_bitcount(&a), i);
         printf("Number of bits a are %d\r\n", bn_digitcount(&a));
        //ck_assert_int_eq(bn_bitcount(&b), i);
         printf("Number of bits b are %d\r\n", bn_digitcount(&a));
      }

      bn_read_uint32(0x3fffffff, &a);
      //ck_assert_int_eq(bn_bitcount(&a), 30);

      bn_read_uint32(0xffffffff, &a);
      //ck_assert_int_eq(bn_bitcount(&a), 32);

}


void format(){
    bignum256 a;
    char buf[128];
    int r;
     bn_read_be(
          fromhex(
              "000000000000000000000000000000000000000000000000000000000000D92A"),
          &a);
      r = bn_format(&a, "Prefx", "Sufix", 3, 0, false, buf, sizeof(buf));
      printf("r = %d",r);
      printf("buff = %s",buf);
}
*/
int main(int argc, char *argv[])
{
    //test_signature_level_one();
    //printf("\r\napi sign testing\r\n");
    //signing();
    /****************************** Cardano Code  ******************/
 /*   printf("blake2b started\n");
    signtrasnsaction();
    printf("\nblake2b end\n");

    printf("Cordano started\r\n");
    cordano();
    printf("\ncordano end \n");
    cordano();

    p_p_address();
    bip32();

    hashing();

    bitcount();
    format();
    printf("cardano_sign_transactio\n ");
    cardano_sign_tx ();
    printf("\ncardano end sign transaction\n");
    
    cardano_test();

<<<<<<< Updated upstream
    bignum256 a;
     uint8_t input[32];
     uint8_t count = 0;
     memcpy(
         input,
         fromhex(
             "c55ece858b0ddd5263f96810fe14437cd3b5e1fbd7c6a2ec1e031f05e86d8bd5"),
         32);

     bn_read_be(input, &a);

     bignum256 b = {{0x286d8bd5, 0x380c7c17, 0x3c6a2ec1, 0x2d787ef5, 0x14437cd3,
                     0x25a043f8, 0x1dd5263f, 0x33a162c3, 0x0000c55e}};

     for (int i = 0; i < 9; i++) {
       //ck_assert_int_eq(a.val[i], b.val[i]);
       if(a.val[i] == b.val[i])
       count++;
     }
    bn_read_be(
          fromhex(
              "c55ece858b0ddd5263f96810fe14437cd3b5e1fbd7c6a2ec1e031f05e86d8bd5"),
          &a);
     printf("bignum256 is ");
    if(bn_is_odd(&a), 1)
        printf("odd");
    else
        printf("even");
     printf("\r\n");
    char buffer[50];
    sprintf(buffer, "%d", count);
    printf("%s Number of uint32-t are equal", buffer);
	bignum256 x, y;	
	uint8_t data[32] = {0,0,0,0, 1,0,0,0 , 2,0,0,0, 3,0,0,0, 4,0,0,0, 5,0,0,0, 6,0,0,0, 7,0,0,0};
	 //8,0,0,0, 9,0,0,0};
	//bn_write_be(&x, data);
	bn_one(&x);
	bn_read_le(data, &x);
	//bn_write_le(&x, data);
	//bn_read_be(data, & x);
	bn_zero(&y);
	bn_add(&y, &x);
	bn_add(&y, &y);
	//p1.x = read_be(*data);
    //p1.x = 110;
    sprintf(buffer, "%d %d %d %d %d", data[0], data[1], data[2], data[3], data[4] );
    printf("data[8] = %s \r\n",buffer);
    printf("Point X = ");
    bn_print(&x);
    printf("\r\n");
    printf("Point y = ");
    bn_print(&y);
    return 0;
*/
/// Tron Test
    // cosmos_test();
    // /// Monero Test
    // printf("Monero address test starting\r\n");
    // monero_get_address();
    // printf("Monero address test end/r/n");
    neo_test();
}