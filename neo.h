#include "bip32.h"
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
#include "nist256p1.h"
#include "ripemd160.h"
#include "segwit_addr.h"


#define SHOW_TX_TYPE true

/** if true, show a screen with the transaction length. */
#define SHOW_TX_LEN false

/** if true, show a screen with the transaction version. */
#define SHOW_VERSION false

/** if true, show the tx-type exclusive data, such as coin claims for a Claim Tx */
#define SHOW_EXCLUSIVE_DATA false

/** if true, show number of attributes. */
#define SHOW_NUM_ATTRIBUTES false

/** if true, show number of tx-in coin references. */
#define SHOW_NUM_COIN_REFERENCES false

/** if true, show number of output transactions. */
#define SHOW_NUM_TX_OUTS false

/** if true, show tx-out values in hex as well as decimal. */
#define SHOW_VALUE_HEX false

/** if true, show script hash screen as well as address screen */
#define SHOW_SCRIPT_HASH false

/**
 * each CoinReference has two fields:
 *  UInt256 PrevHash = 32 bytes.
 *  ushort PrevIndex = 2 bytes.
 */
#define COIN_REFERENCES_LEN (32 + 2)

/** length of tx.output.value */
#define VALUE_LEN 8

/** length of tx.output.asset_id */
#define ASSET_ID_LEN 32

/** length of tx.output.script_hash */
#define SCRIPT_HASH_LEN 20

/** length of the checksum used to convert a tx.output.script_hash into an Address. */
#define SCRIPT_HASH_CHECKSUM_LEN 4

/** length of a tx.output Address, after Base58 encoding. */
#define ADDRESS_BASE58_LEN 34

/** length of a tx.output Address before encoding, which is the length of <address_version>+<script_hash>+<checksum> */
#define ADDRESS_LEN (1 + SCRIPT_HASH_LEN + SCRIPT_HASH_CHECKSUM_LEN)

/** the current version of the address field */
#define ADDRESS_VERSION 23

/** the length of a SHA256 hash */
#define SHA256_HASH_LEN 32

/** the position of the decimal point, 8 characters in from the right side */
#define DECIMAL_PLACE_OFFSET 8
void neo_test();

void get_mnemonic_to_seed(char *mnemo,uint8_t *seed);

void get_node_from_seed(uint8_t *sessionSeed, HDNode *node);

void get_private_key_from_node(HDNode *inout);



unsigned int encode_base_x(const char * alphabet, const unsigned int alphabet_len, const void * in, const unsigned int in_length, char * out,
		const unsigned int out_length);