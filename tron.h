#include "bip32.h"
void tron_test();

void get_mnemonic_to_seed(char *mnemo,uint8_t *seed);

void get_node_from_seed(uint8_t *sessionSeed, HDNode *node);

void get_private_key_from_node(HDNode *inout);



unsigned int encode_base_x(const char * alphabet, const unsigned int alphabet_len, const void * in, const unsigned int in_length, char * out,
		const unsigned int out_length);
