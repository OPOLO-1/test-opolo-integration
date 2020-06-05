
typedef enum _InputScriptType {
    InputScriptType_SPENDADDRESS = 0,
    InputScriptType_SPENDMULTISIG = 1,
    InputScriptType_EXTERNAL = 2,
    InputScriptType_SPENDWITNESS = 3,
    InputScriptType_SPENDP2SHWITNESS = 4
} InputScriptType;


uint32_t uzlib_crc32(const void *data, unsigned int length, uint32_t crc);
void hdnode_cardano(HDNode *node, uint32_t i);
bool cardano_get_public_key(char *mnemonic, uint32_t *path, uint32_t ln_path, HDNode *node);
void cardano_get_xpub(HDNode *node, uint8_t *xpub, uint32_t ln_xpub);
void cardano_get_address(HDNode *node, char * addr, size_t *s);
const uint8_t *fromhex(const char *str);
void print();
void print_chr(const char *title, const char * mesg, const uint32_t limit);
void print_hex(const char *title, uint8_t * mesg, const uint32_t limit);
uint8_t* index_cbor(uint32_t index, uint8_t *ret, uint8_t * size);
void signature(HDNode *node, uint64_t protocol_magic, uint8_t *blk2b, uint8_t *xpub);
void witness(HDNode *node, uint8_t type, uint32_t index, uint64_t protocol_magic, uint8_t *blk2b, uint8_t *wit, uint32_t *siz);
void inputs(const uint8_t * prev_hash, uint32_t prev_index, uint8_t *input, uint32_t *siz);
void outputs(uint8_t *db58, uint32_t amount, uint8_t *output, uint32_t *siz);
void cardano_sign_tx();
void cardano_signtx ();


