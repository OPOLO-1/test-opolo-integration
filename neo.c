#include "neo.h"

void print_Hex(const char *title, uint8_t * mesg, const uint32_t limit){
    printf("%s", title);
    uint32_t i = 0;
    for(i; i < limit; i++){
        if(mesg[i] <16 )printf("0");
        printf("%x", mesg[i]);
    }
    printf("\n");
}



#define DECIMAL_SCALE 8
#define ZERO_FRACTION "00000000"

int fixed8_str_conv(char *output, char *input, char terminator) {
    size_t input_len = strlen(input);
    if (strrchr(output, '.')) return 0; // already converted
    char tmp[DECIMAL_SCALE + 1];
    tmp[DECIMAL_SCALE] = '\0'; // just in case
    if (input_len <= DECIMAL_SCALE) { // satoshi amount
        strcpy(tmp, input);
        output[0] = '0';
        output[1] = '.';
        strcpy(&output[2], ZERO_FRACTION);
        int add_decs = DECIMAL_SCALE - strlen(tmp);
        strcpy(&output[2 + add_decs], tmp);
        output[input_len + 2 + add_decs] = terminator;
        return 1;
    }
    int input_dec_offset = input_len - DECIMAL_SCALE;
    strcpy(tmp, &input[input_dec_offset]);
    output[input_dec_offset] = '.';
    strncpy(output, input, input_len - DECIMAL_SCALE);
    strcpy(&output[input_dec_offset + 1], tmp);
    output[input_len + 1] = terminator;
    return 1;
}

void print_char(const char *title, uint8_t * mesg, const uint32_t limit){
    printf("%s", title);
    uint32_t i = 0;
    for(i; i < limit; i++){
        if(mesg[i] <16 )printf("0");
        printf("%c", mesg[i]);
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
  
  hdnode_from_seed(sessionSeed, ssSize,NIST256P1_NAME, node);
}

void get_private_key_from_node(HDNode *inout)
{
uint8_t adress_size=5;
uint32_t address_n[5]={0x80000000+44, 0x80000000+888, 0x80000000+0,0,1};
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


void public_key_hash160(unsigned char * in, unsigned short inlen, unsigned char *out) {	
	unsigned char buffer[32];
    sha256_Raw(in,inlen,buffer);    
    ripemd160(buffer,32,out);
}

static void to_address(char * dest, unsigned int dest_len, const unsigned char * script_hash) {    
	
	unsigned char address_hash_result_0[SHA256_HASH_LEN];
	unsigned char address_hash_result_1[SHA256_HASH_LEN];
	// concatenate the ADDRESS_VERSION and the address.
	unsigned char address[ADDRESS_LEN];
	address[0] = ADDRESS_VERSION;
	memmove(address + 1, script_hash, SCRIPT_HASH_LEN);
    // do a sha256 hash of the address twice.
    sha256_Raw( address, SCRIPT_HASH_LEN + 1, address_hash_result_0);
    sha256_Raw(address_hash_result_0, SHA256_HASH_LEN, address_hash_result_1);
	// add the first bytes of the hash as a checksum at the end of the address.
	memmove(address + 1 + SCRIPT_HASH_LEN, address_hash_result_1, SCRIPT_HASH_CHECKSUM_LEN);
	// encode the version + address + cehcksum in base58
    encode_base_x(BASE_58_ALPHABET, sizeof(BASE_58_ALPHABET), address, ADDRESS_LEN, dest, dest_len);	
}

void neo_test(){
    printf("\tNEO TEST\n\n");
 
    HDNode node;    
    char mnemonic[] = {"cluster unveil differ bright define prosper hunt warrior fetch rough host fringe worry mention gospel enlist elder laugh segment funny avoid regular market fortune"};
    get_mnemonic_to_seed(mnemonic,sessionSeed);    
    get_node_from_seed(sessionSeed,&node);
    get_private_key_from_node(&node);
// 267 complete

    uint8_t hex_str[]="800000027ec9c8266cc44859bf3224e8472b7bfbbfe0bcb06cdac062e95950b1471dd1480000af549b8e83edb6a9d8a7aa562accdfa97b5d4444bcbb358ab9f1bf4fc1336e580000019b7cffdaa674beae0f930ebe6085af9093e5fe56b34a5c220ccdcf6efc336fc500c2eb0b000000000727551662258eafa752f6dd8a9d2e7becf55561";
    size_t length = sizeof(hex_str);
    unsigned char bytearray[length / 2];

    for (size_t i = 0, j = 0; i < (length / 2); i++, j += 2)
	    bytearray[i] = (hex_str[j] % 32 + 9) % 25 * 16 + (hex_str[j+1] % 32 + 9) % 25;
    print_Hex("RAW TX = ",bytearray,sizeof(bytearray));

    uint8_t tx[32]={0};
    
    sha256_Raw(bytearray,sizeof(bytearray),tx);  

    uint8_t signature[64]={0};
    ecdsa_sign_digest(&nist256p1, node.private_key, tx, signature, NULL,NULL);
   
    print_Hex("Signature = ",signature,sizeof(signature));
    print_Hex("Private_key = ", node.private_key, sizeof(node.private_key));

    uint8_t public_key[65]={0};

    ecdsa_get_public_key65(&nist256p1, node.private_key,public_key);    
    print_Hex("Public key = ", public_key, sizeof(public_key));

    unsigned char public_key_encoded[33];
	public_key_encoded[0] = ((public_key[64] & 1) ? 0x03 : 0x02);
	memmove(public_key_encoded + 1, public_key + 1, 32);

    print_Hex("Public key encoded = ", public_key_encoded, sizeof(public_key_encoded));

	
    
    
    
    
    
    
    
    unsigned char verification_script[35];
	verification_script[0] = 0x21;
	memmove(verification_script + 1, public_key_encoded, sizeof(public_key_encoded));
	verification_script[sizeof(verification_script) - 1] = 0xAC;    

	unsigned char script_hash[SCRIPT_HASH_LEN];
	for (int i = 0; i < SCRIPT_HASH_LEN; i++) {
		script_hash[i] = 0x00;
	}




    



	public_key_hash160(verification_script, sizeof(verification_script), script_hash);
    	unsigned char script_hash_rev[SCRIPT_HASH_LEN];
	for (int i = 0; i < SCRIPT_HASH_LEN; i++) {
		script_hash_rev[i] = script_hash[SCRIPT_HASH_LEN - (i + 1)];
	}

        unsigned char raw_tx_rev[length/2];
	for (int i = 0; i < sizeof(bytearray); i++) {
		raw_tx_rev[i] = bytearray[(length/2) - (i + 1)];
	}
     print_Hex("Rawtx Reversed: ",raw_tx_rev,sizeof(raw_tx_rev));
     print_Hex("sc  : ",script_hash,sizeof(script_hash));

     




     uint8_t outadress_rev[SCRIPT_HASH_LEN]={0};
     uint8_t amount[VALUE_LEN]={0};

    //  if(sizeof(hex_str)>250)
    //  {
    //  memmove(outadress_rev,raw_tx_rev+SCRIPT_HASH_LEN+VALUE_LEN+ASSET_ID_LEN,SCRIPT_HASH_LEN);     
    //  memcpy(amount,raw_tx_rev+SCRIPT_HASH_LEN+VALUE_LEN+ASSET_ID_LEN+SCRIPT_HASH_LEN,VALUE_LEN);
    //  }

    //  else
     {
        memmove(outadress_rev,raw_tx_rev,SCRIPT_HASH_LEN);     
        memcpy(amount,raw_tx_rev+SCRIPT_HASH_LEN,VALUE_LEN);
         
     }
     



    char *s = malloc(sizeof amount * 2 + 1);
    for (size_t i = 0; i < sizeof amount; i++)
    sprintf(s + i * 2, "%02x", amount[i]);
  
    printf("%s\n",s);
     
     char *p;
     int intNumber = strtol(s, &p, 16);
     printf("The received number is: %d.\n", intNumber);
     


 

        unsigned char outadress[SCRIPT_HASH_LEN];
	for (int i = 0; i < SCRIPT_HASH_LEN; i++) {
		outadress[i] = outadress_rev[SCRIPT_HASH_LEN - (i + 1)];
	}

    print_Hex("out adress ",outadress,sizeof(outadress));



    char out_adress_base58[ADDRESS_BASE58_LEN];
    to_address(out_adress_base58, ADDRESS_BASE58_LEN, outadress);
    print_char("Receiver's Adress ",out_adress_base58,sizeof(out_adress_base58));
     


    


	char address_base58[ADDRESS_BASE58_LEN];
	to_address(address_base58, ADDRESS_BASE58_LEN, script_hash);
    print_char("NEO Address = ",address_base58,sizeof(address_base58));   
}