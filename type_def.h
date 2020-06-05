#include "sha3.h"
#include <stdbool.h>
typedef SHA3_CTX cx_sha3_t;
typedef SHA3_CTX cx_hash_t;
typedef int8_t tryte_t;
typedef int8_t trit_t;

#define MIN_TRYTE_VALUE -13
#define MAX_TRYTE_VALUE 13

#define CX_KECCAK384_SIZE 48

#define NUM_CHUNK_BYTES (NUM_HASH_BYTES)
#define NUM_HASH_BYTES (CX_KECCAK384_SIZE)

#define CX_LAST (1 << 0)
#define UNUSED(x) (void)(x)

#define TRITS_PER_TRYTE 3
#define NUM_HASH_TRYTES 81
#define NUM_HASH_TRITS (NUM_HASH_TRYTES * TRITS_PER_TRYTE)

#define NUM_CHECKSUM_TRYTES 9

#define SIGNATURE_FRAGMENT_SIZE 3

#define NUM_TRYTE_VALUES (MAX_TRYTE_VALUE - MIN_TRYTE_VALUE + 1)
#define MAX_IOTA_VALUE INT64_C(2779530283277761)

#define MAX(a, b)                                                              \
    ({                                                                         \
        __typeof__(a) _a = (a);                                                \
        __typeof__(b) _b = (b);                                                \
        _a > _b ? _a : _b;                                                     \
    })

#define MEMCLEAR(x) memset(&x, 0, sizeof(x))
#define NUM_SIGNATURE_FRAGMENTS(s) (CEILING(s * 27, SIGNATURE_FRAGMENT_SIZE))
#define CEILING(x, y)                                                          \
    ({                                                                         \
        typeof(y) _y = (y);                                                    \
        (((x) + _y - 1) / _y);                                                 \
    })

#define MIN_SECURITY_LEVEL 1
#define MAX_SECURITY_LEVEL 3
#define IN_RANGE(x, min, max)                                                  \
    ({                                                                         \
        typeof(x) _x = (x);                                                    \
        (_x >= (min) && _x <= (max));                                          \
    })

#define BUNDLE_INITIALIZED (1 << 0)
#define BUNDLE_FINALIZED (1 << 1)
#define SIGNING_STARTED (1 << 2)
#define MAX_BUNDL_SIZE 8

#define PAD_CHAR '9'

#define BASE 3

#define P1_FIRST 0
#define P1_MORE 128

const trit_t TRITS_TABLE[NUM_TRYTE_VALUES][3] = {
    {-1, -1, -1}, {0, -1, -1}, {1, -1, -1}, {-1, 0, -1}, {0, 0, -1}, {1, 0, -1},
    {-1, 1, -1},  {0, 1, -1},  {1, 1, -1},  {-1, -1, 0}, {0, -1, 0}, {1, -1, 0},
    {-1, 0, 0},   {0, 0, 0},   {1, 0, 0},   {-1, 1, 0},  {0, 1, 0},  {1, 1, 0},
    {-1, -1, 1},  {0, -1, 1},  {1, -1, 1},  {-1, 0, 1},  {0, 0, 1},  {1, 0, 1},
    {-1, 1, 1},   {0, 1, 1},   {1, 1, 1}};


typedef struct TX_INPUT
{
    char address[81];
    uint32_t address_idx;
    int64_t value;
    char tag[27];
    uint32_t current_index;
    uint32_t last_index;
    uint32_t timestamp;
}
TX_INPUT;

#define BIP32_PATH_MAX_LEN 4
#define MAX_BUNDLE_SIZE 8
typedef struct SIGNING_CTX {
    unsigned char state[48]; // state of the last Kerl squeeze

    uint8_t fragment_index; // index of the next fragment
    uint8_t last_fragment;  // final fragment
    uint8_t tx_index;       // index of the signed transaction

    tryte_t hash[81]; // bundle hash used for signing
} SIGNING_CTX;

typedef struct BUNDLE_CTX {
    // bundle_bytes holds all of the bundle information in byte encoding
    unsigned char bytes[MAX_BUNDLE_SIZE * 2 * NUM_HASH_BYTES];

    int64_t values[MAX_BUNDLE_SIZE];
    uint32_t indices[MAX_BUNDLE_SIZE];

    uint8_t current_tx_index;
    uint8_t last_tx_index;

    unsigned char hash[NUM_HASH_BYTES]; // bundle hash, when finalized
} BUNDLE_CTX;

typedef struct TX_OUTPUT
{
    bool finalized;
    char bundle_hash[81];
}TX_OUTPUT;


typedef struct SIGN_INPUT
{
    uint32_t transaction_idx;
}
SIGN_INPUT;

typedef struct SIGN_OUTPUT
{
    char signature_fragment[SIGNATURE_FRAGMENT_SIZE * 81];
    bool fragments_remaining;
}
SIGN_OUTPUT;

#define BIP32_PATH_MIN_LEN 2

#define BIP32_PATH_LENGTH 5

#define TX_BYTES(C) ((C)->bytes + (C)->current_tx_index * (2 * NUM_HASH_BYTES))

#define ASSIGN(dest, src)                                                      \
    ({                                                                         \
        typeof(src) _x = (src);                                                \
        typeof(dest) _y = _x;                                                  \
        (_x == _y && ((_x < 1) == (_y < 1)) ? (void)((dest) = _y), 1 : 0);     \
    })

#define NUM_SIGNATURE_FRAGMENTS(s) (CEILING(s * 27, SIGNATURE_FRAGMENT_SIZE))

#define MIN(a, b)                                                              \
    ({                                                                         \
        __typeof__(a) _a = (a);                                                \
        __typeof__(b) _b = (b);                                                \
        _a < _b ? _a : _b;                                                     \
    })

#define MAX_SECURITY 3
#define MAX_SIGNATURE_LENGTH ((MAX_SECURITY)*27 * (NUM_HASH_TRYTES))

typedef struct API_CTX {
    /// BIP32 path used for seed derivation
    uint32_t bip32_path[BIP32_PATH_MAX_LEN];
    uint8_t bip32_path_length;

    uint8_t security; ///< used security level

    unsigned char seed_bytes[NUM_HASH_BYTES]; ///< IOTA seed

    BUNDLE_CTX bundle_ctx;
    SIGNING_CTX signing_ctx;

    unsigned int state_flags;
}API_CTX;