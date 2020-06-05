#define BIGINT_LENGTH 12
#define UINT32_WIDTH 32
#define TRYTE_BASE 27
#define TRIT_4 9
#define MIN_TRYTE_VALUE -13
#define MAX_TRYTE_VALUE 13
#define NUM_HASH_TRYTES 81
#define NUM_CHUNK_TRYTES (NUM_HASH_TRYTES)
const char CHARS_TABLE[] = "NOPQRSTUVWXYZ9ABCDEFGHIJKLM";
typedef int8_t tryte_t;
const uint32_t HALF_3[BIGINT_LENGTH] = {
    0xa5ce8964, 0x9f007669, 0x1484504f, 0x3ade00d9, 0x0c24486e, 0x50979d57,
    0x79a4c702, 0x48bbae36, 0xa9f6808b, 0xaa06a805, 0xa87fabdf, 0x5e69ebef};

const uint32_t NEG_HALF_3[BIGINT_LENGTH] = {
    0x5a31769c, 0x60ff8996, 0xeb7bafb0, 0xc521ff26, 0xf3dbb791, 0xaf6862a8,
    0x865b38fd, 0xb74451c9, 0x56097f74, 0x55f957fa, 0x57805420, 0xa1961410};

const uint32_t TRIT_243[BIGINT_LENGTH] = {
    0x4b9d12c9, 0x3e00ecd3, 0x2908a09f, 0x75bc01b2, 0x184890dc, 0xa12f3aae,
    0xf3498e04, 0x91775c6c, 0x53ed0116, 0x540d500b, 0x50ff57bf, 0xbcd3d7df};

int bigint_cmp(const uint32_t *a, const uint32_t *b)
{
    for (unsigned int i = BIGINT_LENGTH; i-- > 0;) {
        if (a[i] < b[i]) {
            return -1;
        }
        if (a[i] > b[i]) {
            return 1;
        }
    }
    return 0;
}

bool addcarry_u32(uint32_t *r, uint32_t a, uint32_t b, bool c_in)
{
    const uint32_t sum = a + b + (c_in ? 1 : 0);
    const bool carry = (sum < a) || (c_in && (sum <= a));

    *r = sum;
    return carry;
}

bool bigint_sub(uint32_t *r, const uint32_t *a, const uint32_t *b)
{
    bool carry = true;
    for (unsigned int i = 0; i < BIGINT_LENGTH; i++) {
        carry = addcarry_u32(&r[i], a[i], ~b[i], carry);
    }

    return carry;
}

unsigned int bigint_add_u32_mem(uint32_t *a, uint32_t summand)
{
    bool carry = addcarry_u32(&a[0], a[0], summand, false);
    if (carry == false) {
        return 0;
    }

    for (unsigned int i = 1; i < BIGINT_LENGTH; i++) {
        carry = addcarry_u32(&a[i], a[i], 0, true);
        if (carry == false) {
            return i;
        }
    }

    // overflow
    return BIGINT_LENGTH;
}

bool bigint_is_negative(const uint32_t *bigint)
{
    // whether the most significant bit of the most significant byte is set
    return (bigint[BIGINT_LENGTH - 1] >> (UINT32_WIDTH - 1) != 0);
}

bool bigint_add(uint32_t *r, const uint32_t *a, const uint32_t *b)
{
    bool carry = false;
    for (unsigned int i = 0; i < BIGINT_LENGTH; i++) {
        carry = addcarry_u32(&r[i], a[i], b[i], carry);
    }

    return carry;
}


bool bigint_set_last_trit_zero(uint32_t *bigint)
{
    if (bigint_is_negative(bigint)) {
        if (bigint_cmp(bigint, NEG_HALF_3) < 0) {
            bigint_add(bigint, bigint, TRIT_243);
            return true;
        }
    }
    else {
        if (bigint_cmp(bigint, HALF_3) > 0) {
            bigint_sub(bigint, bigint, TRIT_243);
            return true;
        }
    }
    return false;
}

void bytes_to_bigint(const unsigned char *bytes, uint32_t *bigint)
{
    // reverse word order
    for (unsigned int i = BIGINT_LENGTH; i-- > 0; bytes += 4) {
        bigint[i] = (uint32_t)bytes[0] << 24 | (uint32_t)bytes[1] << 16 |
                    (uint32_t)bytes[2] << 8 | (uint32_t)bytes[3] << 0;
    }
}

tryte_t tryte_set_last_trit_zero(tryte_t tryte)
{
    if (tryte > MAX_TRYTE_VALUE - TRIT_4) {
        return tryte - TRIT_4;
    }
    if (tryte < MIN_TRYTE_VALUE + TRIT_4) {
        return tryte + TRIT_4;
    }
    return tryte;
}

void bigint_to_bytes(const uint32_t *bigint, unsigned char *bytes)
{
    // reverse word order
    for (unsigned int i = BIGINT_LENGTH; i-- > 0; bytes += 4) {
        const uint32_t num = bigint[i];

        bytes[0] = (num >> 24) & 0xFF;
        bytes[1] = (num >> 16) & 0xFF;
        bytes[2] = (num >> 8) & 0xFF;
        bytes[3] = (num >> 0) & 0xFF;
    }
}


void bytes_add_u32_mem(unsigned char *bytes, uint32_t summand)
{
    if (summand > 0) {
        uint32_t bigint[BIGINT_LENGTH];

        bytes_to_bigint(bytes, bigint);
        bigint_add_u32_mem(bigint, summand);
        bigint_set_last_trit_zero(bigint);
        bigint_to_bytes(bigint, bytes);
    }
}

uint32_t bigint_div_u32_mem(uint32_t *a, uint32_t divisor,
                                   unsigned int ms_index)
{
    uint32_t remainder = 0;

    for (unsigned int i = ms_index + 1; i-- > 0;) {
        const uint64_t v = (UINT64_C(1) + UINT32_MAX) * remainder + a[i];

        remainder = (v % divisor) & UINT32_MAX;
        a[i] = (v / divisor) & UINT32_MAX;
    }

    return remainder;
}



void bigint_to_trytes_mem(uint32_t *bigint, tryte_t *trytes)
{
    // the two's complement represention is only correct, if the number fits
    // into 48 bytes, i.e. has the 243th trit set to 0
    bigint_set_last_trit_zero(bigint);

    // convert to the (positive) number representing non-balanced ternary
    bigint_add(bigint, bigint, HALF_3);

    // it is safe to assume that initially each word is non-zero
    unsigned int ms_index = BIGINT_LENGTH - 1;
    for (unsigned int i = 0; i < NUM_CHUNK_TRYTES - 1; i++) {
        const uint32_t rem = bigint_div_u32_mem(bigint, TRYTE_BASE, ms_index);
        trytes[i] = rem - (TRYTE_BASE / 2); // convert back to balanced

        // decrement index, if most significant word turned zero
        if (ms_index > 0 && bigint[ms_index] == 0) {
            ms_index--;
        }
    }

    // special case for the last tryte, where no further division is necessary
    trytes[NUM_CHUNK_TRYTES - 1] =
        tryte_set_last_trit_zero(bigint[0] - (TRYTE_BASE / 2));
}

void bytes_to_trytes(const unsigned char *bytes, tryte_t *trytes)
{
    uint32_t bigint[BIGINT_LENGTH];
    bytes_to_bigint(bytes, bigint);
    bigint_to_trytes_mem(bigint, trytes);
}

void trytes_to_chars(const tryte_t *trytes_in, char *chars_out,
                            unsigned int trytes_len)
{
    for (unsigned int i = 0; i < trytes_len; i++) {
        chars_out[i] = CHARS_TABLE[trytes_in[i] - MIN_TRYTE_VALUE];
    }
}