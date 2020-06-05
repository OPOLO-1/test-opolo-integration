
#include "type_def.h"
#include "seed.h"

struct API_CTX api;
void cx_keccak_init(SHA3_CTX *hash, int size)
{
    UNUSED(size);

    keccak_384_Init(hash);
}

void kerl_initialize(cx_sha3_t *sha3)
{
    cx_keccak_init(sha3, 384);
}

void cx_hash(cx_hash_t *hash, int mode, const unsigned char *in,
                           unsigned int len, unsigned char *out,
                           unsigned int out_len)
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

void kerl_absorb_bytes(cx_sha3_t *sha3, const unsigned char *bytes,
                       unsigned int len)
{
    cx_hash((cx_hash_t *)sha3, 0, (unsigned char *)bytes, len, NULL, 0);
}

void kerl_absorb_chunk(cx_sha3_t *sha3, const unsigned char *bytes)
{
    kerl_absorb_bytes(sha3, bytes, CX_KECCAK384_SIZE);
}

void bytes_set_last_trit_zero(unsigned char *bytes)
{
    uint32_t bigint[BIGINT_LENGTH];
    bytes_to_bigint(bytes, bigint);
    if (bigint_set_last_trit_zero(bigint)) {
        bigint_to_bytes(bigint, bytes);
    }
}

void kerl_squeeze_final_chunk(cx_sha3_t *sha3, unsigned char *bytes)
{
    cx_hash((cx_hash_t *)sha3, CX_LAST, bytes, 0, bytes, CX_KECCAK384_SIZE);
    bytes_set_last_trit_zero(bytes);
}

void derive_seed_entropy(const unsigned char *entropy, unsigned int n, unsigned char *seed_bytes)
{
    // at least one chunk of entropy required
    if (n < NUM_HASH_BYTES) {
        return;
    }

    cx_sha3_t sha;
    kerl_initialize(&sha);

    for (unsigned int i = 0; i < n / NUM_HASH_BYTES; i++) {
        kerl_absorb_chunk(&sha, entropy + i * NUM_HASH_BYTES);
        //printf("\r\n %d \t%d", i, n);
    }
    if (n % NUM_HASH_BYTES != 0) {
        kerl_absorb_chunk(&sha, entropy + (n - NUM_HASH_BYTES));
        //printf("loop end \t%d", n);
    }

    kerl_squeeze_final_chunk(&sha, seed_bytes);
}

void bytes_to_chars(const unsigned char *bytes, char *chars,
                    unsigned int bytes_len)
{
    for (unsigned int i = 0; i < bytes_len / NUM_CHUNK_BYTES; i++) {
        tryte_t trytes[NUM_CHUNK_TRYTES];
        bytes_to_trytes(bytes + i * NUM_CHUNK_BYTES, trytes);
        trytes_to_chars(trytes, chars + i * NUM_CHUNK_TRYTES, NUM_CHUNK_TRYTES);
    }
}

void init_shas(const unsigned char *seed_bytes, uint32_t idx,
                      cx_sha3_t *key_sha, cx_sha3_t *digest_sha,
                      unsigned char *buffer)
{
    // use temp bigint so seed not destroyed
    memcpy(buffer, seed_bytes, NUM_HASH_BYTES);

    bytes_add_u32_mem(buffer, idx);

    kerl_initialize(key_sha);
    kerl_absorb_chunk(key_sha, buffer);
    kerl_squeeze_final_chunk(key_sha, buffer);

    kerl_initialize(key_sha);
    kerl_absorb_chunk(key_sha, buffer);

    kerl_initialize(digest_sha);
}

void flip_hash_bytes(unsigned char *bytes)
{
    for (unsigned int i = 0; i < CX_KECCAK384_SIZE; i++) {
        bytes[i] = ~bytes[i];
    }
}

void kerl_state_squeeze_chunk(cx_sha3_t *sha3, unsigned char *state_bytes,
                              unsigned char *bytes)
{
    cx_hash((cx_hash_t *)sha3, CX_LAST, state_bytes, 0, state_bytes,
            CX_KECCAK384_SIZE);

    memcpy(bytes, state_bytes, CX_KECCAK384_SIZE);
    bytes_set_last_trit_zero(bytes);

    // flip bytes for multiple squeeze
    flip_hash_bytes(state_bytes);
}

void digest_single_chunk(unsigned char *key_fragment,
                                cx_sha3_t *digest_sha3, cx_sha3_t *round_sha3)
{
    for (int k = 0; k < 26; k++) {
        kerl_initialize(round_sha3);
        kerl_absorb_chunk(round_sha3, key_fragment);
        kerl_squeeze_final_chunk(round_sha3, key_fragment);
    }

    // absorb buffer directly to avoid storing the digest fragment
    kerl_absorb_chunk(digest_sha3, key_fragment);
}

void kerl_reinitialize(cx_sha3_t *sha3, const unsigned char *state_bytes)
{
    kerl_initialize(sha3);
    kerl_absorb_chunk(sha3, state_bytes);
}

bool get_public_add(const unsigned char *seed_bytes, uint32_t idx, unsigned int security, unsigned char *address_bytes){

    if (!IN_RANGE(security, MIN_SECURITY_LEVEL, MAX_SECURITY_LEVEL)) {
        return false;
    }
    cx_sha3_t key_sha, digest_sha;
    unsigned char digest[NUM_HASH_BYTES * security];
    unsigned char *buffer = digest + NUM_HASH_BYTES * (security - 1);
    init_shas(seed_bytes, idx, &key_sha, &digest_sha, buffer);
    for (uint8_t i = 0; i < security; i++) {
        for (uint8_t j = 0; j < 27; j++) {
            // use address output array as a temp Kerl state storage
            unsigned char *state = address_bytes;

            // the state takes only 48bytes and allows us to reuse key_sha
            kerl_state_squeeze_chunk(&key_sha, state, buffer);
            // re-use key_sha as round_sha
            digest_single_chunk(buffer, &digest_sha, &key_sha);

            // as key_sha has been tainted, reinitialize with the saved state
            kerl_reinitialize(&key_sha, state);
        }
        kerl_squeeze_final_chunk(&digest_sha, digest + NUM_HASH_BYTES * i);

        // reset digest sha for next digest
        kerl_initialize(&digest_sha);
    }
    kerl_absorb_bytes(&digest_sha, digest, NUM_HASH_BYTES * security);
    kerl_squeeze_final_chunk(&digest_sha, address_bytes);

    //char s[81]={0};
    //display and add check_sum
    //get_address_with_check (address, s);
    return true;
}

void get_address_with_check (const unsigned char *address_bytes, char *full_address){
    cx_sha3_t sha;
    kerl_initialize(&sha);

    unsigned char checksum_bytes[NUM_HASH_BYTES];
    kerl_absorb_chunk(&sha, address_bytes);
    kerl_squeeze_final_chunk(&sha, checksum_bytes);

    char full_checksum[NUM_HASH_TRYTES];
    bytes_to_chars(checksum_bytes, full_checksum, NUM_HASH_BYTES);

    bytes_to_chars(address_bytes, full_address, NUM_HASH_BYTES);

    memcpy(full_address + NUM_HASH_TRYTES,
                  full_checksum + NUM_HASH_TRYTES - NUM_CHECKSUM_TRYTES,
                  NUM_CHECKSUM_TRYTES);
}

void chars_to_trytes(const char *chars_in, tryte_t *trytes_out,
                            unsigned int chars_len)
{
    for (unsigned int i = 0; i < chars_len; i++) {
        if (chars_in[i] == '9') {
            trytes_out[i] = 0;
        }
        else if (chars_in[i] >= 'N') {
            trytes_out[i] = chars_in[i] - 'N' + MIN_TRYTE_VALUE;
        }
        else {
            trytes_out[i] = chars_in[i] - 'A' + 1;
        }
    }
}

uint32_t bigint_mult_u32_mem(uint32_t *a, uint32_t factor,
                                    unsigned int ms_index)
{
    uint32_t carry = 0;

    for (unsigned int i = 0; i <= ms_index; i++) {
        const uint64_t v = (uint64_t)factor * a[i] + carry;

        carry = v >> UINT32_WIDTH;
        a[i] = v & UINT32_MAX;
    }

    return carry;
}

void trytes_to_bigint(const tryte_t *trytes, uint32_t *bigint)
{
    // initialy there is no non-zero word
    unsigned int ms_index = 0;
    memset(bigint, 0, BIGINT_LENGTH * sizeof(bigint[0]));

    // special case for the last tryte only holding two trits of value
    bigint[0] = tryte_set_last_trit_zero(trytes[NUM_CHUNK_TRYTES - 1]) + 4;

    for (unsigned int i = NUM_CHUNK_TRYTES - 1; i-- > 0;) {
        // convert to non-balanced ternary
        const uint8_t tryte = trytes[i] + (TRYTE_BASE / 2);

        const uint32_t carry =
            bigint_mult_u32_mem(bigint, TRYTE_BASE, ms_index);
        if (carry > 0 && ms_index < BIGINT_LENGTH - 1) {
            // if there is a carry, we need to use the next higher word
            bigint[++ms_index] = carry;
        }

        if (tryte == 0) {
            // nothing to add
            continue;
        }

        const unsigned int last_changed_index =
            bigint_add_u32_mem(bigint, tryte);
        if (last_changed_index > ms_index) {
            ms_index = last_changed_index;
        }
    }

    // substract the middle of the domain to get balanced ternary
    // as there cannot be any overflows with 242 trits, a simple substraction
    // yields the correct result in two's complement representation
    bigint_sub(bigint, bigint, HALF_3);
}

void trytes_to_bytes(const tryte_t *trytes, unsigned char *bytes)
{
    uint32_t bigint[BIGINT_LENGTH];
    trytes_to_bigint(trytes, bigint);
    bigint_to_bytes(bigint, bytes);
}

void chars_to_bytes(const char *chars, unsigned char *bytes,
                    unsigned int chars_len)
{
    for (unsigned int i = 0; i < chars_len / NUM_CHUNK_TRYTES; i++) {
        tryte_t trytes[NUM_CHUNK_TRYTES];
        chars_to_trytes(chars + i * NUM_CHUNK_TRYTES, trytes, NUM_CHUNK_TRYTES);
        trytes_to_bytes(trytes, bytes + i * NUM_CHUNK_BYTES);
    }
}

bool first_tx(uint8_t p1)
{
    switch (p1) {
    case P1_FIRST:
        return true;
    case P1_MORE:
        return false;
    default:
        // invalid p1 value
        return false;
    }
    return false; // avoid compiler warnings
}

bool bundle_initialize(BUNDLE_CTX *ctx, uint8_t last_tx_index)
{
    if (last_tx_index < 1 || last_tx_index >= MAX_BUNDLE_SIZE) {
        printf("last tx index not in range\r\n");
        return false;
    }
    memset(ctx, 0, sizeof(BUNDLE_CTX));
    ctx->last_tx_index = last_tx_index;
    return true;
}

bool bundle_is_input_tx(const BUNDLE_CTX *ctx, uint8_t tx_index)
{
    if (tx_index > ctx->last_tx_index) {
        printf("bundel is input tx invalid_parameter\r\n");
        return 0;
        //THROW(INVALID_PARAMETER);
    }

    return ctx->values[tx_index] < 0;
}

bool has_reference_transaction(uint8_t current_index)
{
    for (uint8_t i = 1; i < api.security; i++) {
        if (current_index < i || api.bundle_ctx.values[current_index - i] > 0) {
            return false;
        }
        if (bundle_is_input_tx(&api.bundle_ctx, current_index - i)) {
            return true;
        }
    }

    return false;
}

bool validate_tx_order(const TX_INPUT *input)
{
    const uint8_t current_index = api.bundle_ctx.current_tx_index;

    // the receiving addresses are only allowed first or last
    if (input->value > 0 && current_index > 0 &&
        current_index < api.bundle_ctx.last_tx_index) {
        printf("tx_order; output_tx_index=%u\n", current_index);
        return false;
    }

    // the output address must come first and have positive value
    if (input->value <= 0 && current_index == 0) {
        printf("tx_order; no output_tx\n");
        return false;
    }

    // a meta transaction must have a valid reference input transaction
    if (input->value == 0 && current_index > 0 &&
        current_index < api.bundle_ctx.last_tx_index) {
        // this must be a meta transaction
        if (!has_reference_transaction(current_index)) {
            printf("tx_order; meta_tx_index=%u\n", current_index);
            return false;
        }
    }

    return true;
}

bool validate_chars(const char *chars, unsigned int num_chars)
{
    const size_t len = strnlen(chars, num_chars);
    for (unsigned int i = 0; i < len; i++) {
        const char c = chars[i];
        if (c != '9' && (c < 'A' || c > 'Z')) {
            return false;
        }
    }

    return true;
}

bool bundle_has_open_txs(const BUNDLE_CTX *ctx)
{
    return ctx->current_tx_index <= ctx->last_tx_index;
}

bool s64_to_trits(const int64_t value, trit_t *trits, unsigned int num_trits)
{
    memset(trits, 0, num_trits);

    // nothing to compute for zero value
    if (value == 0) {
        return false;
    }

    const bool is_negative = value < 0;
    uint64_t v_abs;
    if (value == INT64_MIN) {
        // inverting INT64_MIN might lead to undefined behavior
        v_abs = INT64_MAX + UINT64_C(1);
    }
    else if (is_negative) {
        v_abs = -value;
    }
    else {
        v_abs = value;
    }

    for (unsigned int i = 0; i < num_trits; i++) {
        if (v_abs == 0) {
            return false;
        }

        int rem = (v_abs % BASE) & INT32_MAX;
        v_abs = v_abs / BASE;
        if (rem > BASE / 2) {
            // lend one from the next highest digit
            v_abs += 1;
            rem -= BASE;
        }

        trits[i] = is_negative ? -rem : rem;
    }

    return v_abs != 0;
}

void trytes_to_trits(const tryte_t *trytes_in, trit_t *trits_out,
                            unsigned int trytes_len)
{
    for (unsigned int i = 0; i < trytes_len; i++) {
        const unsigned int idx = *trytes_in++ - MIN_TRYTE_VALUE;
        const trit_t *trits_mapping = TRITS_TABLE[idx];

        *trits_out++ = trits_mapping[0];
        *trits_out++ = trits_mapping[1];
        *trits_out++ = trits_mapping[2];
    }
}

void chars_to_trits(const char *chars, trit_t *trits, unsigned int chars_len)
{
    tryte_t trytes[chars_len];
    chars_to_trytes(chars, trytes, chars_len);
    trytes_to_trits(trytes, trits, chars_len);
}

bool u32_to_trits(const uint32_t value, trit_t *trits, unsigned int num_trits)
{
    uint32_t v = value;
    memset(trits, 0, num_trits);

    for (unsigned int i = 0; i < num_trits; i++) {
        if (v == 0) {
            return false;
        }

        int rem = (v % BASE) & INT32_MAX;
        v = v / BASE;
        if (rem > BASE / 2) {
            // lend one from the next highest digit
            v += 1;
            rem -= BASE;
        }

        trits[i] = rem;
    }

    return v != 0;
}

void trits_to_trytes(const trit_t *trits_in, tryte_t *trytes_out,
                            unsigned int trits_len)
{
    for (unsigned int i = 0; i < trits_len / TRITS_PER_TRYTE; i++) {
        trytes_out[i] = *trits_in++;
        trytes_out[i] += *trits_in++ * 3;
        trytes_out[i] += *trits_in++ * 9;
    }
}

void trits_to_bigint(const trit_t *trits, uint32_t *bigint)
{
    tryte_t trytes[NUM_HASH_TRYTES];
    trits_to_trytes(trits, trytes, NUM_HASH_TRITS);
    trytes_to_bigint(trytes, bigint);
}

void trits_to_bytes(const trit_t *trits, unsigned char *bytes)
{
    uint32_t bigint[BIGINT_LENGTH];
    trits_to_bigint(trits, bigint);
    bigint_to_bytes(bigint, bytes);
}

void create_bundle_bytes(int64_t value, const char *tag,
                         uint32_t timestamp, uint8_t current_tx_index,
                         uint8_t last_tx_index, unsigned char *bytes)
{
    trit_t bundle_essence_trits[243] = {0};

    s64_to_trits(value, bundle_essence_trits, 81);
    chars_to_trits(tag, bundle_essence_trits + 81, 27);
    u32_to_trits(timestamp, bundle_essence_trits + 162, 27);
    u32_to_trits(current_tx_index, bundle_essence_trits + 189, 27);
    u32_to_trits(last_tx_index, bundle_essence_trits + 216, 27);

    // now we have exactly one chunk of 243 trits
    trits_to_bytes(bundle_essence_trits, bytes);
}

uint32_t bundle_add_tx(BUNDLE_CTX *ctx, int64_t value, const char *tag,
                       uint32_t timestamp)
{
    if (!bundle_has_open_txs(ctx)) {
        printf("bundle_not_open\r\n");
        return 0;
    }

    unsigned char *bytes_ptr = TX_BYTES(ctx);
    // the combined trits make up the second part
    create_bundle_bytes(value, tag, timestamp, ctx->current_tx_index, ctx->last_tx_index, bytes_ptr + 48);

    ctx->values[ctx->current_tx_index] = value;

    return ctx->current_tx_index++;
}

void compute_hash(BUNDLE_CTX *ctx)
{
    cx_sha3_t sha;

    kerl_initialize(&sha);
    kerl_absorb_bytes(&sha, ctx->bytes, TX_BYTES(ctx) - ctx->bytes);
    kerl_squeeze_final_chunk(&sha, ctx->hash);
}

void rpad_chars(char *destination, const char *source, unsigned int num_chars)
{
    const size_t len = strnlen(source, num_chars);
    memcpy(destination, source, len);
    memset(destination + len, PAD_CHAR, num_chars - len);
}

bool bundle_set_external_address(BUNDLE_CTX *ctx, const char *address)
{
    if (!bundle_has_open_txs(ctx)) {
        return false;
    }

    unsigned char *bytes_ptr = TX_BYTES(ctx);
    chars_to_bytes(address, bytes_ptr, 81);
    return true;
}

void bundle_set_internal_address(BUNDLE_CTX *ctx, const char *address,
                                 uint32_t index)
{
    bundle_set_external_address(ctx, address);
    ctx->indices[ctx->current_tx_index] = index;
}



bool add_tx(const TX_INPUT *input)
{
    if (!IN_RANGE(input->value, -MAX_IOTA_VALUE, MAX_IOTA_VALUE)) {
        printf("input value not in range\r\n");
        return 0;
    }

    char padded_tag[27];
    rpad_chars(padded_tag, input->tag, 27);
    if (!validate_chars(padded_tag, 27)) {
        printf("not valied character\r\n");
        return 0;
    }

    bundle_add_tx(&api.bundle_ctx, input->value, padded_tag, input->timestamp);
}

void user_sign_tx()
{
    //ui_display_validating();
    const int retcode = 0;
    //const int retcode = bundle_validating_finalize(
    //    &api.bundle_ctx, get_change_tx_index(&api.bundle_ctx), api.seed_bytes,
    //    api.security);
    compute_hash(&api.bundle_ctx);
    if (retcode != 0) {
        printf("invalidBundle; retcode=%i\n", retcode);
        return;
        //THROW(SW_INVALID_BUNDLE + retcode);
    }
    api.state_flags |= BUNDLE_FINALIZED;

    TX_OUTPUT output;
    bytes_to_chars(api.bundle_ctx.hash, output.bundle_hash, 48);
    print_chr("bundle hash = ", output.bundle_hash, 81);

    //io_send_bundle_hash(&api.bundle_ctx);
}

unsigned int api_tx(API_CTX api1, uint8_t p1, const unsigned char *input_data, unsigned int len){
    memcpy(&api, &api1, sizeof(API_CTX));
    const bool first = first_tx(p1);
    const TX_INPUT *input;
    if(first){
        if(api.state_flags & BUNDLE_INITIALIZED) {
            printf("first already initialized\r\n");
            return 0;
        }
        //const unsigned int offset = update_seed(input_data, len);
        //input = (TX_INPUT *) input_data + offset;
        input = (TX_INPUT *) input_data;
    }
    else{
        if((api.state_flags & BUNDLE_INITIALIZED)==0){
            printf("multi not initilatized\r\n");
            return 0;
        }
        input = (TX_INPUT *) input_data;
    }

    if(first){
        if (!IN_RANGE(input->last_index, 1, MAX_BUNDLE_SIZE - 1)) {
            printf("last index out of range\r\n");
            return 0;
        }

        bundle_initialize(&api.bundle_ctx, input->last_index);
        api.state_flags |= BUNDLE_INITIALIZED;
    }
    else if((input->last_index != api.bundle_ctx.last_tx_index)){
        printf("last not as expected\r\n");
        return 0;
    }

    if (input->current_index != api.bundle_ctx.current_tx_index) {
        printf("current index not as expected\r\n");
        return 0;
    }
    if (!validate_tx_order(input)) {
        printf("transactions not in the expected order\r\n");
        return 0;
    }

    if (!validate_chars(input->address, 81)) {
        // invalid address
        printf("invalid address\r\n");
        return 0;
    }

    if (input->value < 0 ||
        api.bundle_ctx.current_tx_index == api.bundle_ctx.last_tx_index) {
        bundle_set_internal_address(&api.bundle_ctx, input->address,
                                    input->address_idx);
    }
    else {
        // ignore index completely
        bundle_set_external_address(&api.bundle_ctx, input->address);
    }
    add_tx(input);
    if(!bundle_has_open_txs(&api.bundle_ctx)){
        printf("bundal has open txs\r\n");
        print_chr("hash = ", api.bundle_ctx.hash, 81);
        user_sign_tx();
        return 1;
    }

    return 0;
}

const unsigned char *bundle_get_hash(const BUNDLE_CTX *ctx)
{
    if (bundle_has_open_txs(ctx)) {
        printf("bundle has already been finalized\r\n");

        return 0;
    }
    // TODO check that the bundle has already been finalized

    return ctx->hash;
}

int decrement_tryte(int max, tryte_t *tryte)
{
    const int slack = *tryte - MIN_TRYTE_VALUE;
    if (slack <= 0) {
        return 0;
    }

    const int dec = MIN(max, slack);
    *tryte -= dec;

    return dec;
}

int increment_tryte(int max, tryte_t *tryte)
{
    const int slack = MAX_TRYTE_VALUE - *tryte;
    if (slack <= 0) {
        return 0;
    }

    const int inc = MIN(max, slack);
    *tryte += inc;

    return inc;
}

void normalize_hash_fragment(tryte_t *fragment_trytes)
{
    int sum = 0;
    for (unsigned int j = 0; j < 27; j++) {
        sum += fragment_trytes[j];
    }

    for (unsigned int j = 0; j < 27; j++) {
        if (sum > 0) {
            sum -= decrement_tryte(sum, &fragment_trytes[j]);
        }
        else if (sum < 0) {
            sum += increment_tryte(-sum, &fragment_trytes[j]);
        }
        if (sum == 0) {
            break;
        }
    }
}

void normalize_hash(tryte_t *hash_trytes)
{
    for (unsigned int i = 0; i < 3; i++) {
        normalize_hash_fragment(hash_trytes + i * 27);
    }
}

void bundle_get_normalized_hash(const BUNDLE_CTX *ctx, tryte_t *hash_trytes)
{
    bytes_to_trytes(bundle_get_hash(ctx), hash_trytes);
    normalize_hash(hash_trytes);
}

void initialize_state(const unsigned char *seed_bytes,
                             uint32_t address_idx, unsigned char *state)
{
    memcpy(state, seed_bytes, 48);
    bytes_add_u32_mem(state, address_idx);

    cx_sha3_t sha;
    kerl_initialize(&sha);
    kerl_absorb_chunk(&sha, state);
    kerl_squeeze_final_chunk(&sha, state);
}

void signing_initialize(SIGNING_CTX *ctx, uint8_t tx_index,
                        const unsigned char *seed_bytes, uint32_t address_idx,
                        uint8_t security, const tryte_t *normalized_hash)
{
    memset(ctx, 0, sizeof(SIGNING_CTX));

    initialize_state(seed_bytes, address_idx, ctx->state);
    ctx->last_fragment = NUM_SIGNATURE_FRAGMENTS(security) - 1;
    ctx->tx_index = tx_index;

    memcpy(ctx->hash, normalized_hash, 81);
}

bool signing_has_next_fragment(const SIGNING_CTX *ctx)
{
    return ctx->fragment_index <= ctx->last_fragment;
}

void generate_signature_fragment(unsigned char *state,
                                        const tryte_t *hash_fragment,
                                        unsigned char *signature_bytes)
{
    cx_sha3_t sha;

    for (unsigned int j = 0; j < SIGNATURE_FRAGMENT_SIZE; j++) {
        unsigned char *signature_f = signature_bytes + j * NUM_HASH_BYTES;

        kerl_reinitialize(&sha, state);
        // the output of the squeeze is exactly the private key
        kerl_state_squeeze_chunk(&sha, state, signature_f);

        for (unsigned int k = MAX_TRYTE_VALUE - hash_fragment[j]; k-- > 0;) {
            kerl_initialize(&sha);
            kerl_absorb_chunk(&sha, signature_f);
            kerl_squeeze_final_chunk(&sha, signature_f);
        }
        //print_hex("signature_f = ", signature_f, sizeof(signature_f));
    }
}

unsigned int signing_next_fragment(SIGNING_CTX *ctx,
                                   unsigned char *signature_bytes)
{
    if (!signing_has_next_fragment(ctx)) {
        printf("invaled state \r\n");
        return 0;
    }

    generate_signature_fragment(
        ctx->state, ctx->hash + ctx->fragment_index * SIGNATURE_FRAGMENT_SIZE,
        signature_bytes);

    return ctx->fragment_index++;
}

bool next_signature_fragment(SIGNING_CTX *ctx, char *signature_fragment)
{
    unsigned char fragment_bytes[SIGNATURE_FRAGMENT_SIZE * 48];
    signing_next_fragment(ctx, fragment_bytes);

    bytes_to_chars(fragment_bytes, signature_fragment,
                   SIGNATURE_FRAGMENT_SIZE * 48);
    //print_chr("signature_fragment = ", signature_fragment, SIGNATURE_FRAGMENT_SIZE * 48);
    return signing_has_next_fragment(ctx);
}

unsigned int api_sign(uint8_t p1, const unsigned char *input_data, unsigned int len)
{
    UNUSED(p1);
    const SIGN_INPUT *input = (SIGN_INPUT *) input_data;
    uint8_t tx_idx;
        if (!ASSIGN(tx_idx, input->transaction_idx) ||
            tx_idx > api.bundle_ctx.last_tx_index) {
            // index is out of bounds
            printf("index more then last index\r\n");
            return 0;
        }
    // initialize signing if necessary
    if ((api.state_flags & SIGNING_STARTED) == 0) {
        if (api.bundle_ctx.values[tx_idx] >= 0) {
            // no input transaction
            printf("No input transaction\r\n");
            return 0;
        }

        tryte_t normalized_hash[81];
        bundle_get_normalized_hash(&api.bundle_ctx, normalized_hash);
        signing_initialize(&api.signing_ctx, tx_idx, api.seed_bytes,
                           api.bundle_ctx.indices[tx_idx], api.security,
                           normalized_hash);

        api.state_flags |= SIGNING_STARTED;
    }
    else if (tx_idx != api.signing_ctx.tx_index) {
        // transaction changed after initialization
        printf("transaction changed after initialization\r\n");
        return 0;
    }

    SIGN_OUTPUT output;
    output.fragments_remaining =
        next_signature_fragment(&api.signing_ctx, output.signature_fragment);

    print_chr("signature fragment = ", output.signature_fragment, SIGNATURE_FRAGMENT_SIZE * 81);
    //io_send(&output, sizeof(output), SW_OK);

}



void iota_seed(){

    

    const char mnemonic[] = {"rare axis denial pursa updates people worry audit walk zoo flower mosquito urge icon stand ability puppy walk mandate flash body journey soon head"};
    //const char mnemonic[] = {"glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"};


    //const char mnemonic[] = {"since hollow sweet misery advice siren grant across copper crunch drastic subject brass inside slight cannon ordinary silly theme begin noise coil mechanic gospel"};
    uint8_t sessionSeed[64];
    mnemonic_to_seed(mnemonic, "", sessionSeed, NULL);
    //correct
    print_hex("sessionSeed = ", sessionSeed, 64);
    HDNode node;
    hdnode_from_seed(sessionSeed, 64, SECP256K1_NAME, &node);
    //correct
    uint32_t address_n[5]={0x8000002C, 0x8000107A, 0x80000000, 0x00000000, 0x00000000};
    hdnode_private_ckd_cached(&node, address_n, 5, 0);

    //curve25519_scalarmult_basepoint(node.public_key + 1, node.private_key);

    //hdnode_fill_public_key(&node);
    print_hex("private_key = ", node.private_key, 32);
    print_hex("chain_code = ", node.chain_code, 32);

    char entropy[64]={0};    
    memcpy(entropy, node.private_key, 32);
    memcpy(entropy+32, node.chain_code, 32);
    uint8_t seed_bytes[48]={0};
    uint8_t address[48];
    derive_seed_entropy(entropy, sizeof(entropy), seed_bytes);
    print_hex("seed = ", seed_bytes, 48);
    get_public_add(seed_bytes, 0, 1, address);
    
    char s[90]= {0};
    bytes_to_chars(address, s, 81);

    // get_address_with_check (address, s);

    //print_hex("seed = ", seed_bytes, 48);
    // print_hex("seed = ", seed_bytes, 48);

    tryte_t trytes[81];

    bytes_to_trytes(seed_bytes, trytes);
    char sed[81];
    trytes_to_chars(trytes, sed, 81);
    
    print_chr("seed = ", sed, 81);    
    

    
    // bytes_to_chars(seed_bytes, s, 81);
    // print_chr("seed = ", s, 81);
    
    
    // printf("hello \r\n");
    // bytes_to_chars(address, s, 81);
    // print_chr("address 44\'/4218\'/0\'/0/0 = ", s, 81);

    
    print_chr("address+chksm 44\'/4218\'/0\'/0/0 = ", s, 81);
    // char sed[81];

    // bytes_to_trytes(entropy, trytes);
    // trytes_to_chars(trytes, sed, 81);

    // print_chr("entropy tryts = ", sed, 81);
    // //print_hex("in hex = ", sed, 81);


    // bytes_to_trytes(sessionSeed, trytes);
    // trytes_to_chars(trytes, sed, 81);
    // //print_hex("in hex = ", sed, 81);
    // print_chr("session seed = ", sed, 81);
    // print_hex("trytes = ", (char *)trytes, 48);
    // print_chr("trytes = ", (char *)trytes, 48);
    // //unsigned char address_bytes[512];
    // //char see[]={"QNWOIDYNBFKYYRZGJFHRLIACH9QHDTTBUOFHNSQCPLWTLZCZZUWUQFBQVMNUIXWNQOKBUXDBBPYHHNT9C"};
    // char see[]={"FZEWQQDWIDOAKVCUXJGWLSOKPYEBAILHYISARHDVYEMNZPADFTSRCQDQJSFTRWFXELAVSHXNNNNON9DHH"};
    // uint8_t sead[48];
    // chars_to_bytes(see, sead, 81);

    // print_chr("seed = ", see, 81);
    // print_hex("seed hex = ", sead, 51);

    // get_public_add(sead, 0, 1, seed_bytes);

    //get_public_add(seed_bytes, 0, 1, sead);

}

void signing(){

    api.state_flags = 0;
    printf("Signing started\r\n");
    //char seed[] = {"SXDIQDWJYBAYNGITNVYGBKVPFTZQNSZIPIQYXNISQTAVUCKR9LPXRHGQITDRNTJDKYCOKXMFVIGNWGAGS"};
    char seed[] = {"YQYPUOKZXI9IFG9LB9HZLZYADAFIBGQMHUHDIXBZRDMEL9FBKHGILAZLR9RUEEEU9BKLBNVTVMBYRDPCB"};

    uint8_t sead[48]={0};
    printf("api.seed bytes = %ld", strlen((const char *)&api.seed_bytes));
    chars_to_bytes(seed, sead, 81);
    //unsigned char sead[48]={0};
    //chars_to_bytes(seed, sead, 48);
    print_hex("seed hex befor = ", sead, 48);
    memcpy(api.seed_bytes, sead, NUM_HASH_BYTES);
    uint8_t security = 3;
    api.security = security;
    TX_INPUT input[3];
    char address0[] = {"EGVASUBSWPDEYRRGTLBXVDJBR9GCTYPMOFBTJWMRARDQA9HI9BPLAWZMATSTSJ9GPHVQTGRFLNUI9WIEC"};
//    char address0[] = {"TIX9FZNCNZQCNTGQXKSIRPHWBYBPIPEJIZMHAILBTSPEREHEBQUPKFHXUYTJSLVCARXHOOEXYEGAXUDAR"};
    memcpy(input[0].address, address0, 81);
    input[0].address_idx = 0;
    input[0].value = 1;
    char tag0[] = {"OPOLOFKXFZJTWEZFQZTIWIXHLB"};
    char tag[] = {"999999999999999999999999999"};
    memcpy(input[0].tag, tag0, 27);
    input[0].timestamp = 1583225083;
    input[0].current_index = 0;
    input[0].last_index = 2;

    char address1[] = {"IZMUDBYKSYKHWPIBPPQYDGUVHEMDPUHEKOSKIZCFHKAECLFPCQPUUYSFOWLSFCNJYWOFANJZLLOEGRKBX"};
    memcpy(input[1].address, address1, 81);
    //input[1].address_idx = 145;
    input[1].value = -1;
    memcpy(input[1].tag, tag, 27);
    input[1].timestamp = 1583225083;
    input[1].current_index = 1;
    input[1].last_index = 2;

    char address2[] = {"IZMUDBYKSYKHWPIBPPQYDGUVHEMDPUHEKOSKIZCFHKAECLFPCQPUUYSFOWLSFCNJYWOFANJZLLOEGRKBX"};
    memcpy(input[2].address, address2, 81);
    //input[2].address_idx = 145;//79
    input[2].value = 0;
    memcpy(input[2].tag, tag, 27);
    input[2].timestamp = 1583225083;
    input[2].current_index = 2;
    input[2].last_index = 2;

    {
    TX_OUTPUT output = {0};
    output.finalized = false;
    //io_send(&output, sizeof(output), 0);
    api_tx(api, P1_FIRST, (const unsigned char *)&input[0], sizeof(TX_INPUT));
    }

    {
    TX_OUTPUT output = {0};
    output.finalized = false;
    api_tx(api, P1_MORE, (const unsigned char *)&input[1], sizeof(TX_INPUT));
    }
    /*{
    TX_OUTPUT output = {0};
    output.finalized = false;
    api_tx(P1_MORE, (const unsigned char *)&input[2], sizeof(input));
    }
    {
    TX_OUTPUT output = {0};
    output.finalized = false;
    api_tx(P1_MORE, (const unsigned char *)&input[3], sizeof(input));
    }*/
    {
    TX_OUTPUT output = {0};
    output.finalized = true;
    api_tx(api, P1_MORE, (const unsigned char *)&input[2], sizeof(TX_INPUT));
    //9*print_chr("bundle hash = ", api.bundle_ctx.hash, 81);
    //print_hex("TX_output = ", output.bundle_hash, 81);
    char s[81];
    bytes_to_chars(api.seed_bytes, s, 81);
    print_chr("seed = ", s, 81);
    print_hex("seed hex = ", api.seed_bytes, 48);
    //api.signing_ctx.hash
    //trytes_to_chars(api.signing_ctx.hash, s, 81);
    //print_chr("hash = ", s, 81);
    //chars_to_bytes(api.seed_bytes, sead, 81);
    }

    //const char signature[][SIGNATURE_LENGTH]={0};
    const int num_inputs = (4 - 1) / 3;
    //printf("\r\nSignature = ");
    for (int i = 0; i < num_inputs; i++) {
        for (int j = 0; j < NUM_SIGNATURE_FRAGMENTS(security); j++) {
            SIGN_INPUT input;
            input.transaction_idx = 1 + i * security;

            SIGN_OUTPUT output;
            output.fragments_remaining = (j + 1) != NUM_SIGNATURE_FRAGMENTS(security);

            //memcpy(output.signature_fragment, signature + i + j * 243, 243);
            api_sign(0, (unsigned char *)&input, sizeof(input));
            //print_chr("",output.signature_fragment, 243);
            //EXPECT_API_DATA_OK(sign, 0, input, output);
        }
    }
    //char s[81];
    //trytes_to_chars(api.signing_ctx.hash, s, 81);
    //print_chr("hash = ", s , 81);
    printf("\r\nsigning ended\r\n");
}