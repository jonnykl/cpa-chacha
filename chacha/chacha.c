#include <stdint.h>
#include "chacha.h"


// based on:
// - https://tools.ietf.org/html/rfc7539
// - https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant


#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d) (                        \
    a += b,  d ^= a,  d = ROTL(d,16),           \
    c += d,  b ^= c,  b = ROTL(b,12),           \
    a += b,  d ^= a,  d = ROTL(d, 8),           \
    c += d,  b ^= c,  b = ROTL(b, 7))


void chacha_init (struct chacha_state *state, uint8_t key[32], uint32_t counter, uint8_t nonce[12], int auto_increment) {
    state->initial_state[0] = 0x61707865;       // 'expa'
    state->initial_state[1] = 0x3320646e;       // 'nd 3'
    state->initial_state[2] = 0x79622d32;       // '2-by'
    state->initial_state[3] = 0x6b206574;       // 'te k'

    chacha_set_key(state, key);
    chacha_set_counter(state, counter);
    chacha_set_nonce(state, nonce);

    state->auto_increment = auto_increment;
}


void chacha_block (struct chacha_state *state, uint8_t out[64]) {
    int i;
    uint32_t x[16];
    uint32_t tmp;


    for (i=0; i<16; i++) {
        x[i] = state->initial_state[i];
    }

    // 10 loops × 2 rounds/loop = 20 rounds
    for (i=0; i<CHACHA_ROUNDS; i+=2) {
        // odd round
        QR(x[0], x[4], x[ 8], x[12]); // column 0
        QR(x[1], x[5], x[ 9], x[13]); // column 1
        QR(x[2], x[6], x[10], x[14]); // column 2
        QR(x[3], x[7], x[11], x[15]); // column 3

        // even round
        QR(x[0], x[5], x[10], x[15]); // diagonal 1 (main diagonal)
        QR(x[1], x[6], x[11], x[12]); // diagonal 2
        QR(x[2], x[7], x[ 8], x[13]); // diagonal 3
        QR(x[3], x[4], x[ 9], x[14]); // diagonal 4
    }

    // serialize state
    for (i=0; i<64; i+=4) {
        tmp = state->initial_state[i/4] + x[i/4];

        out[i+0] = tmp;
        out[i+1] = tmp>>8;
        out[i+2] = tmp>>16;
        out[i+3] = tmp>>24;
    }


    if (state->auto_increment) {
        state->initial_state[12]++;
    }
}


void chacha_set_counter (struct chacha_state *state, uint32_t counter) {
    state->initial_state[12] = counter;
}

void chacha_set_nonce (struct chacha_state *state, uint8_t nonce[12]) {
    int i;

    for (i=0; i<12; i+=4) {
        state->initial_state[13 + i/4] =
            (((uint32_t) nonce[i+3])<<24) |
            (((uint32_t) nonce[i+2])<<16) |
            (((uint32_t) nonce[i+1])<< 8) |
            nonce[i];
    }
}

void chacha_set_key (struct chacha_state *state, uint8_t key[32]) {
    int i;

    for (i=0; i<32; i+=4) {
        state->initial_state[4 + i/4] =
            (((uint32_t) key[i+3])<<24) |
            (((uint32_t) key[i+2])<<16) |
            (((uint32_t) key[i+1])<< 8) |
            key[i];
    }
}

