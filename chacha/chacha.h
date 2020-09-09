#ifndef CHACHA_H
#define CHACHA_H


#include <stdint.h>


#define CHACHA_ROUNDS 20


// current state and parameters
struct chacha_state {
    uint32_t initial_state[16];
    int auto_increment;
};


// init state with given key, counter, nonce and counter auto increment option
void chacha_init(struct chacha_state *state, uint8_t key[32], uint32_t counter, uint8_t nonce[12], int auto_increment);

// calculate block
void chacha_block(struct chacha_state *state, uint8_t out[64]);

// set counter
void chacha_set_counter(struct chacha_state *state, uint32_t counter);

// set nonce
void chacha_set_nonce(struct chacha_state *state, uint8_t nonce[12]);

// set key
void chacha_set_key(struct chacha_state *state, uint8_t key[32]);


#endif /* CHACHA_H */
