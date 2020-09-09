#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hal.h"
#include "simpleserial.h"

#include "chacha.h"


#define BLOCK_LENGTH                (64)
#define KEY_LENGTH                  (32)
#define NONCE_LENGTH                (12)

#define DEFAULT_KEY                 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
#define DEFAULT_NONCE               0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x4a,0x00,0x00,0x00,0x00
#define AUTO_INCREMENT              (0)


static struct chacha_state state;
static uint8_t key[KEY_LENGTH] = {DEFAULT_KEY};
static uint8_t nonce[NONCE_LENGTH] = {DEFAULT_NONCE};
static uint32_t counter = 1;
static uint8_t plaintext[BLOCK_LENGTH];
static uint8_t ciphertext[BLOCK_LENGTH];


// update the key
uint8_t set_key (uint8_t *k) {
    memcpy(key, k, KEY_LENGTH);
    chacha_set_key(&state, key);
	return 0x00;
}

// update the nonce
uint8_t set_nonce (uint8_t *n) {
    memcpy(nonce, n, NONCE_LENGTH);
    chacha_set_nonce(&state, nonce);
	return 0x00;
}

// update the counter
uint8_t set_counter (uint8_t *c) {
    counter = (((uint32_t) c[3])<<24) | (((uint32_t) c[2])<<16) | (((uint32_t) c[1])<<8) | c[0];
    chacha_set_counter(&state, counter);
	return 0x00;
}

// update the first half of the plaintext
uint8_t set_pt_a (uint8_t *pt) {
    memcpy(plaintext, pt, BLOCK_LENGTH/2);
    return 0x00;
}

// update the second half of the plaintext
uint8_t set_pt_b (uint8_t *pt) {
    memcpy(plaintext+BLOCK_LENGTH/2, pt, BLOCK_LENGTH/2);
    return 0x00;
}

// read the first half of the ciphertext
uint8_t get_ct_a (uint8_t *ct) {
	simpleserial_put('A', BLOCK_LENGTH/2, ciphertext);
    return 0x00;
}

// read the second half of the ciphertext
uint8_t get_ct_b (uint8_t *ct) {
	simpleserial_put('B', BLOCK_LENGTH/2, ciphertext+BLOCK_LENGTH/2);
    return 0x00;
}


// perform a calculation of the chacha block
uint8_t do_enc (uint8_t *x) {
	trigger_low();
	trigger_high();

    uint8_t out[64];
    chacha_block(&state, out);

    for (int i=0; i<BLOCK_LENGTH; i++) {
        ciphertext[i] = plaintext[i] ^ out[i];
    }
    
	simpleserial_put('r', 0, NULL);
	return 0x00;
}

// set counter to 1
uint8_t reset (uint8_t *x) {
    counter = 1;
    chacha_set_counter(&state, counter);
	return 0x00;
}


int main( void) {
    platform_init();
    init_uart();
    trigger_setup();

    chacha_init(&state, key, counter, nonce, AUTO_INCREMENT);

	simpleserial_init();
    simpleserial_addcmd('k', KEY_LENGTH, set_key);
    simpleserial_addcmd('a', BLOCK_LENGTH/2, set_pt_a);
    simpleserial_addcmd('b', BLOCK_LENGTH/2, set_pt_b);
    simpleserial_addcmd('A', 0, get_ct_a);
    simpleserial_addcmd('B', 0, get_ct_b);
    simpleserial_addcmd('p', 1, do_enc);
    simpleserial_addcmd('x', 0, reset);
    simpleserial_addcmd('n', NONCE_LENGTH, set_nonce);
    simpleserial_addcmd('c', 4, set_counter);

    while (1) {
        simpleserial_get();
    }
}

