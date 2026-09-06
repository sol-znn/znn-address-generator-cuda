// mnemonic.cuh -- device-side mnemonic generation.
//
// znn-address-generator-go builds each mnemonic with
// bip39.NewMnemonic(32 random bytes): 256 bits of entropy plus an 8-bit
// SHA-256 checksum, cut into 24 eleven-bit word indices. This file does the
// same on the GPU, and supplies the entropy each thread starts from.
//
// The entropy is not drawn on the device. The host draws one 32-byte key per
// launch from the operating system's CSPRNG, and each thread expands it with
// SHA-512(key || counter) -- a counter-mode PRF, so every thread of every
// launch gets a distinct, unpredictable 256 bits without any device-side RNG
// state to seed, checkpoint, or accidentally repeat.
#ifndef MNEMONIC_CUH
#define MNEMONIC_CUH

#include <cstdint>

#include "crypto.cuh"
#include "wordlist.h"  // ENTROPY_BYTES, MNEMONIC_WORDS

// ---------------------------------------------------------------------------
// SHA-256, used only for the 8-bit BIP-39 checksum of a 32-byte entropy.
// The input always fits one 64-byte block, so there is no streaming path.
// ---------------------------------------------------------------------------

__constant__ uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

__device__ __forceinline__ uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

// sha256_block hashes a single-block message (len <= 55 bytes).
__device__ void sha256_block(const uint8_t* msg, int len, uint8_t out[32]) {
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    uint8_t block[64];
    for (int i = 0; i < 64; i++) block[i] = 0;
    for (int i = 0; i < len; i++) block[i] = msg[i];
    block[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) block[63 - i] = (uint8_t)(bits >> (8 * i));

    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;

    for (int i = 0; i < 8; i++) {
        out[i * 4 + 0] = (uint8_t)(h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(h[i]);
    }
}

// ---------------------------------------------------------------------------
// Entropy and mnemonic
// ---------------------------------------------------------------------------

// entropy_from_counter expands the launch key into this thread's 32 entropy
// bytes: SHA-512(key || counter)[:32], with the counter big-endian.
__device__ void entropy_from_counter(const uint8_t key[32], uint64_t counter,
                                     uint8_t entropy[ENTROPY_BYTES]) {
    uint8_t buf[40];
    for (int i = 0; i < 32; i++) buf[i] = key[i];
    for (int i = 0; i < 8; i++) buf[32 + i] = (uint8_t)(counter >> (8 * (7 - i)));

    uint8_t h[64];
    sha512(buf, 40, h);
    for (int i = 0; i < ENTROPY_BYTES; i++) entropy[i] = h[i];
}

// mnemonic_from_entropy turns 32 entropy bytes into 24 word indices, exactly
// as bip39.NewMnemonic does: append the top 8 bits of SHA-256(entropy), then
// read the 264-bit string 11 bits at a time.
__device__ void mnemonic_from_entropy(const uint8_t entropy[ENTROPY_BYTES],
                                      uint16_t words[MNEMONIC_WORDS]) {
    uint8_t digest[32];
    sha256_block(entropy, ENTROPY_BYTES, digest);

    // Two bytes of zero padding so the last word can read three whole bytes.
    uint8_t bits[ENTROPY_BYTES + 3];
    for (int i = 0; i < ENTROPY_BYTES; i++) bits[i] = entropy[i];
    bits[ENTROPY_BYTES] = digest[0];
    bits[ENTROPY_BYTES + 1] = 0;
    bits[ENTROPY_BYTES + 2] = 0;

    for (int i = 0; i < MNEMONIC_WORDS; i++) {
        int bit = i * 11;
        int byte = bit >> 3;
        int off = bit & 7;
        uint32_t v = ((uint32_t)bits[byte] << 16) | ((uint32_t)bits[byte + 1] << 8) |
                     (uint32_t)bits[byte + 2];
        words[i] = (uint16_t)((v >> (13 - off)) & 0x7ff);
    }
}

#endif  // MNEMONIC_CUH
