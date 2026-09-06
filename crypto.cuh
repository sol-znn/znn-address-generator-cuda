// crypto.cuh -- device-side cryptography for the Zenon mnemonic search.
//
// Every candidate mnemonic is turned into one or more Zenon addresses entirely
// on the GPU, mirroring what deriveAddresses does in znn-bruteforce-go:
//
//   mnemonic --PBKDF2-HMAC-SHA512 (2048 rounds)--> 64-byte BIP-39 seed
//   seed     --SLIP-0010 (ed25519), m/44'/73404'/{account}'--> 32-byte key
//   key      --SHA-512 + ed25519 scalar-base mult--> 32-byte public key
//   pubkey   --SHA3-256--> digest; core = 0x00 || digest[:19]
//   core     compared against the target address cores
//
// PBKDF2 is by far the hot path (2048 SHA-512 iterations per candidate), so it
// uses the standard precomputed-ipad/opad optimization. The English BIP-39
// list is pure lowercase ASCII, so NFKD normalization is the identity and is
// not performed.

#ifndef CRYPTO_CUH
#define CRYPTO_CUH

#include <cstdint>

// ---------------------------------------------------------------------------
// SHA-512
// ---------------------------------------------------------------------------

__constant__ uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

__device__ __forceinline__ uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

// sha512_compress folds one 128-byte block into the eight-word state.
__device__ void sha512_compress(uint64_t state[8], const uint8_t block[128]) {
    uint64_t w[80];
#pragma unroll
    for (int i = 0; i < 16; i++) {
        int j = i * 8;
        w[i] = ((uint64_t)block[j] << 56) | ((uint64_t)block[j + 1] << 48) |
               ((uint64_t)block[j + 2] << 40) | ((uint64_t)block[j + 3] << 32) |
               ((uint64_t)block[j + 4] << 24) | ((uint64_t)block[j + 5] << 16) |
               ((uint64_t)block[j + 6] << 8) | ((uint64_t)block[j + 7]);
    }
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint64_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 80; i++) {
        uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t t1 = h + S1 + ch + K512[i] + w[i];
        uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

__device__ __forceinline__ void sha512_iv(uint64_t state[8]) {
    state[0] = 0x6a09e667f3bcc908ULL; state[1] = 0xbb67ae8584caa73bULL;
    state[2] = 0x3c6ef372fe94f82bULL; state[3] = 0xa54ff53a5f1d36f1ULL;
    state[4] = 0x510e527fade682d1ULL; state[5] = 0x9b05688c2b3e6c1fULL;
    state[6] = 0x1f83d9abfb41bd6bULL; state[7] = 0x5be0cd19137e2179ULL;
}

// serialize writes the state as 64 big-endian bytes.
__device__ __forceinline__ void sha512_serialize(const uint64_t state[8], uint8_t out[64]) {
#pragma unroll
    for (int i = 0; i < 8; i++) {
        uint64_t v = state[i];
        out[i * 8 + 0] = (uint8_t)(v >> 56); out[i * 8 + 1] = (uint8_t)(v >> 48);
        out[i * 8 + 2] = (uint8_t)(v >> 40); out[i * 8 + 3] = (uint8_t)(v >> 32);
        out[i * 8 + 4] = (uint8_t)(v >> 24); out[i * 8 + 5] = (uint8_t)(v >> 16);
        out[i * 8 + 6] = (uint8_t)(v >> 8);  out[i * 8 + 7] = (uint8_t)(v);
    }
}

// sha512 hashes an arbitrary-length message (general streaming path, used off
// the hot loop: hashing over-long HMAC keys and the ed25519 seed).
__device__ void sha512(const uint8_t* msg, uint32_t len, uint8_t out[64]) {
    uint64_t state[8];
    sha512_iv(state);

    uint32_t off = 0;
    while (len - off >= 128) {
        sha512_compress(state, msg + off);
        off += 128;
    }

    uint8_t block[256];
    uint32_t rem = len - off;
    for (uint32_t i = 0; i < rem; i++) block[i] = msg[off + i];
    block[rem] = 0x80;

    uint32_t total = (rem + 1 <= 112) ? 128 : 256;
    for (uint32_t i = rem + 1; i < total; i++) block[i] = 0;

    uint64_t bits = (uint64_t)len * 8;
    // 128-bit length; message length here always fits in the low 64 bits.
    for (int i = 0; i < 8; i++) block[total - 8 + i] = (uint8_t)(bits >> (56 - 8 * i));

    sha512_compress(state, block);
    if (total == 256) sha512_compress(state, block + 128);  // never reached for our sizes
    sha512_serialize(state, out);
}

// sha512_finish_block finalizes a hash whose first 128-byte block has already
// been folded into `state` (the ipad/opad block). The remaining message must
// fit in a single block (<= 111 bytes), which holds for every use here.
__device__ void sha512_finish_block(uint64_t state[8], const uint8_t* msg, int msglen,
                                     uint64_t total_bytes, uint8_t out[64]) {
    uint8_t block[128];
    for (int i = 0; i < msglen; i++) block[i] = msg[i];
    block[msglen] = 0x80;
    for (int i = msglen + 1; i < 128; i++) block[i] = 0;

    uint64_t bits = total_bytes * 8;
    for (int i = 0; i < 8; i++) block[120 + i] = (uint8_t)(bits >> (56 - 8 * i));

    sha512_compress(state, block);
    sha512_serialize(state, out);
}

// ---------------------------------------------------------------------------
// HMAC-SHA512
// ---------------------------------------------------------------------------

// hmac_prepare folds the ipad/opad key blocks into their two mid-states.
__device__ void hmac_prepare(const uint8_t* key, int keylen,
                             uint64_t istate[8], uint64_t ostate[8]) {
    uint8_t k0[128];
    if (keylen > 128) {
        uint8_t hk[64];
        sha512(key, keylen, hk);
        for (int i = 0; i < 64; i++) k0[i] = hk[i];
        for (int i = 64; i < 128; i++) k0[i] = 0;
    } else {
        for (int i = 0; i < keylen; i++) k0[i] = key[i];
        for (int i = keylen; i < 128; i++) k0[i] = 0;
    }

    uint8_t blk[128];
    for (int i = 0; i < 128; i++) blk[i] = k0[i] ^ 0x36;
    sha512_iv(istate);
    sha512_compress(istate, blk);

    for (int i = 0; i < 128; i++) blk[i] = k0[i] ^ 0x5c;
    sha512_iv(ostate);
    sha512_compress(ostate, blk);
}

// hmac_sha512 computes a full HMAC for a short message (datalen <= 111).
__device__ void hmac_sha512(const uint8_t* key, int keylen,
                            const uint8_t* data, int datalen, uint8_t out[64]) {
    uint64_t istate[8], ostate[8];
    hmac_prepare(key, keylen, istate, ostate);

    uint8_t inner[64];
    sha512_finish_block(istate, data, datalen, 128 + datalen, inner);
    sha512_finish_block(ostate, inner, 64, 128 + 64, out);
}

// ---------------------------------------------------------------------------
// PBKDF2-HMAC-SHA512, dkLen = 64 (a single output block), c = 2048.
// This is the BIP-39 seed stretch and the dominant cost of the search.
// ---------------------------------------------------------------------------

__device__ void pbkdf2_bip39_seed(const uint8_t* pw, int pwlen, uint8_t seed[64]) {
    // The password (mnemonic) is fixed across all 2048 iterations, so the
    // ipad/opad states are computed once and reused.
    uint64_t istate[8], ostate[8];
    hmac_prepare(pw, pwlen, istate, ostate);

    // U1 = HMAC(pw, "mnemonic" || INT32BE(1))
    uint8_t msg[12] = {'m', 'n', 'e', 'm', 'o', 'n', 'i', 'c', 0, 0, 0, 1};
    uint64_t is[8], os[8];
    uint8_t inner[64], u[64], t[64];

    for (int i = 0; i < 8; i++) is[i] = istate[i];
    sha512_finish_block(is, msg, 12, 128 + 12, inner);
    for (int i = 0; i < 8; i++) os[i] = ostate[i];
    sha512_finish_block(os, inner, 64, 128 + 64, u);
    for (int i = 0; i < 64; i++) t[i] = u[i];

    // U2..U2048, each HMAC over the previous 64-byte block.
    for (int it = 1; it < 2048; it++) {
        for (int i = 0; i < 8; i++) is[i] = istate[i];
        sha512_finish_block(is, u, 64, 128 + 64, inner);
        for (int i = 0; i < 8; i++) os[i] = ostate[i];
        sha512_finish_block(os, inner, 64, 128 + 64, u);
        for (int i = 0; i < 64; i++) t[i] ^= u[i];
    }

    for (int i = 0; i < 64; i++) seed[i] = t[i];
}

// ---------------------------------------------------------------------------
// SLIP-0010 ed25519 key derivation for m/44'/73404'/{account}'
// ---------------------------------------------------------------------------

#define ZNN_COIN_TYPE 73404u
#define HARDENED 0x80000000u

// slip10_account_key derives the 32-byte ed25519 seed for the given account.
__device__ void slip10_account_key(const uint8_t seed[64], uint32_t account, uint8_t out_key[32]) {
    uint8_t key[32], cc[32];

    // Master key: HMAC-SHA512("ed25519 seed", seed)
    const uint8_t masterKey[12] = {'e', 'd', '2', '5', '5', '1', '9', ' ', 's', 'e', 'e', 'd'};
    uint8_t I[64];
    hmac_sha512(masterKey, 12, seed, 64, I);
    for (int i = 0; i < 32; i++) { key[i] = I[i]; cc[i] = I[i + 32]; }

    const uint32_t path[3] = {44u, ZNN_COIN_TYPE, account};
    for (int p = 0; p < 3; p++) {
        uint32_t idx = HARDENED + path[p];
        uint8_t data[37];
        data[0] = 0x00;
        for (int i = 0; i < 32; i++) data[1 + i] = key[i];
        data[33] = (uint8_t)(idx >> 24);
        data[34] = (uint8_t)(idx >> 16);
        data[35] = (uint8_t)(idx >> 8);
        data[36] = (uint8_t)(idx);
        hmac_sha512(cc, 32, data, 37, I);
        for (int i = 0; i < 32; i++) { key[i] = I[i]; cc[i] = I[i + 32]; }
    }

    for (int i = 0; i < 32; i++) out_key[i] = key[i];
}

// ---------------------------------------------------------------------------
// Ed25519 public key from a 32-byte seed. The field arithmetic lives in
// ed25519.cuh (ref10 radix-2^25.5, GPU-friendly 32-bit limbs).
// ---------------------------------------------------------------------------

#include "ed25519.cuh"

// ed25519_pubkey computes the 32-byte public key for a 32-byte private seed,
// exactly as crypto/ed25519.NewKeyFromSeed(seed).Public() does.
__device__ void ed25519_pubkey(const uint8_t seed[32], uint8_t pk[32]) {
    uint8_t d[64];
    sha512(seed, 32, d);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
    fe P[4];
    ge_scalarbase(P, d);
    ge_pack(pk, P);
}

// ---------------------------------------------------------------------------
// SHA3-256 (Keccak-f[1600], NIST domain separation). Input is a single block
// (a 32-byte public key), so only one absorb permutation is needed.
// ---------------------------------------------------------------------------

__constant__ uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

__constant__ int KECCAK_ROT[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                                    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
__constant__ int KECCAK_PI[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                                   15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

__device__ __forceinline__ uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

__device__ void keccakf(uint64_t st[25]) {
    for (int round = 0; round < 24; round++) {
        uint64_t bc[5];
        for (int i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (int i = 0; i < 5; i++) {
            uint64_t t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
        }
        uint64_t tmp = st[1];
        for (int i = 0; i < 24; i++) {
            int j = KECCAK_PI[i];
            uint64_t t = st[j];
            st[j] = rotl64(tmp, KECCAK_ROT[i]);
            tmp = t;
        }
        for (int j = 0; j < 25; j += 5) {
            uint64_t t0 = st[j], t1 = st[j + 1], t2 = st[j + 2], t3 = st[j + 3], t4 = st[j + 4];
            st[j]     = t0 ^ (~t1 & t2);
            st[j + 1] = t1 ^ (~t2 & t3);
            st[j + 2] = t2 ^ (~t3 & t4);
            st[j + 3] = t3 ^ (~t4 & t0);
            st[j + 4] = t4 ^ (~t0 & t1);
        }
        st[0] ^= KECCAK_RC[round];
    }
}

// sha3_256 hashes a message shorter than the 136-byte rate (a 32-byte pubkey).
__device__ void sha3_256(const uint8_t* in, int inlen, uint8_t out[32]) {
    uint64_t st[25];
    for (int i = 0; i < 25; i++) st[i] = 0;

    uint8_t block[136];
    for (int i = 0; i < inlen; i++) block[i] = in[i];
    block[inlen] = 0x06;  // SHA-3 domain separation + first pad bit
    for (int i = inlen + 1; i < 136; i++) block[i] = 0;
    block[135] |= 0x80;  // final pad bit

    for (int i = 0; i < 17; i++) {  // 136 / 8 = 17 lanes
        uint64_t lane = 0;
        for (int b = 0; b < 8; b++) lane |= (uint64_t)block[i * 8 + b] << (8 * b);
        st[i] ^= lane;
    }
    keccakf(st);

    for (int i = 0; i < 4; i++) {  // 32 output bytes = 4 lanes
        uint64_t lane = st[i];
        for (int b = 0; b < 8; b++) out[i * 8 + b] = (uint8_t)(lane >> (8 * b));
    }
}

#endif  // CRYPTO_CUH
