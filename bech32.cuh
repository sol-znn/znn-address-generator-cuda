// bech32.cuh -- device-side Bech32 encoding and prefix/suffix matching.
//
// Matching happens on the GPU, on the encoded address rather than on the raw
// core, because a suffix falls inside the Bech32 checksum: the last six
// characters of "z1q..." are a function of every byte of the core, so there is
// no way to test a suffix without encoding first. The encoding is the same
// BIP-173 variant (checksum XOR constant 1) the host side in bech32.h uses.
//
// A Zenon address is exactly 40 characters: "z", "1", and 38 encoded ones --
// 32 data characters for the 20-byte core (160 bits / 5, with nothing left
// over) and 6 of checksum. The core's first byte is Address.userByte (0x00),
// so the first encoded character is always 'q'; that is the "q" in "z1q".
#ifndef BECH32_CUH
#define BECH32_CUH

#include <cstdint>

const int ADDR_CHARS = 38;      // encoded characters after the "z1" prefix
const int ADDR_DATA_CHARS = 32; // of which these carry the core
const int MAX_AFFIX = 37;       // "z1q" + 37 characters = a 40-character address

__constant__ char BECH32_CHARSET[33] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
__constant__ uint32_t BECH32_GEN[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};

__device__ __forceinline__ uint32_t bech32_polymod_step(uint32_t chk, uint8_t v) {
    uint32_t top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ (uint32_t)v;
    for (int i = 0; i < 5; i++)
        if ((top >> i) & 1) chk ^= BECH32_GEN[i];
    return chk;
}

// bech32_encode_core writes the 38 characters that follow "z1" for a 20-byte
// Zenon address core.
__device__ void bech32_encode_core(const uint8_t core[20], char out[ADDR_CHARS]) {
    uint8_t padded[21];
    for (int i = 0; i < 20; i++) padded[i] = core[i];
    padded[20] = 0;

    uint8_t data[ADDR_DATA_CHARS];
    for (int i = 0; i < ADDR_DATA_CHARS; i++) {
        int bit = i * 5;
        int byte = bit >> 3;
        int off = bit & 7;
        uint32_t v = ((uint32_t)padded[byte] << 8) | (uint32_t)padded[byte + 1];
        data[i] = (uint8_t)((v >> (11 - off)) & 31);
        out[i] = BECH32_CHARSET[data[i]];
    }

    // Checksum over hrp_expand("z") = {3, 0, 26}, the data, and six zeros.
    uint32_t chk = 1;
    chk = bech32_polymod_step(chk, 3);
    chk = bech32_polymod_step(chk, 0);
    chk = bech32_polymod_step(chk, 26);
    for (int i = 0; i < ADDR_DATA_CHARS; i++) chk = bech32_polymod_step(chk, data[i]);
    for (int i = 0; i < 6; i++) chk = bech32_polymod_step(chk, 0);
    chk ^= 1;

    for (int i = 0; i < 6; i++)
        out[ADDR_DATA_CHARS + i] = BECH32_CHARSET[(chk >> (5 * (5 - i))) & 31];
}

// bech32_affix_match reports whether the encoded address satisfies the Go
// tool's ^z1q{prefix}.*{suffix}$ test. `enc` holds the 38 characters after
// "z1", so enc[0] is the "q" and the prefix starts at enc[1].
__device__ __forceinline__ bool bech32_affix_match(const char enc[ADDR_CHARS],
                                                   const char* prefix, int prefixLen,
                                                   const char* suffix, int suffixLen) {
    if (enc[0] != 'q') return false;
    for (int i = 0; i < prefixLen; i++)
        if (enc[1 + i] != prefix[i]) return false;
    for (int i = 0; i < suffixLen; i++)
        if (enc[ADDR_CHARS - suffixLen + i] != suffix[i]) return false;
    return true;
}

#endif  // BECH32_CUH
