// bech32.h -- host-side Bech32 (BIP-173), matching the `bech32` Dart package
// used by znn_sdk_dart (checksum XOR constant 1, not bech32m). Used to turn
// target addresses into 20-byte cores for GPU comparison, and to render the
// core of a match back into a "z1q..." address.
#ifndef BECH32_H
#define BECH32_H

#include <cstdint>
#include <string>
#include <vector>

namespace bech32 {

static const char* CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

inline uint32_t polymod(const std::vector<uint8_t>& values) {
    static const uint32_t GEN[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    uint32_t chk = 1;
    for (uint8_t v : values) {
        uint32_t top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ (uint32_t)v;
        for (int i = 0; i < 5; i++)
            if ((top >> i) & 1) chk ^= GEN[i];
    }
    return chk;
}

inline std::vector<uint8_t> hrp_expand(const std::string& hrp) {
    std::vector<uint8_t> r;
    for (char c : hrp) r.push_back((uint8_t)c >> 5);
    r.push_back(0);
    for (char c : hrp) r.push_back((uint8_t)c & 31);
    return r;
}

// convert_bits regroups `from`-bit values into `to`-bit values.
inline bool convert_bits(const std::vector<uint8_t>& data, int from, int to, bool pad,
                         std::vector<uint8_t>& out) {
    uint32_t acc = 0;
    int bits = 0;
    uint32_t maxv = (1u << to) - 1;
    for (uint8_t value : data) {
        acc = (acc << from) | value;
        bits += from;
        while (bits >= to) {
            bits -= to;
            out.push_back((acc >> bits) & maxv);
        }
    }
    if (pad) {
        if (bits > 0) out.push_back((acc << (to - bits)) & maxv);
    } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
        return false;  // leftover bits -- invalid encoding
    }
    return true;
}

inline std::vector<uint8_t> create_checksum(const std::string& hrp, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> values = hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    for (int i = 0; i < 6; i++) values.push_back(0);
    uint32_t mod = polymod(values) ^ 1;
    std::vector<uint8_t> checksum(6);
    for (int i = 0; i < 6; i++) checksum[i] = (mod >> (5 * (5 - i))) & 31;
    return checksum;
}

// encode builds an address string from hrp + 8-bit core bytes.
inline std::string encode(const std::string& hrp, const std::vector<uint8_t>& core) {
    std::vector<uint8_t> data;
    convert_bits(core, 8, 5, true, data);
    std::vector<uint8_t> checksum = create_checksum(hrp, data);

    std::string out = hrp + "1";
    for (uint8_t b : data) out += CHARSET[b];
    for (uint8_t b : checksum) out += CHARSET[b];
    return out;
}

// address_from_core renders a 20-byte Zenon address core as "z1q...".
inline std::string address_from_core(const uint8_t core[20]) {
    return encode("z", std::vector<uint8_t>(core, core + 20));
}

// decode_core recovers the 20-byte core of a "z1q..." address. Returns false
// if the address is not a well-formed Zenon Bech32 address.
inline bool decode_core(const std::string& addr, uint8_t core[20]) {
    if (addr.size() != 40 || addr[0] != 'z' || addr[1] != '1') return false;

    std::vector<uint8_t> values;
    for (size_t i = 2; i < addr.size(); i++) {
        const char* p = nullptr;
        for (int j = 0; j < 32; j++)
            if (CHARSET[j] == addr[i]) { p = CHARSET + j; break; }
        if (!p) return false;
        values.push_back((uint8_t)(p - CHARSET));
    }

    // Verify checksum over hrp + all values.
    std::vector<uint8_t> chk = hrp_expand("z");
    chk.insert(chk.end(), values.begin(), values.end());
    if (polymod(chk) != 1) return false;

    std::vector<uint8_t> data(values.begin(), values.end() - 6);  // drop 6-char checksum
    std::vector<uint8_t> out;
    if (!convert_bits(data, 5, 8, false, out)) return false;
    if (out.size() != 20) return false;
    for (int i = 0; i < 20; i++) core[i] = out[i];
    return true;
}

}  // namespace bech32

#endif  // BECH32_H
