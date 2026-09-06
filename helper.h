// helper.h -- validation, output routing and the search-space estimate,
// ported from helper.go.
#ifndef HELPER_H
#define HELPER_H

#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>

#include "bech32.h"
#include "settings.h"

// is_valid_affix reports whether a prefix or suffix is spellable in Bech32.
// The message it fills in on failure matches the Go tool's.
inline bool is_valid_affix(const std::string& input, std::string& err) {
    for (char c : input) {
        if (!strchr(bech32::CHARSET, c)) {
            err = input + " is invalid\nValid characters are [a-z0-9], excluding 1, b, i, o.";
            return false;
        }
    }
    return true;
}

inline bool append_to_file(const std::string& path, const std::string& data) {
    if (data.empty()) return true;
    std::ofstream f(path, std::ios::app);
    if (!f) return false;
    f << data;
    return (bool)f;
}

// save_to_file routes a block of results to the right file, as saveToFile
// does in the Go tool: matches always go to the output file, everything else
// only when there is no search on, or when --all asked for it.
inline bool save_to_file(const Settings& s, const std::string& data, bool match) {
    if (match) return append_to_file(s.filename, data);
    if (!s.findMatch()) return append_to_file(s.filename, data);
    if (s.saveAll) return append_to_file(s.allResults, data);
    return true;
}

// estimate_total estimates how many mnemonics a search will need, for the
// progress bar: one in 32^(prefix+suffix) addresses matches, and each
// mnemonic yields addressesPerMnemonic of them.
inline int64_t estimate_total(const Settings& s) {
    int exp = (int)(s.prefix.size() + s.suffix.size());
    double total = std::pow(32.0, (double)exp) / (double)s.addressesPerMnemonic;
    if (total > (double)INT64_MAX) return INT64_MAX;
    return (int64_t)total;
}

#endif  // HELPER_H
