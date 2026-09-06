// settings.h -- runtime configuration, mirroring settings.go from
// znn-address-generator-go, plus the GPU tuning knobs this port adds.
#ifndef SETTINGS_H
#define SETTINGS_H

#include <ctime>
#include <string>

struct Settings {
    int64_t numberOfMnemonics = 100;  // -n, ignored while searching for a match
    int addressesPerMnemonic = 5;     // -a

    std::string filename;    // matches, or every mnemonic when not searching
    std::string allResults;  // every mnemonic, when --all is given with a search
    std::string wordlistFile;

    std::string prefix;  // -p, the characters that must follow "z1q"
    std::string suffix;  // -s, the characters the address must end with

    bool verbose = false;
    bool saveAll = false;
    bool infinite = false;
    bool assume = false;  // -y, skip the confirmation prompt
    bool bench = false;

    // GPU tuning.
    int batch = 1 << 20;  // mnemonics dispatched per kernel launch
    int block = 256;      // CUDA threads per block
    int device = 0;       // CUDA device ordinal
    bool batchIsSet = false;

    Settings() {
        char buf[64];
        std::time_t t = std::time(nullptr);
        std::strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", std::localtime(&t));
        filename = std::string("./results/results-") + buf + ".txt";
        allResults = std::string("./results/allresults-") + buf + ".txt";
    }

    bool findMatch() const { return !prefix.empty() || !suffix.empty(); }
};

#endif  // SETTINGS_H
