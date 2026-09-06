// responses.h -- the console output around the run, ported from responses.go.
#ifndef RESPONSES_H
#define RESPONSES_H

#include <iostream>
#include <string>

#include "settings.h"
#include "wordlist.h"

inline void print_usage() {
    std::cout <<
        "Zenon Address Generator (CUDA)\n"
        "Usage: znn-address-generator-cuda [OPTIONS]\n\n"
        "Generates random BIP-39 mnemonics and derives their Zenon addresses on\n"
        "the GPU, saving them to disk. With a prefix and/or suffix it keeps only\n"
        "the mnemonics whose addresses match.\n\n"
        "Options\n"
        "  -n, --mnemonics       number of mnemonics to generate (default 100)\n"
        "  -a, --addresses       number of addresses per mnemonic (default 5)\n"
        "  -o, --output          output file name (default ./results/results-<time>.txt)\n"
        "  -p, --prefix          save addresses that match a specific prefix\n"
        "  -s, --suffix          save addresses that match a specific suffix\n"
        "  -i, --infinite        generate infinite mnemonics\n"
        "      --all             save all generated mnemonics, even if they don't match\n"
        "  -v, --verbose         display mnemonics as they're being generated\n"
        "  -t, --threads         accepted and ignored (a CPU concept)\n"
        "      --wordlist        BIP-39 word list file (default: built-in English list)\n"
        "      --batch           mnemonics per GPU launch (default 1048576, or 65536\n"
        "                        when every mnemonic is written out)\n"
        "      --block           CUDA threads per block (default 256)\n"
        "      --device          CUDA device ordinal (default 0)\n"
        "  -y, --yes             skip the confirmation prompt\n"
        "      --selftest        derive a known vector and exit (validates the GPU)\n"
        "      --bench           time the derivation kernel and exit\n"
        "  -h, --help            Displays help information\n"
        "      --version         Displays version information\n\n"
        "Example\n"
        "  znn-address-generator-cuda -p zzz -s 329\n\n";
}

inline void confirm_settings(const Settings& s) {
    if (s.assume) return;
    std::cout << "Do you want to proceed? (Y/n): ";
    std::string line;
    std::getline(std::cin, line);
    line = to_lower(trim(line));
    if (!line.empty() && line != "y" && line != "yes") std::exit(0);
}

inline void display_settings(const Settings& s, const std::string& gpu, int64_t estimate) {
    bool findMatch = s.findMatch();

    std::cout << "---------------------------------------------------\n";
    if (!findMatch && !s.infinite)
        std::cout << "Number of Mnemonics: " << s.numberOfMnemonics << "\n";
    else if (s.infinite)
        std::cout << "Number of Mnemonics: infinite\n";
    else
        std::cout << "Number of Mnemonics: until a match is found\n";
    std::cout << "Addresses per mnemonic: " << s.addressesPerMnemonic << "\n";
    std::cout << "Output file: " << s.filename << "\n";
    std::cout << "GPU: " << gpu << "\n";
    std::cout << "Batch size: " << s.batch << " mnemonics/launch\n";
    std::cout << "Verbose output: " << (s.verbose ? "true" : "false") << "\n";
    if (findMatch) {
        if (!s.prefix.empty()) std::cout << "Matching prefix: " << s.prefix << "\n";
        if (!s.suffix.empty()) std::cout << "Matching suffix: " << s.suffix << "\n";
        std::cout << "Mnemonics to try, on average: " << estimate << "\n";
        std::cout << "Save all mnemonics to separate file: " << (s.saveAll ? "true" : "false") << "\n";
        if (s.saveAll) std::cout << "All-results file: " << s.allResults << "\n";
    }
    std::cout << "---------------------------------------------------\n";
}

#endif  // RESPONSES_H
