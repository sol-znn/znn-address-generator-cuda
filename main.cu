// znn-address-generator-cuda -- a CUDA port of znn-address-generator-go.
//
// It generates random BIP-39 mnemonics, derives their first few Zenon (NoM)
// addresses, and writes them to disk -- optionally keeping only the mnemonics
// whose addresses carry a chosen prefix and/or suffix. The bookkeeping runs on
// the CPU exactly as in the Go tool; everything per-mnemonic runs on the GPU,
// one mnemonic per CUDA thread:
//
//   key+counter --SHA-512--> 32 entropy bytes
//   entropy     --SHA-256 checksum, 11-bit split--> 24 BIP-39 words
//   mnemonic    --PBKDF2-HMAC-SHA512 (2048 rounds)--> 64-byte BIP-39 seed
//   seed        --SLIP-0010 ed25519, m/44'/73404'/{account}'--> 32-byte key
//   key         --SHA-512 + ed25519 scalar-base mult--> 32-byte public key
//   pubkey      --SHA3-256--> digest; core = 0x00 || digest[:19]
//   core        --Bech32--> "z1q...", matched against the prefix and suffix
//
// The entropy for every mnemonic comes from the host's CSPRNG: one 32-byte key
// is drawn per launch and expanded per thread, so no key is ever reused.

#include <cuda_runtime.h>

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <string>
#include <vector>

#include "bech32.cuh"
#include "bech32.h"
#include "crypto.cuh"
#include "helper.h"
#include "mnemonic.cuh"
#include "progress.h"
#include "responses.h"
#include "settings.h"
#include "sha256.h"
#include "wordlist.h"

// ZNN_VERSION is set via -D ZNN_VERSION=\"x.y.z\" when building a release;
// it defaults to the current development version otherwise.
#ifndef ZNN_VERSION
#define ZNN_VERSION "1.0.0"
#endif
const char* VERSION = ZNN_VERSION;

#define CUDA_CHECK(call)                                                                \
    do {                                                                                \
        cudaError_t err__ = (call);                                                     \
        if (err__ != cudaSuccess) {                                                     \
            fprintf(stderr, "\nCUDA error %s at %s:%d: %s\n", cudaGetErrorName(err__),  \
                    __FILE__, __LINE__, cudaGetErrorString(err__));                     \
            std::exit(1);                                                               \
        }                                                                               \
    } while (0)

const int WORD_STRIDE = MAX_WORD_LEN + 1;          // per-word bytes in the GPU word table
const int MSG_MAX = MNEMONIC_WORDS * WORD_STRIDE;  // upper bound on a mnemonic's byte length
const int HIT_CAP = 1024;                          // matches recorded per launch
const int REPORT_CAP = 16;                         // address cores stored per match

// Batch default when every mnemonic is copied back and written out. A launch
// then costs about (24*2 + addresses*20) bytes per mnemonic of transfer and
// several times that in text, so a smaller batch keeps memory in hand.
const int DUMP_BATCH = 1 << 16;

// ---------------------------------------------------------------------------
// Device
// ---------------------------------------------------------------------------

// build_message writes the space-separated mnemonic that PBKDF2 stretches.
__device__ void build_message(const uint16_t* w, int numWords, const char* words,
                              const uint8_t* wordlen, uint8_t* msg, int* pwlen) {
    int pos = 0;
    for (int i = 0; i < numWords; i++) {
        int idx = w[i];
        const char* wp = words + idx * WORD_STRIDE;
        int L = wordlen[idx];
        for (int k = 0; k < L; k++) msg[pos++] = (uint8_t)wp[k];
        if (i + 1 < numWords) msg[pos++] = ' ';
    }
    *pwlen = pos;
}

// core_from_seed computes the 20-byte address core for one account index.
__device__ void core_from_seed(const uint8_t seed[64], uint32_t account, uint8_t core[20]) {
    uint8_t key[32], pk[32], dig[32];
    slip10_account_key(seed, account, key);
    ed25519_pubkey(key, pk);
    sha3_256(pk, 32, dig);
    core[0] = 0x00;  // Address.userByte
    for (int i = 0; i < 19; i++) core[1 + i] = dig[i];
}

// Job carries one launch's inputs and outputs. outWords/outCores are set when
// every mnemonic is wanted back on the host; the hit arrays are set when a
// prefix or suffix is being searched for. Either group may be null.
struct Job {
    const uint8_t* rngKey;
    unsigned long long counterBase;
    const uint8_t* fixedEntropy;  // n * 32 bytes, or null to draw from rngKey
    int n;
    const char* words;
    const uint8_t* wordlen;
    int addresses;
    const char* prefix;
    int prefixLen;
    const char* suffix;
    int suffixLen;
    bool matchMode;
    uint16_t* outWords;
    uint8_t* outCores;
    int* hitCount;
    int* hitCand;
    int* hitAccount;
    uint16_t* hitWords;
    uint8_t* hitCores;
};

__global__ void generate_kernel(Job j) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= j.n) return;

    uint8_t entropy[ENTROPY_BYTES];
    if (j.fixedEntropy) {
        for (int i = 0; i < ENTROPY_BYTES; i++) entropy[i] = j.fixedEntropy[tid * ENTROPY_BYTES + i];
    } else {
        entropy_from_counter(j.rngKey, j.counterBase + (unsigned long long)tid, entropy);
    }

    uint16_t w[MNEMONIC_WORDS];
    mnemonic_from_entropy(entropy, w);

    uint8_t msg[MSG_MAX];
    int pwlen;
    build_message(w, MNEMONIC_WORDS, j.words, j.wordlen, msg, &pwlen);

    uint8_t seed[64];
    pbkdf2_bip39_seed(msg, pwlen, seed);

    if (j.outWords)
        for (int i = 0; i < MNEMONIC_WORDS; i++) j.outWords[tid * MNEMONIC_WORDS + i] = w[i];

    // Kept so a match can be reported without the full dump buffers.
    uint8_t keep[REPORT_CAP][20];
    int nkeep = j.addresses < REPORT_CAP ? j.addresses : REPORT_CAP;
    int hitAccount = -1;

    for (int a = 0; a < j.addresses; a++) {
        uint8_t core[20];
        core_from_seed(seed, (uint32_t)a, core);

        if (j.outCores)
            for (int i = 0; i < 20; i++)
                j.outCores[((size_t)tid * j.addresses + a) * 20 + i] = core[i];

        if (j.matchMode) {
            if (a < REPORT_CAP)
                for (int i = 0; i < 20; i++) keep[a][i] = core[i];
            if (hitAccount < 0) {
                char enc[ADDR_CHARS];
                bech32_encode_core(core, enc);
                if (bech32_affix_match(enc, j.prefix, j.prefixLen, j.suffix, j.suffixLen))
                    hitAccount = a;
            }
        }
    }

    if (hitAccount >= 0) {
        int slot = atomicAdd(j.hitCount, 1);
        if (slot < HIT_CAP) {
            j.hitCand[slot] = tid;
            j.hitAccount[slot] = hitAccount;
            for (int i = 0; i < MNEMONIC_WORDS; i++) j.hitWords[slot * MNEMONIC_WORDS + i] = w[i];
            for (int a = 0; a < nkeep; a++)
                for (int i = 0; i < 20; i++)
                    j.hitCores[((size_t)slot * REPORT_CAP + a) * 20 + i] = keep[a][i];
        }
    }
}

// encode_cores_kernel runs the device Bech32 encoder over a list of cores, so
// --selftest can hold it against the host encoder that writes the output files.
__global__ void encode_cores_kernel(const uint8_t* cores, int n, char* out) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    char enc[ADDR_CHARS];
    bech32_encode_core(cores + (size_t)tid * 20, enc);
    for (int i = 0; i < ADDR_CHARS; i++) out[(size_t)tid * ADDR_CHARS + i] = enc[i];
}

// ---------------------------------------------------------------------------
// Host helpers
// ---------------------------------------------------------------------------

static volatile std::sig_atomic_t g_interrupted = 0;
void on_sigint(int) { g_interrupted = 1; }

void die(const std::string& msg) {
    std::cout << "Error! " << msg << "\n";
    std::exit(1);
}

int64_t must_atoll(const std::string& v, const std::string& flag) {
    try {
        size_t pos = 0;
        long long n = std::stoll(v, &pos);
        if (pos != v.size()) throw std::invalid_argument("trailing");
        return n;
    } catch (...) {
        die(flag + " must be a number");
        return 0;
    }
}

// random_key draws a fresh 32-byte launch key from the operating system's
// entropy source -- the stand-in for crypto/rand in the Go tool.
void random_key(uint8_t key[32]) {
    static std::random_device rd;
    for (int i = 0; i < 32; i += 4) {
        unsigned int v = rd();
        memcpy(key + i, &v, 4);
    }
}

struct DeviceWords {
    char* words = nullptr;       // 2048 * WORD_STRIDE
    uint8_t* wordlen = nullptr;  // 2048
};

DeviceWords upload_words(const std::vector<std::string>& words) {
    std::vector<char> flat(2048 * WORD_STRIDE, 0);
    std::vector<uint8_t> lens(2048, 0);
    for (int i = 0; i < 2048; i++) {
        memcpy(&flat[i * WORD_STRIDE], words[i].data(), words[i].size());
        lens[i] = (uint8_t)words[i].size();
    }
    DeviceWords d;
    CUDA_CHECK(cudaMalloc(&d.words, flat.size()));
    CUDA_CHECK(cudaMalloc(&d.wordlen, lens.size()));
    CUDA_CHECK(cudaMemcpy(d.words, flat.data(), flat.size(), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d.wordlen, lens.data(), lens.size(), cudaMemcpyHostToDevice));
    return d;
}

char* upload_affix(const std::string& affix) {
    char* d = nullptr;
    size_t n = affix.size() + 1;
    CUDA_CHECK(cudaMalloc(&d, n));
    CUDA_CHECK(cudaMemcpy(d, affix.c_str(), n, cudaMemcpyHostToDevice));
    return d;
}

std::string mnemonic_text(const uint16_t* w, const std::vector<std::string>& words) {
    std::string out;
    for (int i = 0; i < MNEMONIC_WORDS; i++) out += (i ? " " : "") + words[w[i]];
    return out;
}

// format_block renders one mnemonic and its addresses in the layout
// generateAddresses produces in the Go tool: the mnemonic, one address per
// line, then a blank line.
std::string format_block(const uint16_t* w, const uint8_t* cores, int addresses,
                         const std::vector<std::string>& words) {
    std::string b = mnemonic_text(w, words) + "\n";
    for (int a = 0; a < addresses; a++) b += bech32::address_from_core(cores + (size_t)a * 20) + "\n";
    return b + "\n";
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

struct Flag {
    const char* name;
    bool isBool;
};

static const std::vector<std::pair<std::string, Flag>> FLAGS = {
    {"n", {"mnemonics", false}},      {"mnemonics", {"mnemonics", false}},
    {"a", {"addresses", false}},      {"addresses", {"addresses", false}},
    {"o", {"output", false}},         {"output", {"output", false}},
    {"p", {"prefix", false}},         {"prefix", {"prefix", false}},
    {"s", {"suffix", false}},         {"suffix", {"suffix", false}},
    {"t", {"threads", false}},        {"threads", {"threads", false}},  // accepted, ignored
    {"i", {"infinite", true}},        {"infinite", {"infinite", true}},
    {"all", {"all", true}},
    {"v", {"verbose", true}},         {"verbose", {"verbose", true}},
    {"wordlist", {"wordlist", false}},
    {"batch", {"batch", false}},      {"block", {"block", false}},
    {"device", {"device", false}},
    {"y", {"yes", true}},             {"yes", {"yes", true}},
    {"selftest", {"selftest", true}}, {"bench", {"bench", true}},
    {"h", {"help", true}},            {"help", {"help", true}},
    {"version", {"version", true}},
};

const Flag* lookup_flag(const std::string& name) {
    for (const auto& f : FLAGS)
        if (f.first == name) return &f.second;
    return nullptr;
}

// The only characters a Zenon address can carry directly after "z1q": the
// core's leading zero byte pins the rest of that Bech32 group.
static const std::set<char> FIRST_CHARS = {'p', 'q', 'r', 'z'};

Settings parse_args(const std::vector<std::string>& args, bool& selftest) {
    Settings s;
    selftest = false;
    if (args.empty()) {
        print_usage();
        std::exit(0);
    }

    std::map<std::string, std::string> values;
    std::set<std::string> seen;

    for (size_t i = 0; i < args.size(); i++) {
        std::string tok = args[i];
        if (tok.empty() || tok[0] != '-')
            die("Unrecognized argument: " + tok +
                "\n(Did you forget a leading '-' or '--' before a flag name?)");

        std::string name = tok.substr(tok.find_first_not_of('-'));
        std::string inlineVal;
        bool hasInline = false;
        size_t eq = name.find('=');
        if (eq != std::string::npos) {
            inlineVal = name.substr(eq + 1);
            name = name.substr(0, eq);
            hasInline = true;
        }

        const Flag* spec = lookup_flag(name);
        if (!spec) die("Unrecognized flag: " + tok);
        std::string canonical = spec->name;
        seen.insert(canonical);

        if (spec->isBool) {
            values[canonical] = hasInline ? inlineVal : "true";
            continue;
        }
        if (!hasInline) {
            if (i + 1 >= args.size()) die("Flag " + tok + " requires a value");
            inlineVal = args[++i];
        }
        values[canonical] = inlineVal;
    }

    if (seen.count("help")) {
        print_usage();
        std::exit(0);
    }
    if (seen.count("version")) {
        std::cout << "znn-address-generator-cuda v" << VERSION << "\n";
        std::exit(0);
    }
    selftest = seen.count("selftest") > 0;
    s.bench = seen.count("bench") > 0;

    if (seen.count("mnemonics")) {
        s.numberOfMnemonics = must_atoll(values["mnemonics"], "--mnemonics");
        if (s.numberOfMnemonics < 1) die("You must generate at least one mnemonic");
    }
    if (seen.count("addresses")) {
        s.addressesPerMnemonic = (int)must_atoll(values["addresses"], "--addresses");
        if (s.addressesPerMnemonic < 1) die("You must generate at least one address per mnemonic");
    }

    if (seen.count("prefix")) {
        s.prefix = to_lower(values["prefix"]);
        std::string err;
        if (!is_valid_affix(s.prefix, err)) die(err);
        if (s.prefix.empty() || !FIRST_CHARS.count(s.prefix[0]))
            die("The prefix should start with one of these letters: p, q, r, z");
    }
    if (seen.count("suffix")) {
        s.suffix = to_lower(values["suffix"]);
        std::string err;
        if (!is_valid_affix(s.suffix, err)) die(err);
    }
    if ((int)(s.prefix.size() + s.suffix.size()) > MAX_AFFIX)
        die("combined prefix and suffix length cannot exceed " + std::to_string(MAX_AFFIX));

    if (seen.count("output")) s.filename = values["output"];
    if (seen.count("wordlist")) s.wordlistFile = values["wordlist"];

    if (seen.count("batch")) {
        s.batch = (int)must_atoll(values["batch"], "--batch");
        if (s.batch < 1) die("--batch must be positive");
        s.batchIsSet = true;
    }
    if (seen.count("block")) {
        s.block = (int)must_atoll(values["block"], "--block");
        if (s.block < 1 || s.block > 1024) die("--block must be 1..1024");
    }
    if (seen.count("device")) s.device = (int)must_atoll(values["device"], "--device");

    s.verbose = seen.count("verbose") && values["verbose"] == "true";
    s.saveAll = seen.count("all") && values["all"] == "true";
    s.infinite = seen.count("infinite") && values["infinite"] == "true";
    s.assume = seen.count("yes") && values["yes"] == "true";
    return s;
}

// ensure_parent_dirs creates the directories the output files live in, as the
// Go tool's os.MkdirAll calls do.
void ensure_parent_dirs(const Settings& s) {
    for (const std::string& path : {s.filename, s.allResults}) {
        std::filesystem::path dir = std::filesystem::path(path).parent_path();
        if (dir.empty() || dir == ".") continue;
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        if (ec) die("could not create " + dir.string() + ": " + ec.message());
    }
}

// ---------------------------------------------------------------------------
// GPU buffers for one run
// ---------------------------------------------------------------------------

struct Buffers {
    DeviceWords dw;
    char* prefix = nullptr;
    char* suffix = nullptr;
    uint16_t* outWords = nullptr;
    uint8_t* outCores = nullptr;
    int* hitCount = nullptr;
    int* hitCand = nullptr;
    int* hitAccount = nullptr;
    uint16_t* hitWords = nullptr;
    uint8_t* hitCores = nullptr;
    uint8_t* rngKey = nullptr;

    void free() {
        for (void* p : {(void*)dw.words, (void*)dw.wordlen, (void*)prefix, (void*)suffix,
                        (void*)outWords, (void*)outCores, (void*)hitCount, (void*)hitCand,
                        (void*)hitAccount, (void*)hitWords, (void*)hitCores, (void*)rngKey})
            if (p) cudaFree(p);
    }
};

Buffers allocate(const Settings& s, const std::vector<std::string>& words, int batch, bool dump,
                 bool matchMode) {
    Buffers b;
    b.dw = upload_words(words);
    CUDA_CHECK(cudaMalloc(&b.rngKey, 32));

    if (dump) {
        CUDA_CHECK(cudaMalloc(&b.outWords, (size_t)batch * MNEMONIC_WORDS * sizeof(uint16_t)));
        CUDA_CHECK(cudaMalloc(&b.outCores, (size_t)batch * s.addressesPerMnemonic * 20));
    }
    if (matchMode) {
        b.prefix = upload_affix(s.prefix);
        b.suffix = upload_affix(s.suffix);
        CUDA_CHECK(cudaMalloc(&b.hitCount, sizeof(int)));
        CUDA_CHECK(cudaMalloc(&b.hitCand, HIT_CAP * sizeof(int)));
        CUDA_CHECK(cudaMalloc(&b.hitAccount, HIT_CAP * sizeof(int)));
        CUDA_CHECK(cudaMalloc(&b.hitWords, HIT_CAP * MNEMONIC_WORDS * sizeof(uint16_t)));
        CUDA_CHECK(cudaMalloc(&b.hitCores, HIT_CAP * REPORT_CAP * 20));
    }
    return b;
}

Job make_job(const Settings& s, const Buffers& b, int n, unsigned long long counterBase,
             bool matchMode) {
    Job j{};
    j.rngKey = b.rngKey;
    j.counterBase = counterBase;
    j.fixedEntropy = nullptr;
    j.n = n;
    j.words = b.dw.words;
    j.wordlen = b.dw.wordlen;
    j.addresses = s.addressesPerMnemonic;
    j.prefix = b.prefix;
    j.prefixLen = (int)s.prefix.size();
    j.suffix = b.suffix;
    j.suffixLen = (int)s.suffix.size();
    j.matchMode = matchMode;
    j.outWords = b.outWords;
    j.outCores = b.outCores;
    j.hitCount = b.hitCount;
    j.hitCand = b.hitCand;
    j.hitAccount = b.hitAccount;
    j.hitWords = b.hitWords;
    j.hitCores = b.hitCores;
    return j;
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

void run(Settings& s, const std::vector<std::string>& words) {
    std::signal(SIGINT, on_sigint);

    const bool matchMode = s.findMatch();
    // Every mnemonic has to come back to the host when it will be written out
    // or displayed; a plain search only needs the matches.
    const bool dump = !matchMode || s.saveAll || s.verbose;

    int batch = s.batch;
    if (!matchMode && !s.infinite && s.numberOfMnemonics < batch) batch = (int)s.numberOfMnemonics;

    Buffers b = allocate(s, words, batch, dump, matchMode);

    std::vector<uint16_t> h_words(dump ? (size_t)batch * MNEMONIC_WORDS : 0);
    std::vector<uint8_t> h_cores(dump ? (size_t)batch * s.addressesPerMnemonic * 20 : 0);

    std::unique_ptr<Progress> bar;
    if (!s.verbose) {
        if (matchMode)
            bar.reset(new Progress("Finding matches", estimate_total(s), true));
        else
            bar.reset(new Progress("Generating", s.numberOfMnemonics, !s.infinite));
        bar->draw();
    }

    int64_t produced = 0, matches = 0;
    unsigned long long counter = 0;
    bool done = false;

    while (!g_interrupted && !done) {
        int n = batch;
        if (!matchMode && !s.infinite) {
            int64_t remaining = s.numberOfMnemonics - produced;
            if (remaining <= 0) break;
            if (remaining < n) n = (int)remaining;
        }

        uint8_t key[32];
        random_key(key);
        CUDA_CHECK(cudaMemcpy(b.rngKey, key, 32, cudaMemcpyHostToDevice));
        if (matchMode) CUDA_CHECK(cudaMemset(b.hitCount, 0, sizeof(int)));

        Job j = make_job(s, b, n, counter, matchMode);
        int blocks = (n + s.block - 1) / s.block;
        generate_kernel<<<blocks, s.block>>>(j);
        CUDA_CHECK(cudaGetLastError());
        CUDA_CHECK(cudaDeviceSynchronize());

        counter += (unsigned long long)n;
        produced += n;

        // Matches first, so they reach disk before the bulk write.
        if (matchMode) {
            int found = 0;
            CUDA_CHECK(cudaMemcpy(&found, b.hitCount, sizeof(int), cudaMemcpyDeviceToHost));
            int nrec = std::min(found, HIT_CAP);
            if (nrec > 0) {
                std::vector<int> hc(nrec), ha(nrec);
                std::vector<uint16_t> hw((size_t)nrec * MNEMONIC_WORDS);
                std::vector<uint8_t> hcores((size_t)nrec * REPORT_CAP * 20);
                CUDA_CHECK(cudaMemcpy(hc.data(), b.hitCand, nrec * sizeof(int), cudaMemcpyDeviceToHost));
                CUDA_CHECK(cudaMemcpy(ha.data(), b.hitAccount, nrec * sizeof(int), cudaMemcpyDeviceToHost));
                CUDA_CHECK(cudaMemcpy(hw.data(), b.hitWords, hw.size() * sizeof(uint16_t),
                                      cudaMemcpyDeviceToHost));
                CUDA_CHECK(cudaMemcpy(hcores.data(), b.hitCores, hcores.size(), cudaMemcpyDeviceToHost));

                // Report in the order the mnemonics were generated.
                std::vector<int> order(nrec);
                for (int i = 0; i < nrec; i++) order[i] = i;
                std::sort(order.begin(), order.end(), [&](int x, int y) { return hc[x] < hc[y]; });

                if (bar) bar->finish();
                int nrep = std::min(s.addressesPerMnemonic, REPORT_CAP);
                for (int i : order) {
                    std::string block = format_block(&hw[(size_t)i * MNEMONIC_WORDS],
                                                     &hcores[(size_t)i * REPORT_CAP * 20], nrep, words);
                    std::cout << "\nFound a match!\n" << block;
                    if (!save_to_file(s, block, true))
                        fprintf(stderr, "Error writing to %s\n", s.filename.c_str());
                    matches++;
                }
                if (found > HIT_CAP)
                    printf("(%d more matches in this batch were not recorded; shorten --batch or "
                           "lengthen the prefix/suffix)\n",
                           found - HIT_CAP);
                std::cout << "Saved to " << s.filename << "\n";
                if (!s.infinite) done = true;
            }
        }

        if (dump) {
            CUDA_CHECK(cudaMemcpy(h_words.data(), b.outWords,
                                  (size_t)n * MNEMONIC_WORDS * sizeof(uint16_t),
                                  cudaMemcpyDeviceToHost));
            CUDA_CHECK(cudaMemcpy(h_cores.data(), b.outCores,
                                  (size_t)n * s.addressesPerMnemonic * 20, cudaMemcpyDeviceToHost));

            std::string cache;
            cache.reserve((size_t)n * (MNEMONIC_WORDS * 7 + s.addressesPerMnemonic * 41 + 1));
            for (int i = 0; i < n; i++) {
                std::string block = format_block(&h_words[(size_t)i * MNEMONIC_WORDS],
                                                 &h_cores[(size_t)i * s.addressesPerMnemonic * 20],
                                                 s.addressesPerMnemonic, words);
                if (s.verbose) std::cout << block;
                cache += block;
            }
            if (!save_to_file(s, cache, false)) fprintf(stderr, "Error writing to file\n");
        }

        if (bar && !done) bar->add(n);
    }

    if (bar && !done) bar->finish();

    if (g_interrupted)
        std::cout << "\nStopped after " << produced << " mnemonics.\n";
    else if (matchMode && matches == 0)
        std::cout << "\nNo match found.\n";
    else if (!matchMode)
        std::cout << "Generated " << produced << " mnemonics into " << s.filename << "\n";

    b.free();
}

// ---------------------------------------------------------------------------
// Self-test: rebuild a known mnemonic from its entropy on the GPU and check
// both the words and the addresses znn_sdk_dart derives from them.
// ---------------------------------------------------------------------------

// entropy_of_mnemonic reverses the 11-bit packing, recovering the entropy a
// mnemonic was built from and verifying its BIP-39 checksum.
bool entropy_of_mnemonic(const std::vector<std::string>& mw, const std::map<std::string, int>& index,
                         uint8_t entropy[ENTROPY_BYTES]) {
    if ((int)mw.size() != MNEMONIC_WORDS) return false;
    uint8_t bits[ENTROPY_BYTES + 1] = {0};
    for (int i = 0; i < MNEMONIC_WORDS; i++) {
        auto it = index.find(mw[i]);
        if (it == index.end()) return false;
        int wi = it->second;
        for (int b = 0; b < 11; b++) {
            if ((wi >> (10 - b)) & 1) {
                int bit = i * 11 + b;
                bits[bit >> 3] |= (uint8_t)(0x80 >> (bit & 7));
            }
        }
    }
    memcpy(entropy, bits, ENTROPY_BYTES);

    uint8_t digest[32];
    host_sha256::sha256(entropy, ENTROPY_BYTES, digest);
    return digest[0] == bits[ENTROPY_BYTES];
}

// check_device_encoder encodes the given cores on the GPU and compares the
// result with the host encoder. Returns true when every address agrees.
bool check_device_encoder(const std::vector<uint8_t>& cores, int n) {
    uint8_t* d_cores;
    char* d_enc;
    CUDA_CHECK(cudaMalloc(&d_cores, (size_t)n * 20));
    CUDA_CHECK(cudaMalloc(&d_enc, (size_t)n * ADDR_CHARS));
    CUDA_CHECK(cudaMemcpy(d_cores, cores.data(), (size_t)n * 20, cudaMemcpyHostToDevice));

    encode_cores_kernel<<<1, 32>>>(d_cores, n, d_enc);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    std::vector<char> enc((size_t)n * ADDR_CHARS);
    CUDA_CHECK(cudaMemcpy(enc.data(), d_enc, enc.size(), cudaMemcpyDeviceToHost));
    cudaFree(d_cores);
    cudaFree(d_enc);

    bool ok = true;
    for (int i = 0; i < n; i++) {
        std::string gpu = "z1" + std::string(&enc[(size_t)i * ADDR_CHARS], ADDR_CHARS);
        std::string host = bech32::address_from_core(&cores[(size_t)i * 20]);
        if (gpu != host) {
            std::cout << "  [" << i << "] GPU encoder gave " << gpu << ", host gave " << host << "\n";
            ok = false;
        }
    }
    return ok;
}

int run_selftest(const std::vector<std::string>& words) {
    // The 24-word vector znn-bruteforce-cuda validates against, with the
    // addresses znn_sdk_dart derives from it.
    const char* mnemonic =
        "neither fiction member destroy become hour artefact aspect brisk hello subway worry "
        "sell side space secret desk draw sting shoe scheme vital hedgehog track";
    const std::vector<std::string> want = {
        "z1qq9t4c0hk80xwwunvwncnh7nz5yjw4l0mder7f", "z1qqh55r4f85z9e3rxalhmsc7aczaqv4e6y265r5",
        "z1qrr9lpsg2knz45qgu6gngt9jhrfy3echylss8v", "z1qp4cc9u4dsfxgjehdnlu22hn0pkshu505juz64",
        "z1qzsgh49gmlpu5c7ajlrg77sacdv3uts2kkly6z"};

    auto index = word_index(words);
    std::vector<std::string> mw = split_fields(mnemonic);
    uint8_t entropy[ENTROPY_BYTES];
    if (!entropy_of_mnemonic(mw, index, entropy)) {
        std::cout << "Self-test FAILED: the test vector is not a valid BIP-39 mnemonic for this "
                     "word list.\n";
        return 1;
    }

    const int addresses = (int)want.size();
    DeviceWords dw = upload_words(words);

    uint8_t* d_entropy;
    uint16_t* d_words;
    uint8_t* d_cores;
    CUDA_CHECK(cudaMalloc(&d_entropy, ENTROPY_BYTES));
    CUDA_CHECK(cudaMalloc(&d_words, MNEMONIC_WORDS * sizeof(uint16_t)));
    CUDA_CHECK(cudaMalloc(&d_cores, addresses * 20));
    CUDA_CHECK(cudaMemcpy(d_entropy, entropy, ENTROPY_BYTES, cudaMemcpyHostToDevice));

    Job j{};
    j.fixedEntropy = d_entropy;
    j.n = 1;
    j.words = dw.words;
    j.wordlen = dw.wordlen;
    j.addresses = addresses;
    j.matchMode = false;
    j.outWords = d_words;
    j.outCores = d_cores;

    generate_kernel<<<1, 32>>>(j);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    std::vector<uint16_t> gotWords(MNEMONIC_WORDS);
    std::vector<uint8_t> cores(addresses * 20);
    CUDA_CHECK(cudaMemcpy(gotWords.data(), d_words, gotWords.size() * sizeof(uint16_t),
                          cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(cores.data(), d_cores, cores.size(), cudaMemcpyDeviceToHost));

    bool allOk = true;
    std::string got = mnemonic_text(gotWords.data(), words);
    bool wordsOk = got == mnemonic;
    allOk = allOk && wordsOk;
    std::cout << "Mnemonic rebuilt from its entropy:\n  " << got << "\n  "
              << (wordsOk ? "OK" : "MISMATCH, want:\n  " + std::string(mnemonic)) << "\n";

    std::cout << "Addresses:\n";
    for (int a = 0; a < addresses; a++) {
        std::string addr = bech32::address_from_core(&cores[(size_t)a * 20]);
        bool ok = addr == want[a];
        allOk = allOk && ok;
        std::cout << "  [" << a << "] " << addr << "  " << (ok ? "OK" : "MISMATCH, want " + want[a])
                  << "\n";
    }

    // The GPU has its own Bech32 encoder, and it is the one that decides a
    // match, so check it against the host encoder that wrote the lines above.
    bool encOk = check_device_encoder(cores, addresses);
    allOk = allOk && encOk;
    std::cout << "Device Bech32 encoder: " << (encOk ? "OK" : "MISMATCH") << "\n";

    std::cout << (allOk ? "\nSelf-test passed: GPU generation matches the known vector.\n"
                        : "\nSelf-test FAILED.\n");

    cudaFree(d_entropy);
    cudaFree(d_words);
    cudaFree(d_cores);
    cudaFree(dw.words);
    cudaFree(dw.wordlen);
    return allOk ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Benchmark: time the generation kernel alone, with CUDA events.
// ---------------------------------------------------------------------------

int run_bench(Settings& s, const std::vector<std::string>& words) {
    // A prefix no address will carry, so every mnemonic runs the full pipeline
    // and nothing is written out.
    s.prefix = "zzzzzz";
    s.suffix.clear();

    int batch = s.batchIsSet ? s.batch : (1 << 18);
    Buffers b = allocate(s, words, batch, false, true);

    uint8_t key[32];
    random_key(key);
    CUDA_CHECK(cudaMemcpy(b.rngKey, key, 32, cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemset(b.hitCount, 0, sizeof(int)));

    Job j = make_job(s, b, batch, 0, true);
    int blocks = (batch + s.block - 1) / s.block;
    auto launch = [&]() { generate_kernel<<<blocks, s.block>>>(j); };

    launch();  // warm-up
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    cudaEvent_t t0, t1;
    cudaEventCreate(&t0);
    cudaEventCreate(&t1);
    const int iters = 5;
    cudaEventRecord(t0);
    for (int i = 0; i < iters; i++) launch();
    cudaEventRecord(t1);
    CUDA_CHECK(cudaEventSynchronize(t1));
    float ms = 0;
    cudaEventElapsedTime(&ms, t0, t1);

    double perLaunch = ms / iters;
    double rate = (double)batch / (perLaunch / 1000.0);

    cudaDeviceProp prop;
    CUDA_CHECK(cudaGetDeviceProperties(&prop, s.device));
    std::cout << "Benchmark (" << prop.name << ", " << s.addressesPerMnemonic
              << " addresses per mnemonic)\n";
    std::cout << "  batch:        " << batch << " mnemonics\n";
    printf("  kernel time:  %.2f ms/batch (avg of %d)\n", perLaunch, iters);
    printf("  throughput:   %.0f mnemonics/s (%.0f addresses/s)\n", rate,
           rate * s.addressesPerMnemonic);

    b.free();
    return 0;
}

// ---------------------------------------------------------------------------

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    bool selftest = false;
    Settings s = parse_args(args, selftest);

    std::vector<std::string> words;
    try {
        words = load_wordlist(s.wordlistFile);
    } catch (const std::exception& e) {
        die(e.what());
    }

    CUDA_CHECK(cudaSetDevice(s.device));

    if (selftest) return run_selftest(words);
    if (s.bench) return run_bench(s, words);

    // Writing every mnemonic out costs far more per launch than searching does,
    // so use a smaller default batch unless the user chose one.
    if (!s.batchIsSet && (!s.findMatch() || s.saveAll || s.verbose)) s.batch = DUMP_BATCH;

    ensure_parent_dirs(s);

    cudaDeviceProp prop;
    CUDA_CHECK(cudaGetDeviceProperties(&prop, s.device));
    std::string gpu = std::string(prop.name) + " (device " + std::to_string(s.device) + ", " +
                      std::to_string(prop.multiProcessorCount) + " SMs)";

    display_settings(s, gpu, estimate_total(s));
    confirm_settings(s);
    run(s, words);
    return 0;
}
