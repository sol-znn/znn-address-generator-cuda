# znn-address-generator-cuda

Generate Zenon (NoM) mnemonics and addresses on the GPU, then save them to
disk. Optionally search for an address with a specific prefix and/or suffix.

A CUDA port of [znn-address-generator-go](../znn-address-generator-go), which
is itself a Go port of
[znn-address-generator](https://github.com/Sol-Sanctum/znn-address-generator).
It uses the same 256-bit BIP-39 mnemonics and the same `m/44'/73404'/{account}'`
derivation path as `znn_sdk_dart`, so a mnemonic it produces opens the same
wallet in Syrius or `znn_cli_dart`.

The CPU still does the cheap part -- drawing the randomness, writing the
files, reporting matches. Every expensive step runs on the GPU, one mnemonic
per CUDA thread:

```
key+counter --SHA-512--> 32 entropy bytes
entropy     --SHA-256 checksum, 11-bit split--> 24 BIP-39 words
mnemonic    --PBKDF2-HMAC-SHA512 (2048 rounds)--> 64-byte BIP-39 seed
seed        --SLIP-0010 ed25519, m/44'/73404'/{account}'--> 32-byte key
key         --SHA-512 + ed25519 scalar-base mult--> 32-byte public key
pubkey      --SHA3-256--> digest; core = 0x00 || digest[:19]
core        --Bech32--> "z1q...", matched against the prefix and suffix
```

Matching happens on the GPU, on the encoded address rather than on the raw
bytes: a suffix falls inside the Bech32 checksum, so there is no way to test
one without encoding first.

## Where the randomness comes from

Every mnemonic must be unpredictable, so none of it is invented on the device.
Before each launch the host draws a fresh 32-byte key from the operating
system's CSPRNG (`std::random_device`, the stand-in for Go's `crypto/rand`),
and each thread expands it into its own entropy with
`SHA-512(key || thread counter)`. That is a counter-mode PRF over a secret
key: distinct per thread, unpredictable without the key, and with no
device-side RNG state to seed, checkpoint, or accidentally repeat between
launches.

## Requirements

- An NVIDIA GPU and driver.
- The [CUDA Toolkit](https://developer.nvidia.com/cuda-downloads) (`nvcc`).
- A host C++ compiler `nvcc` can drive: MSVC (Build Tools) on Windows, or GCC
  on Linux.

Developed and tested against CUDA 13.3 on an RTX 3060 (compute capability 8.6).

## Build

### Windows (MSVC + nvcc)

`build.ps1` finds your Visual Studio / Build Tools install, imports its x64
developer environment, and compiles:

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

Pass `-Arch` for a different GPU (the default is `sm_86`, the RTX 3060):

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1 -Arch sm_89
```

### Any platform (CMake)

```bash
cmake -B build -DCMAKE_CUDA_ARCHITECTURES=86
cmake --build build --config Release
```

### By hand

```bash
nvcc -O3 -std=c++17 -arch=sm_86 -o znn-address-generator-cuda main.cu
```

Match `-arch` to your card's compute capability (`70` Volta, `75` Turing,
`80/86` Ampere, `89` Ada, `90` Hopper).

Any of the three methods can embed a version string (what `--version` prints):
`build.ps1 -Version 1.2.3`, `cmake -B build -DZNN_VERSION=1.2.3`, or by hand
`-DZNN_VERSION=\"1.2.3\"`. It defaults to a development version otherwise.

## Releases

Download compiled binaries for Windows/Linux from the
[latest release](https://github.com/sol-znn/znn-address-generator-cuda/releases/latest).
Each release binary is built as a fat binary covering Turing through Blackwell
GPUs (`sm_75`-`sm_120`, plus a PTX image for forward compatibility with newer
architectures via JIT) -- see `.github/workflows/release.yml`.

GitHub-hosted runners have no NVIDIA GPU, so CI only verifies that the release
binaries compile; it cannot run `--selftest` or `--bench`. Run `--selftest` on
your own GPU after downloading a release to confirm it's correct on your
hardware.

## Verify the GPU derivation

```bash
znn-address-generator-cuda --selftest
```

This rebuilds a known 24-word mnemonic from its entropy on the GPU, derives
its first five addresses there, and checks all of it against the values
`znn_sdk_dart` produced -- so the mnemonic construction, the derivation, and
the device Bech32 encoder are all covered. It should print `OK` throughout and
`Self-test passed`.

## Options

```text
  -n, --mnemonics       number of mnemonics to generate (default 100)
  -a, --addresses       number of addresses per mnemonic (default 5)
  -o, --output          output file name (default ./results/results-<time>.txt)
  -p, --prefix          save addresses that match a specific prefix
  -s, --suffix          save addresses that match a specific suffix
  -i, --infinite        generate infinite mnemonics
      --all             save all generated mnemonics, even if they don't match
  -v, --verbose         display mnemonics as they're being generated
  -t, --threads         accepted and ignored (a CPU concept)
      --wordlist        BIP-39 word list file (default: built-in English list)
      --batch           mnemonics per GPU launch (default 1048576, or 65536
                        when every mnemonic is written out)
      --block           CUDA threads per block (default 256)
      --device          CUDA device ordinal (default 0)
  -y, --yes             skip the confirmation prompt
      --selftest        derive a known vector and exit (validates the GPU)
      --bench           time the derivation kernel and exit
  -h, --help            Displays help information
      --version         Displays version information
```

The command line matches znn-address-generator-go, so an existing command
works as-is (the CPU-only `-t/--threads` flag is accepted and ignored). What
is new is GPU tuning -- `--batch`, `--block`, `--device` -- plus `-y`,
`--selftest` and `--bench`.

## Usage

You can mix and match whatever settings you want.

### Generate 1000 mnemonics

```bash
znn-address-generator-cuda -n 1000
```

### Find an address with suffix 329

```bash
znn-address-generator-cuda -s 329
```

### Find an address with prefix zzz and suffix 329

```bash
znn-address-generator-cuda -p zzz -s 329
```

### Find an address with suffix 329 and save all generated mnemonics to a separate file

```bash
znn-address-generator-cuda -s 329 --all
```

### Keep searching for addresses with suffix 329 until stopped

```bash
znn-address-generator-cuda -s 329 --infinite
# Ctrl-C to end execution
```

A prefix or suffix may only use Bech32 characters -- `[a-z0-9]` excluding
`1`, `b`, `i` and `o` -- and a prefix must begin with `p`, `q`, `r` or `z`,
because the address core's leading zero byte pins that position to those four.
Combined, they cannot exceed 37 characters.

## Batches, and what "found a match" means here

The GPU tests a whole batch of mnemonics at once, so a batch can contain more
than one match. Where the Go tool stops at the first match it sees, this one
reports every match in the batch that found one -- discarding work already
paid for would be worse -- and then stops unless `--infinite` was given. Up to
1024 matches per launch are recorded; beyond that it says how many it had to
drop, which only happens with a prefix or suffix so short that the search is
not really a search.

A reported match lists at most the first 16 addresses of its mnemonic; with
`-a` above 16, use `--all` if you want the rest written out too.

`--batch` is the tuning knob. Bigger batches keep the GPU busier; smaller ones
report matches sooner and use less memory. When every mnemonic is written out
(plain generation, `--all`, or `-v`) each one has to be copied back and
formatted, so the default drops to 65536.

## Performance

Measured with `--bench`, which times the generation kernel alone with CUDA
events -- no host formatting, file writes or display in the way:

```text
Benchmark (NVIDIA GeForce RTX 3060, 5 addresses per mnemonic)
  batch:        262144 mnemonics
  kernel time:  4684.34 ms/batch (avg of 5)
  throughput:   55962 mnemonics/s (279809 addresses/s)
```

That is about 33x the ~1,680 mnemonics/s the Go tool reaches on 16 threads of
the same machine. Checking a single address (`-a 1`) reaches about 82,000
mnemonics/s on the same card, since the per-address ed25519 work is then paid
once instead of five times.

Searching is the mode that runs at kernel speed: nothing but a match leaves
the GPU. Plain generation is slower end to end -- about 26,000 mnemonics/s for
`-n 200000` -- because every mnemonic and address has to be copied back,
rendered to text, and written to disk. That is inherent to asking for the
output rather than for a match.

PBKDF2 and the ed25519 scalar multiplication are the two comparable costs;
unlike on the CPU, where PBKDF2 dominates and the address count is nearly
free, here each extra address per mnemonic is visible. The rest -- entropy,
SHA-256 checksum, Bech32 -- does not measurably register: this kernel benches
within a percent of znn-bruteforce-cuda's, which does no mnemonic construction
at all.

## How it relates to znn-address-generator-go

| | znn-address-generator-go | znn-address-generator-cuda |
| --- | --- | --- |
| Randomness | `crypto/rand` per mnemonic | OS CSPRNG per launch, expanded per thread |
| Mnemonic construction, derivation, hashing | CPU, one goroutine per thread | GPU, one thread per mnemonic |
| Prefix/suffix matching | CPU, regex over the address | GPU, on the encoded address |
| File output, reporting | CPU | CPU (identical logic) |
| Word list, derivation path, address format | \-\- | identical |
| Output file layout | \-\- | identical |
| CLI | \-\- | identical, plus `--batch`/`--block`/`--device`/`-y`/`--selftest`/`--bench` |

Mnemonics are always 24 words from 256 bits of entropy, as in the Go tool.
Seed derivation is only defined for the built-in English word list; a custom
`--wordlist` must still be 2048 ASCII words of at most 8 characters.
