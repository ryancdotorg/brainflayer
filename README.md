This project provides a performant, flexible implementations of Colin Percival's [scrypt](http://www.tarsnap.com/scrypt.html).

# Features

## Modular Design

The code uses a modular (compile, not runtime) layout to allow new mixing & hash functions to be added easily. The base components (HMAC, PBKDF2, and scrypt) are static and will immediately work with any conforming mix or hash function.

## Supported Mix Functions

* [Salsa20/8](http://cr.yp.to/salsa20.html)
* [ChaCha20/8](http://cr.yp.to/chacha.html)

I am not actually aware of any other candidates for a decent mix function. Salsa20/8 was nearly perfect, but its successor, ChaCha20/8, has better diffusion and is thus stronger, is potentially faster given advanced SIMD support (byte level shuffles, or a 32bit rotate), and is slightly cleaner to implement give that it requires no pre/post processing of data for SIMD implementations. 

While everything is mostly generic, there are a few places that are hardcoded to assume a 64-byte block size, e.g. single block copy and xor for SSE implentations, so these would need to be modularized-ish if a mixing function with a different block size is added.

## Support Hash Functions

* SHA256/512
* [BLAKE256/512](https://www.131002.net/blake/)
* [Skein512](http://www.skein-hash.info/)

Hash function implementations, unlike mix functions, are not optimized. The PBKDF2 computations are relatively minor in the scrypt algorithm, so including CPU specific versions, or vastly unrolling loops, would serve little purpose while bloating the code, both source and binary, and making it more confusing to implement correctly.

Most of the SHA-3 candidates fall in to the "annoying to read/implement" category and have not been included yet. This will of course be moot once BLAKE is chosen as SHA-3.

## CPU Adaptation

The mixing function specialization is selected at runtime based on what the CPU supports (well, x86/x86-64 for now, but theoretically any). On platforms where this is not needed, e.g. where packages are usually compiled from source, it can also select the most suitable implementation at compile time, cutting down on binary size.

For those who are familiar with the scrypt spec, the code specializes at the ROMix level, allowing all copy, xor, and mix calls to be inlined efficiently.

MSVC uses SSE intrinsics as opposed to inline assembly for the mix functions to allow the compiler to fully inline properly. Also, Visual Studio is not smart enough to allow inline assembly in 64-bit code. 

## Self Testing

On first use, scrypt() runs a small series of tests to make sure the hash function, mix functions, and scrypt() itself, are generating correct results. It will exit() (or call a user defined fatal error function) should any of these tests fail. 

Test vectors for individual mix and hash functions are generated from reference implementations. The only "official" test vectors for the full scrypt() are for SHA256 + Salsa20/8 of course; other combinations are generated from this code (once it works with all reference reference test vectors) and subject to change if any implementation errors are discovered.

# Performance

# Building

# Using


