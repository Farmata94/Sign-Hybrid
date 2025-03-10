# SignHybrid

This repository implements the hybrid signature system, which combines classical and quantum encryption.

Classical ciphers available : RSA, DSA, ECDSA

Quantum ciphers available : Dilithium, Falcon, PHINICS+

## Content 

This repository contains the following files (roughly in order of dependency):
1. [`dilithium_signature.c`]('Signature/dilithium_signature.c') contains shared functions and constants
1. [`rng.py`](rng.py) implements a ChaCha20-based PRNG, useful for KATs (standalone)
1. [`samplerz.py`](samplerz.py) implements a Gaussian sampler over the integers (standalone)
1. [`fft_constants.py`](fft_constants.py) contains precomputed constants used in the FFT
1. [`ntt_constants.py`](ntt_constants.py) contains precomputed constants used in the NTT
1. [`fft.py`](fft.py) implements the FFT over R[x] / (x<sup>n</sup> + 1)
1. [`ntt.py`](ntt.py) implements the NTT over Z<sub>q</sub>[x] / (x<sup>n</sup> + 1)
1. [`ntrugen.py`](ntrugen.py) generate polynomials f,g,F,G in Z[x] / (x<sup>n</sup> + 1) such that f G - g F = q
1. [`ffsampling.py`](ffsampling.py) implements the fast Fourier sampling algorithm
1. [`falcon.py`](falcon.py) implements Falcon
1. [`test.py`](test.py) implements tests to check that everything is properly implemented


## How to use
