# SignHybrid

This repository implements the hybrid signature system, which combines classical and quantum encryption.

- Classical ciphers available : RSA, DSA, ECDSA

- Quantum ciphers available : Dilithium, Falcon, PHINICS+

## Content 
#### This repository contains the following files (roughly in order of dependency)

1. [`rsa_sign.c`](Signature/rsa_sign.c) allows to implement the RSA's signature
1. [`rsa_sign.h`](Signature/rsa_sign.h) allow to call the function that implements RSA's signature
1. [`ecdsa_sign.c`](Signature/ecdsa_sign.c) allows to implement the ECDSA's signature
1. [`ecdsa_sign.h`](Signature/ecdsa_sign.h) allow to call the function that implements ECDSA's signature
1. [`dsa_signature.c`](Signature/dsa_signature.c) allows to implement the DSA's signature
1. [`dsa_signature.h`](Signature/dsa_signature.h) allow to call the function that implements DSA's signature
1. [`dilithium_signature.c`](Signature/dilithium_signature.c) allows to implement the dilithium's signature
1. [`dilithium_signature.h`](Signature/dilithium_signature.h) allow to call the function that implements dilithium's signature
1. [`falcon_signature.c`](Signature/falcon_signature.c) allows to implement the falcon's signature
1. [`falcon_signature.h`](Signature/falcon_signature.h) allow to call the function that implements falcon's signature
1. [`phinics_sign.c`](Signature/phinics/src/phinics_sign.c) allows to implement the phinics's signature
1. [`phinics_sign.h`](Signature/phinics/src/phinics_sign.h) allow to call the function that implements phinics's signature
1. [`phinics_verify.c`](Signature/phinics/src/phinics_verify.c) allow to verify the phinics's signature

1. [`hybrid_signature.c`](Signature/hybrid_signature.c) allows to call twice function that implement signature and implement the hybrid signature
1. [`interface`](interface/signature_gui.py) allows to call twice function that implement signature and implement the hybrid signature

## How to use

Ongoing...

## Authors

Farmata Cissé

Noémie Mbongo

Cabrel Tayo Foyo
