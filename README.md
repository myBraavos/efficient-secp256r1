# Efficient secp256r1 (aka nist-p256) ECDSA in Cairo

The purpose of this library is to provide a gas-efficient implementation of secp256r1 signature validation in Cairo.

## Background

Allowing transactions to be signed and validated using the `secp256r1` curve enables great end-user experience in the form of signing transactions using the biometrics on the user's device.

On top of great UX, this also has the added benefit of moving away from seed phrases to better security in modern mobile-devices / laptops, and superior security when the user's device supports a dedicated security chip (e.g. Android's Secure Element and Apple's Secure Enclave etc.).

Since `secp256r1` ECDSA is not native to Cairo (i.e. it does not have a dedicated Builtin), the Gas cost incurred in validation of the signature is very high. In this library we aim to optimize that as much as possible.

## Implementation Notes

We've adapted `cairo-lang`'s `secp256k1` ECDSA validation implementation. We had to modify some field operations and
handling of `BigInt3` limbs as `secp256r1`'s operations only very tightly fit into the `BigInt3` representation.
Also, `cairo-lang` uses the public-key recovery algorithm for ECDSA validation while this library uses straight-forward validation since in a secure-hardware signing setup, we don't have `v` which is necessary for correct public-key recovery.

Some hints were modified to accommodate the above, these will be introduced as part of `cairo-lang` version `0.11.0`. To use this prior to that you will have to apply the patch at `cairo-lang-secp256r1-hints.patch` on your python virtual env.

## API

In `src/secp256r1/signature.cairo`:
> verify_secp256r1_signature(msg_hash: BigInt3, r: BigInt3, s: BigInt3, public_key: EcPoint)


## Running tests

We adapted Google's `Project Wycheproof` tests with the exception of `asn.1` related tests since our implementation assumes that `(r, s)` are sent in an already decoded form.

to run tests:
> pytest tests/test_secp256r1.py

We kept the same naming conventions and test ids from the original test-suite so filtering on a specific test-case can be done as follows:
> pytest tests/test_secp256r1.py -k tc-292

You can use `cairo-nile` to run coverage:
> nile coverage

