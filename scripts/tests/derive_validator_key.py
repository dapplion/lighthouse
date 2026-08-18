"""Derive an EIP-2334 validator signing key from a BIP39 mnemonic.

The optional-proofs devnet needs the secret key of an active validator to sign execution proofs
with, because consumers reject proofs from validators they cannot find in the active set. Run this
against the mnemonic the devnet generated its keys from.

Needs `py_ecc` (pip install py_ecc), which is not a Lighthouse dependency.

    python3 scripts/tests/derive_validator_key.py "<mnemonic>" [validator_index]
"""

import hashlib
import hmac
import sys
import unicodedata

from py_ecc.bls import G2ProofOfPossession as bls

CURVE_ORDER = 52435875175126190479447740508185965837690552500527637822603658699938581184513


def hkdf(salt, ikm, info, length):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def hkdf_mod_r(ikm, key_info=b""):
    salt = b"BLS-SIG-KEYGEN-SALT-"
    secret_key = 0
    while secret_key == 0:
        salt = hashlib.sha256(salt).digest()
        okm = hkdf(salt, ikm + b"\x00", key_info + (48).to_bytes(2, "big"), 48)
        secret_key = int.from_bytes(okm, "big") % CURVE_ORDER
    return secret_key


def ikm_to_lamport_sk(ikm, salt):
    okm = hkdf(salt, ikm, b"", 255 * 32)
    return [okm[i * 32 : (i + 1) * 32] for i in range(255)]


def parent_sk_to_lamport_pk(parent_sk, index):
    salt = index.to_bytes(4, "big")
    ikm = parent_sk.to_bytes(32, "big")
    lamport = ikm_to_lamport_sk(ikm, salt) + ikm_to_lamport_sk(
        bytes(byte ^ 0xFF for byte in ikm), salt
    )
    return hashlib.sha256(b"".join(hashlib.sha256(x).digest() for x in lamport)).digest()


def derive_child_sk(parent_sk, index):
    return hkdf_mod_r(parent_sk_to_lamport_pk(parent_sk, index))


def seed_from_mnemonic(mnemonic, passphrase=""):
    normalised = unicodedata.normalize("NFKD", mnemonic).encode()
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase).encode()
    return hashlib.pbkdf2_hmac("sha512", normalised, salt, 2048, 64)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    validator_index = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    secret_key = hkdf_mod_r(seed_from_mnemonic(sys.argv[1]))
    for node in (12381, 3600, validator_index, 0, 0):
        secret_key = derive_child_sk(secret_key, node)

    print(f"validator_index {validator_index}")
    print(f"secret_key      {secret_key.to_bytes(32, 'big').hex()}")
    print(f"public_key      0x{bls.SkToPk(secret_key).hex()}")


if __name__ == "__main__":
    main()
