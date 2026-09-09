"""
Handling of the public keys Snowflake uses for key-pair authentication.

Both the legacy user properties (rsa_public_key, rsa_public_key_2) and named key pairs
take the same key material, so the normalization and fingerprinting live here rather than
on either resource.
"""

import base64
import binascii
import hashlib
import re

FINGERPRINT_PREFIX = "SHA256:"

_PEM_DELIMITER = re.compile(r"-{2,}[A-Z ]*-{2,}")


def normalize_public_key(public_key: str) -> str:
    """
    The single-line, delimiter-free form of a public key that Snowflake's SQL expects.

    Snowflake's docs are explicit that the public key delimiters are excluded from the
    SQL statement, and DESC USER reports keys that way, so a key pasted straight out of a
    .pub file is accepted here and the `-----BEGIN PUBLIC KEY-----` wrapper and newlines
    are removed.
    """
    return "".join(_PEM_DELIMITER.sub("", public_key).split())


def public_key_fingerprint(public_key: str) -> str:
    """
    The SHA-256 fingerprint Snowflake reports for a public key.

    Snowflake never echoes a named key pair's public key back -- SHOW USER KEY PAIRS
    returns a fingerprint and nothing else -- so drift on the key itself is detected by
    computing the same fingerprint locally. The fingerprint is the base64-encoded SHA-256
    digest of the key's DER (SubjectPublicKeyInfo) bytes, which is exactly what the
    base64 body of a PEM public key decodes to. It matches:

        openssl rsa -pubin -in rsa_key.pub -outform DER | openssl dgst -sha256 -binary | openssl enc -base64

    https://docs.snowflake.com/en/user-guide/key-pair-auth
    """
    key = normalize_public_key(public_key)
    if not key:
        raise ValueError("public_key is empty")
    try:
        der = base64.b64decode(key, validate=True)
    except (binascii.Error, ValueError) as err:
        raise ValueError(f"public_key is not valid base64-encoded key material: {err}") from err
    return FINGERPRINT_PREFIX + base64.b64encode(hashlib.sha256(der).digest()).decode("utf-8")


def normalize_fingerprint(fingerprint: str) -> str:
    """
    A fingerprint in the `SHA256:<base64>` form snowcap compares on, whether or not
    Snowflake included the prefix.
    """
    fingerprint = fingerprint.strip()
    if fingerprint.upper().startswith(FINGERPRINT_PREFIX):
        fingerprint = fingerprint[len(FINGERPRINT_PREFIX) :]
    return FINGERPRINT_PREFIX + fingerprint
