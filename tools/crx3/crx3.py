#!/usr/bin/env python3

# This source code is licensed under the MIT License.
# See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/crx3/LICENSE

# Ported from crx3 (https://github.com/ahwayakchih/crx3) by Marcin Konicki, MIT License.
# See NOTICES.md (https://github.com/SenseiDeElite/agecord/blob/main/NOTICES.md#crx3) for the full license text.

# Python script to create CRX3 files (web extension package v3 format) for Chromium-based browsers.

import argparse
import os
import struct
import sys
import zipfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# --------------------------------------------------------------------------
# Constants (mirrors crx3stream.js)
# --------------------------------------------------------------------------

MAGIC = b"Cr24"
VERSION = 3
CRX_ID_SIZE = 16
SIGNATURE_CONTEXT = b"CRX3 SignedData\x00"
RSA_KEY_BITS = 4096


# --------------------------------------------------------------------------
# Minimal protobuf wire-format writer
#
# CRX3's protobuf schema is tiny (a handful of bytes/message fields), so
# rather than pull in a full protobuf toolchain we hand-roll the few
# primitives we need: varints, tags, and length-delimited fields.
# --------------------------------------------------------------------------

WIRE_VARINT = 0
WIRE_LENGTH_DELIMITED = 2


def write_varint(value):
    """Encode an unsigned integer as a protobuf varint."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def write_tag(field_number, wire_type):
    """Encode a protobuf field tag. Field numbers >127 (e.g. 10000) need a
    multi-byte varint here -- this is the one spot a naive single-byte tag
    writer would silently produce a corrupt header."""
    return write_varint((field_number << 3) | wire_type)


def write_bytes_field(field_number, data):
    """Length-delimited bytes/string/embedded-message field."""
    return write_tag(field_number, WIRE_LENGTH_DELIMITED) + write_varint(len(data)) + data


# message-typed fields use the same wire encoding as bytes fields
write_message_field = write_bytes_field


def encode_signed_data(crx_id):
    """SignedData{ crx_id = 1 }"""
    return write_bytes_field(1, crx_id)


def encode_asymmetric_key_proof(public_key_der, signature):
    """AsymmetricKeyProof{ public_key = 1, signature = 2 }"""
    return write_bytes_field(1, public_key_der) + write_bytes_field(2, signature)


def encode_crx_file_header(public_key_der, signature, signed_header_data):
    """CrxFileHeader{ sha256_with_rsa = 2 (repeated), signed_header_data = 10000 }"""
    proof = encode_asymmetric_key_proof(public_key_der, signature)
    return (
        write_message_field(2, proof)
        + write_bytes_field(10000, signed_header_data)
    )


# --------------------------------------------------------------------------
# Key handling (mirrors keypair.js)
# --------------------------------------------------------------------------

def load_or_create_private_key(key_path):
    """Load an RSA private key from `key_path` if it exists, otherwise
    generate a new one and save it there. Returns (private_key, created)."""
    if key_path and os.path.exists(key_path):
        with open(key_path, "rb") as f:
            data = f.read()
        try:
            private_key = serialization.load_pem_private_key(data, password=None)
            return private_key, False
        except ValueError as exc:
            raise SystemExit(f'"{key_path}" already exists but could not be loaded: {exc}')

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_BITS)

    if key_path:
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(key_path, "wb") as f:
            f.write(pem)

    return private_key, True


def public_key_der(private_key):
    """SubjectPublicKeyInfo DER encoding of the public key."""
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def compute_crx_id(pub_der):
    """First 16 bytes of SHA-256(public key DER) -- the extension ID."""
    import hashlib
    return hashlib.sha256(pub_der).digest()[:CRX_ID_SIZE]


def encode_app_id(crx_id):
    """Render the 16-byte app id the way Chrome's update manifests / the
    chrome://extensions page display it: hex digits remapped from
    [0-9a-f] to [a-p]."""
    hex_str = crx_id.hex()
    return "".join(chr(int(ch, 16) + ord("a")) for ch in hex_str)


# --------------------------------------------------------------------------
# Building the zip archive (mirrors getFilePaths.js / findCommonPath.js /
# the zip.addFile loop in writeCRX3File.js)
# --------------------------------------------------------------------------

def collect_files(src):
    """Given a path to an extension directory, return (root_dir, sorted
    list of absolute file paths) covering everything that should go into
    the extension's zip."""
    if not os.path.isdir(src):
        raise SystemExit(f'"{src}" is not a directory')
    root = os.path.abspath(src)

    files = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            files.append(os.path.join(dirpath, name))
    files.sort()

    manifest_path = os.path.join(root, "manifest.json")
    if manifest_path not in files:
        raise SystemExit(f'"{manifest_path}" file is missing')

    return root, files


def build_zip_bytes(root, files):
    """Zip up `files` (absolute paths under `root`) with deterministic,
    root-relative arcnames. Returns the raw zip bytes."""
    import io

    buf = io.BytesIO()

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in files:
            arcname = os.path.relpath(path, root)
            # zip entries should use "/" regardless of host OS
            arcname = arcname.replace(os.sep, "/")
            zf.write(path, arcname)

    return buf.getvalue()


# --------------------------------------------------------------------------
# Signing + final assembly (mirrors crxInit/crxFinish in crx3stream.js)
# --------------------------------------------------------------------------

def sign_zip(private_key, signed_header_data, zip_bytes):
    """RSASSA-PKCS1-v1_5 + SHA-256 signature over the CRX3 signed blob."""
    size_octets = struct.pack("<I", len(signed_header_data))
    to_sign = SIGNATURE_CONTEXT + size_octets + signed_header_data + zip_bytes
    return private_key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())


def build_crx3(private_key, zip_bytes):
    """Assemble the full CRX3 file bytes. Returns (crx_bytes, encoded_app_id)."""
    pub_der = public_key_der(private_key)
    crx_id = compute_crx_id(pub_der)
    signed_header_data = encode_signed_data(crx_id)

    signature = sign_zip(private_key, signed_header_data, zip_bytes)

    header = encode_crx_file_header(pub_der, signature, signed_header_data)

    crx = (
        MAGIC
        + struct.pack("<I", VERSION)
        + struct.pack("<I", len(header))
        + header
        + zip_bytes
    )

    return crx, encode_app_id(crx_id)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Pack a directory into a signed CRX3 file."
    )
    parser.add_argument("src", help="Path to extension directory")
    parser.add_argument("-o", "--crx", dest="crx_path", default="web-extension.crx",
                         help="Output .crx path (default: %(default)s)")
    parser.add_argument("-p", "--key", dest="key_path", default="web-extension.pem",
                         help="Private key PEM path; created if missing (default: %(default)s)")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)

    root, files = collect_files(args.src)
    zip_bytes = build_zip_bytes(root, files)

    private_key, created = load_or_create_private_key(args.key_path)

    crx_bytes, app_id = build_crx3(private_key, zip_bytes)

    with open(args.crx_path, "wb") as f:
        f.write(crx_bytes)

    if created:
        print(f'Private key file created at "{args.key_path}"')
    print(f'CRX file created at "{args.crx_path}"')
    print(f"Extension ID: {app_id}")


if __name__ == "__main__":
    main()
