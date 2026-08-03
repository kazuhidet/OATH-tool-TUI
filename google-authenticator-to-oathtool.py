#!/usr/bin/env python3
"""Extract oathtool-compatible Base32 secrets from Google Authenticator QR data.

The script works entirely locally.  Python dependencies are not required;
decoding a QR image uses the external `zbarimg` command from the zbar package.
"""

from __future__ import annotations

import argparse
import base64
import csv
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from urllib.parse import parse_qs, unquote, urlparse


ALGORITHMS = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}
DIGITS = {0: 6, 1: 6, 2: 8}
OTP_TYPES = {0: "TOTP", 1: "HOTP", 2: "TOTP"}


class DecodeError(ValueError):
    pass


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data) and shift < 70:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
    raise DecodeError("invalid or truncated Protobuf varint")


def protobuf_fields(data: bytes):
    """Yield (field_number, wire_type, value) from a Protobuf message."""
    offset = 0
    while offset < len(data):
        key, offset = read_varint(data, offset)
        field_number, wire_type = key >> 3, key & 7
        if field_number == 0:
            raise DecodeError("invalid Protobuf field number 0")
        if wire_type == 0:
            value, offset = read_varint(data, offset)
        elif wire_type == 1:
            if offset + 8 > len(data):
                raise DecodeError("truncated 64-bit Protobuf field")
            value, offset = data[offset : offset + 8], offset + 8
        elif wire_type == 2:
            length, offset = read_varint(data, offset)
            if offset + length > len(data):
                raise DecodeError("truncated length-delimited Protobuf field")
            value, offset = data[offset : offset + length], offset + length
        elif wire_type == 5:
            if offset + 4 > len(data):
                raise DecodeError("truncated 32-bit Protobuf field")
            value, offset = data[offset : offset + 4], offset + 4
        else:
            raise DecodeError(f"unsupported Protobuf wire type: {wire_type}")
        yield field_number, wire_type, value


def decode_text(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")


def parse_otp_parameters(data: bytes) -> dict:
    fields: dict[int, object] = {}
    for number, _wire_type, value in protobuf_fields(data):
        fields[number] = value

    secret = fields.get(1)
    if not isinstance(secret, bytes) or not secret:
        raise DecodeError("an account has no OTP secret")

    otp_type_number = int(fields.get(6, 0))
    return {
        "name": decode_text(fields.get(2, b"")),
        "issuer": decode_text(fields.get(3, b"")),
        "algorithm": ALGORITHMS.get(int(fields.get(4, 0)), f"UNKNOWN-{fields.get(4)}"),
        "digits": DIGITS.get(int(fields.get(5, 0)), int(fields.get(5, 0))),
        "type": OTP_TYPES.get(otp_type_number, f"UNKNOWN-{otp_type_number}"),
        "counter": int(fields.get(7, 0)),
        "period": 30,
        "secret": base64.b32encode(secret).decode("ascii").rstrip("="),
    }


def parse_migration_uri(uri: str) -> tuple[list[dict], dict]:
    parsed = urlparse(uri.strip())
    if parsed.scheme != "otpauth-migration":
        raise DecodeError("not a Google Authenticator migration URI")
    values = parse_qs(parsed.query).get("data")
    if not values:
        raise DecodeError("migration URI does not contain data=")

    encoded = values[0]
    try:
        payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except Exception as exc:
        raise DecodeError(f"invalid Base64 migration payload: {exc}") from exc

    accounts = []
    metadata = {"version": 0, "batch_size": 1, "batch_index": 0, "batch_id": 0}
    metadata_fields = {2: "version", 3: "batch_size", 4: "batch_index", 5: "batch_id"}
    for number, wire_type, value in protobuf_fields(payload):
        if number == 1 and wire_type == 2 and isinstance(value, bytes):
            accounts.append(parse_otp_parameters(value))
        elif number in metadata_fields and wire_type == 0:
            metadata[metadata_fields[number]] = int(value)
    if not accounts:
        raise DecodeError("migration payload contains no accounts")
    return accounts, metadata


def parse_standard_uri(uri: str) -> tuple[list[dict], dict]:
    parsed = urlparse(uri.strip())
    if parsed.scheme != "otpauth" or parsed.netloc.lower() not in {"totp", "hotp"}:
        raise DecodeError("not a supported otpauth://totp or otpauth://hotp URI")
    query = parse_qs(parsed.query)
    if "secret" not in query:
        raise DecodeError("OTP URI does not contain secret=")
    label = unquote(parsed.path.lstrip("/"))
    label_issuer, separator, name = label.partition(":")
    issuer = query.get("issuer", [label_issuer if separator else ""])[0]
    if not separator:
        name = label
    account = {
        "name": name,
        "issuer": issuer,
        "algorithm": query.get("algorithm", ["SHA1"])[0].upper(),
        "digits": int(query.get("digits", ["6"])[0]),
        "type": parsed.netloc.upper(),
        "counter": int(query.get("counter", ["0"])[0]),
        "period": int(query.get("period", ["30"])[0]),
        "secret": query["secret"][0].replace(" ", "").upper().rstrip("="),
    }
    return [account], {"version": 0, "batch_size": 1, "batch_index": 0, "batch_id": 0}


def qr_uris_from_image(path: Path) -> list[str]:
    if not shutil.which("zbarimg"):
        raise DecodeError("zbarimg was not found; install the zbar package first")
    result = subprocess.run(
        ["zbarimg", "--quiet", "--raw", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode not in (0, 4):
        message = result.stderr.strip() or "QR decoding failed"
        raise DecodeError(message)
    uris = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not uris:
        raise DecodeError("no QR code was found in the image")
    return uris


def collect_accounts(source: str) -> tuple[list[dict], list[dict]]:
    path = Path(source).expanduser()
    if path.is_file():
        uris = qr_uris_from_image(path)
    elif source == "-":
        uris = [line.strip() for line in sys.stdin if line.strip()]
    else:
        uris = [source.strip()]

    accounts: list[dict] = []
    batches: list[dict] = []
    for uri in uris:
        if uri.startswith("otpauth-migration://"):
            new_accounts, metadata = parse_migration_uri(uri)
        elif uri.startswith("otpauth://"):
            new_accounts, metadata = parse_standard_uri(uri)
        else:
            continue
        accounts.extend(new_accounts)
        batches.append(metadata)
    if not accounts:
        raise DecodeError("no otpauth URI was found")
    return accounts, batches


def clean_tsv(value: object) -> str:
    return str(value).replace("\t", " ").replace("\r", " ").replace("\n", " ")


def render(accounts: list[dict], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(accounts, ensure_ascii=False, indent=2) + "\n"
    if output_format == "secret":
        secret_field = "secret_gpg_base64" if "secret_gpg_base64" in accounts[0] else "secret"
        return "".join(f"{account[secret_field]}\n" for account in accounts)

    encrypted = "secret_gpg_base64" in accounts[0]
    secret_header = "SECRET_GPG_BASE64" if encrypted else "SECRET_BASE32"
    secret_field = "secret_gpg_base64" if encrypted else "secret"
    header = [
        "INDEX", "TYPE", "ISSUER", "ACCOUNT", "DIGITS", "ALGORITHM",
        "COUNTER", "PERIOD", secret_header,
    ]
    data_rows = []
    for index, account in enumerate(accounts, 1):
        data_rows.append([
            index,
            account["type"],
            account["issuer"],
            account["name"],
            account["digits"],
            account["algorithm"],
            account["counter"],
            account["period"],
            account[secret_field],
        ])
    if output_format == "csv":
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(data_rows)
        return output.getvalue()

    rows = ["\t".join(header)]
    rows.extend("\t".join(clean_tsv(value) for value in row) for row in data_rows)
    return "\n".join(rows) + "\n"


def write_securely(path: Path, content: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = -1
            output.write(content)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def encrypt_secret_with_gpg(secret: str, recipient: str) -> str:
    """Return a one-line Base64 representation of a GPG-encrypted secret."""
    if not shutil.which("gpg"):
        raise DecodeError("gpg was not found; install gnupg")
    command = [
        "gpg", "--batch", "--yes",
        "--recipient", recipient, "--encrypt",
    ]
    try:
        result = subprocess.run(
            command,
            input=secret.encode("ascii"),
            capture_output=True,
            timeout=30,
            check=False,
        )
        if result.returncode:
            message = result.stderr.decode("utf-8", errors="replace").strip()
            raise DecodeError(message or "GPG encryption failed")
        return base64.b64encode(result.stdout).decode("ascii")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DecodeError(f"could not run gpg: {exc}") from exc


def encrypt_account_secrets(accounts: list[dict], recipient: str) -> list[dict]:
    protected = []
    for account in accounts:
        encrypted = dict(account)
        encrypted["secret_gpg_base64"] = encrypt_secret_with_gpg(account["secret"], recipient)
        del encrypted["secret"]
        protected.append(encrypted)
    return protected


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract Base32 OTP secrets from a Google Authenticator export QR."
    )
    parser.add_argument("source", help="QR image, otpauth URI, or - to read URI(s) from stdin")
    parser.add_argument(
        "-f", "--format", choices=("tsv", "csv", "json", "secret"), default="tsv",
        help="output format (default: tsv)",
    )
    parser.add_argument("-o", "--output", type=Path, help="write to a mode-0600 file")
    parser.add_argument(
        "--gpg-recipient", metavar="KEY",
        help="GPG-encrypt each secret for this key ID, fingerprint, or email address",
    )
    parser.add_argument(
        "--oathtool", type=int, metavar="INDEX",
        help="run oathtool for the selected 1-based account index",
    )
    args = parser.parse_args()
    if args.gpg_recipient and args.oathtool is not None:
        parser.error("--gpg-recipient cannot be combined with --oathtool")

    try:
        accounts, batches = collect_accounts(args.source)
        expected_parts = max((batch["batch_size"] for batch in batches), default=1)
        if expected_parts > len(batches):
            print(
                f"warning: this export has {expected_parts} QR parts; only {len(batches)} were read. "
                "Decode every QR and pass their URIs through stdin.",
                file=sys.stderr,
            )

        if args.oathtool is not None:
            if not 1 <= args.oathtool <= len(accounts):
                raise DecodeError(f"account index must be between 1 and {len(accounts)}")
            if not shutil.which("oathtool"):
                raise DecodeError("oathtool was not found")
            account = accounts[args.oathtool - 1]
            command = ["oathtool"]
            if account["type"] == "TOTP":
                command += [f"--totp={account['algorithm'].lower()}"]
            elif account["type"] == "HOTP":
                if account["algorithm"] != "SHA1":
                    raise DecodeError("oathtool supports HOTP with SHA1 only")
                command += ["--hotp", f"--counter={account['counter']}"]
            else:
                raise DecodeError(f"unsupported OTP type: {account['type']}")
            command += [f"--digits={account['digits']}", "-b", "-"]
            result = subprocess.run(
                command,
                input=account["secret"] + "\n",
                check=False,
                text=True,
                capture_output=True,
            )
            if result.returncode:
                raise DecodeError(result.stderr.strip() or "oathtool failed")
            content = result.stdout
        else:
            if args.gpg_recipient:
                accounts = encrypt_account_secrets(accounts, args.gpg_recipient)
            content = render(accounts, args.format)

        if args.output:
            write_securely(args.output.expanduser(), content)
        else:
            sys.stdout.write(content)
        return 0
    except (DecodeError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
