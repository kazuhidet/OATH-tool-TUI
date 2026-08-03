#!/usr/bin/env python3
"""Curses TUI for generating OTPs from TSV/CSV with optional GPG secrets."""

from __future__ import annotations

import argparse
import base64
import csv
import curses
from dataclasses import dataclass, replace
import getpass
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


@dataclass(frozen=True)
class Account:
    index: str
    otp_type: str
    issuer: str
    name: str
    digits: int
    algorithm: str
    secret: str = ""
    encrypted_secret: str = ""
    counter: int = 0
    period: int = 30

    @property
    def label(self) -> str:
        if self.issuer and self.name:
            return f"{self.issuer} — {self.name}"
        return self.issuer or self.name or f"Account {self.index}"


class InputError(ValueError):
    pass


def detect_delimiter(sample: str) -> str:
    first_line = sample.splitlines()[0] if sample.splitlines() else ""
    if "\t" in first_line:
        return "\t"
    try:
        return csv.Sniffer().sniff(sample[:8192], delimiters=",;\t").delimiter
    except csv.Error:
        return ","


def normalized(row: dict[str, str | None]) -> dict[str, str]:
    return {
        str(key).strip().upper(): (value or "").strip()
        for key, value in row.items()
        if key is not None
    }


def require_int(value: str, field: str, row_number: int, default: int) -> int:
    if not value:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise InputError(f"row {row_number}: {field} must be an integer") from exc


def validate_secret(secret: str, row_number: int) -> str:
    secret = "".join(secret.split()).upper().rstrip("=")
    if not secret:
        raise InputError(f"row {row_number}: SECRET_BASE32 is empty")
    try:
        base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise InputError(f"row {row_number}: SECRET_BASE32 is invalid") from exc
    return secret


def validate_encrypted_secret(value: str, row_number: int) -> str:
    value = "".join(value.split())
    if not value:
        raise InputError(f"row {row_number}: SECRET_GPG_BASE64 is empty")
    try:
        base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise InputError(f"row {row_number}: SECRET_GPG_BASE64 is invalid") from exc
    return value


def decrypt_gpg_secret(encrypted_secret: str, passphrase_provider=None) -> str:
    """Decrypt one secret in memory, asking for its key passphrase every time."""
    if not shutil.which("gpg"):
        raise InputError("gpg was not found; install gnupg")
    if passphrase_provider is None:
        passphrase_provider = lambda: getpass.getpass("GPG private-key passphrase: ")
    try:
        passphrase = passphrase_provider()
    except (EOFError, KeyboardInterrupt) as exc:
        raise InputError("GPG passphrase input was cancelled") from exc
    if len(passphrase.encode("utf-8")) > 4096:
        raise InputError("GPG passphrase is unexpectedly long")
    try:
        ciphertext = base64.b64decode(encrypted_secret, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise InputError("SECRET_GPG_BASE64 is invalid") from exc

    passphrase_fd, passphrase_writer = os.pipe()
    command = [
        "gpg", "--batch", "--quiet", "--pinentry-mode", "loopback",
        "--passphrase-fd", str(passphrase_fd), "--decrypt",
    ]
    try:
        os.write(passphrase_writer, (passphrase + "\n").encode("utf-8"))
        os.close(passphrase_writer)
        passphrase_writer = -1
        result = subprocess.run(
            command,
            input=ciphertext,
            capture_output=True,
            pass_fds=(passphrase_fd,),
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InputError(f"could not run gpg: {exc}") from exc
    finally:
        passphrase = ""
        os.close(passphrase_fd)
        if passphrase_writer >= 0:
            os.close(passphrase_writer)
    if result.returncode:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise InputError(message or "GPG decryption failed")
    try:
        secret = result.stdout.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise InputError("decrypted secret is not ASCII Base32") from exc
    return validate_secret(secret, 0)


def load_accounts(path: Path) -> list[Account]:
    try:
        content = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise InputError(str(exc)) from exc
    if not content.strip():
        raise InputError("the input file is empty")

    reader = csv.DictReader(content.splitlines(), delimiter=detect_delimiter(content))
    headers = {str(name).strip().upper() for name in (reader.fieldnames or [])}
    required = {"TYPE", "ISSUER", "ACCOUNT"}
    missing = required - headers
    if missing:
        raise InputError("missing column(s): " + ", ".join(sorted(missing)))
    if not headers.intersection({"SECRET_BASE32", "SECRET_GPG_BASE64"}):
        raise InputError("missing column: SECRET_BASE32 or SECRET_GPG_BASE64")

    accounts: list[Account] = []
    for row_number, raw_row in enumerate(reader, 2):
        if not any(value and value.strip() for value in raw_row.values()):
            continue
        row = normalized(raw_row)
        otp_type = (row.get("TYPE") or "TOTP").upper()
        if otp_type not in {"TOTP", "HOTP"}:
            raise InputError(f"row {row_number}: unsupported TYPE {otp_type!r}")
        algorithm = (row.get("ALGORITHM") or "SHA1").upper().replace("-", "")
        if algorithm not in {"SHA1", "SHA256", "SHA512"}:
            raise InputError(f"row {row_number}: unsupported ALGORITHM {algorithm!r}")
        digits = require_int(row.get("DIGITS", ""), "DIGITS", row_number, 6)
        if digits not in {6, 7, 8}:
            raise InputError(f"row {row_number}: DIGITS must be 6, 7, or 8")
        period = require_int(row.get("PERIOD", ""), "PERIOD", row_number, 30)
        if period <= 0:
            raise InputError(f"row {row_number}: PERIOD must be positive")
        counter = require_int(row.get("COUNTER", ""), "COUNTER", row_number, 0)
        if counter < 0:
            raise InputError(f"row {row_number}: COUNTER must not be negative")
        plaintext = row.get("SECRET_BASE32", "")
        encrypted = row.get("SECRET_GPG_BASE64", "")
        if bool(plaintext) == bool(encrypted):
            raise InputError(
                f"row {row_number}: provide exactly one of SECRET_BASE32 or SECRET_GPG_BASE64"
            )
        accounts.append(Account(
            index=row.get("INDEX") or str(len(accounts) + 1),
            otp_type=otp_type,
            issuer=row.get("ISSUER", ""),
            name=row.get("ACCOUNT", ""),
            digits=digits,
            algorithm=algorithm,
            secret=validate_secret(plaintext, row_number) if plaintext else "",
            encrypted_secret=validate_encrypted_secret(encrypted, row_number) if encrypted else "",
            counter=counter,
            period=period,
        ))
    if not accounts:
        raise InputError("the input file contains no accounts")
    return accounts


def unlock_account(account: Account, passphrase_provider=None) -> Account:
    if account.secret:
        return account
    secret = decrypt_gpg_secret(account.encrypted_secret, passphrase_provider)
    return replace(account, secret=secret, encrypted_secret="")


def generate_otp(account: Account, counter: int | None = None) -> str:
    if account.otp_type == "TOTP":
        command = [
            "oathtool",
            f"--totp={account.algorithm.lower()}",
            f"--time-step-size={account.period}s",
        ]
    else:
        command = ["oathtool", "--hotp", f"--counter={account.counter if counter is None else counter}"]
    command += ["--base32", f"--digits={account.digits}", "-"]
    try:
        result = subprocess.run(
            command,
            input=account.secret + "\n",
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"could not run oathtool: {exc}") from exc
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "oathtool failed")
    otp = result.stdout.strip().splitlines()
    if not otp:
        raise RuntimeError("oathtool returned no OTP")
    return otp[-1].strip()


def clipboard_command() -> tuple[list[str], str]:
    """Select a clipboard command suitable for the current desktop."""
    if sys.platform == "darwin" and shutil.which("pbcopy"):
        return ["pbcopy"], "pbcopy"
    if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-copy"):
        return ["wl-copy", "--type", "text/plain;charset=utf-8"], "wl-copy"
    if os.environ.get("DISPLAY") and shutil.which("xclip"):
        return ["xclip", "-selection", "clipboard", "-in"], "xclip"
    if os.environ.get("DISPLAY") and shutil.which("xsel"):
        return ["xsel", "--clipboard", "--input"], "xsel"
    if os.environ.get("TERMUX_VERSION") and shutil.which("termux-clipboard-set"):
        return ["termux-clipboard-set"], "termux-clipboard-set"
    if shutil.which("clip.exe"):
        return ["clip.exe"], "clip.exe"
    raise RuntimeError(
        "no clipboard command found (install wl-clipboard on Wayland or xclip on X11)"
    )


def copy_to_clipboard(value: str) -> str:
    command, backend = clipboard_command()
    try:
        result = subprocess.run(
            command,
            input=value,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"clipboard copy failed: {exc}") from exc
    if result.returncode:
        raise RuntimeError(f"clipboard copy failed using {backend}")
    return backend


def generate_and_copy(account: Account, counter: int | None = None) -> tuple[str, str]:
    otp = generate_otp(account, counter)
    try:
        backend = copy_to_clipboard(otp)
        notice = f"Copied to clipboard ({backend})"
    except RuntimeError as exc:
        notice = f"Clipboard: {exc}"
    return otp, notice


def put(screen, y: int, x: int, text: object, width: int, attr: int = 0) -> None:
    height, screen_width = screen.getmaxyx()
    if y < 0 or y >= height or x >= screen_width or width <= 0:
        return
    value = str(text).replace("\n", " ")
    try:
        screen.addnstr(y, max(0, x), value, min(width, screen_width - max(0, x)), attr)
    except curses.error:
        pass


def prompt(screen, label: str) -> str | None:
    height, width = screen.getmaxyx()
    screen.timeout(-1)
    curses.echo()
    try:
        curses.curs_set(1)
    except curses.error:
        pass
    put(screen, height - 1, 0, " " * max(0, width - 1), width - 1)
    put(screen, height - 1, 0, label, width - 1, curses.A_BOLD)
    screen.refresh()
    try:
        raw = screen.getstr(height - 1, min(len(label), width - 2), max(1, width - len(label) - 2))
        return raw.decode("utf-8", errors="replace").strip()
    except (curses.error, KeyboardInterrupt):
        return None
    finally:
        curses.noecho()
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        screen.timeout(200)


def account_matches(account: Account, query: str) -> bool:
    haystack = f"{account.index} {account.otp_type} {account.issuer} {account.name}".casefold()
    return query.casefold() in haystack


def draw(screen, accounts: list[Account], visible: list[int], selected: int, top: int,
         query: str, active: int | None, otp: str, error: str, notice: str,
         hotp_counter: int | None) -> int:
    screen.erase()
    height, width = screen.getmaxyx()
    list_top = 3
    detail_lines = 6
    list_height = max(1, height - list_top - detail_lines)

    title = f" oathtool TUI — {len(visible)}/{len(accounts)} accounts "
    put(screen, 0, 0, title, width, curses.A_REVERSE | curses.A_BOLD)
    filter_text = f"Filter: {query}" if query else "Filter: (none)"
    put(screen, 1, 0, filter_text, width - 1)
    if width >= 72:
        put(screen, 2, 0, " #   Type  Issuer                    Account", width - 1, curses.A_BOLD)
    else:
        put(screen, 2, 0, " #   Type  Account", width - 1, curses.A_BOLD)

    if not visible:
        put(screen, list_top, 2, "No matching accounts", width - 3, curses.A_DIM)
    else:
        selected = max(0, min(selected, len(visible) - 1))
        if selected < top:
            top = selected
        elif selected >= top + list_height:
            top = selected - list_height + 1
        top = max(0, min(top, max(0, len(visible) - list_height)))
        for row_pos, visible_pos in enumerate(range(top, min(len(visible), top + list_height))):
            account = accounts[visible[visible_pos]]
            marker = "▶" if visible[visible_pos] == active else " "
            if width >= 72:
                line = f"{marker}{account.index:>3.3}  {account.otp_type:<4}  {account.issuer:<24.24}  {account.name}"
            else:
                line = f"{marker}{account.index:>3.3}  {account.otp_type:<4}  {account.label}"
            attr = curses.A_REVERSE if visible_pos == selected else 0
            put(screen, list_top + row_pos, 0, line, width - 1, attr)

    divider_y = max(list_top + 1, height - detail_lines)
    put(screen, divider_y, 0, "─" * max(0, width - 1), width - 1, curses.A_DIM)
    if active is not None:
        account = accounts[active]
        put(screen, divider_y + 1, 1, account.label, width - 2, curses.A_BOLD)
        if error:
            put(screen, divider_y + 2, 1, f"Error: {error}", width - 2, curses.A_BOLD)
        elif otp:
            grouped = " ".join(otp[i:i + 3] for i in range(0, len(otp), 3))
            put(screen, divider_y + 2, 1, grouped, width - 2, curses.A_BOLD)
            if account.otp_type == "TOTP":
                remaining = account.period - (int(time.time()) % account.period)
                bar_width = min(30, max(5, width - 22))
                filled = int(bar_width * remaining / account.period)
                put(screen, divider_y + 3, 1, f"Valid for {remaining:2d}s  [{'█' * filled}{'·' * (bar_width - filled)}]", width - 2)
            else:
                put(screen, divider_y + 3, 1, f"HOTP counter: {hotp_counter}", width - 2)
        if notice:
            put(screen, divider_y + 4, 1, notice, width - 2, curses.A_DIM)
    else:
        put(screen, divider_y + 1, 1, "Select an account and press Enter", width - 2, curses.A_DIM)

    help_text = "↑/↓ j/k: move  Enter: generate+copy  c: copy  /: search  x: clear  r: refresh  q: quit"
    put(screen, height - 1, 0, help_text, width - 1, curses.A_REVERSE)
    screen.refresh()
    return top


def run_tui(screen, accounts: list[Account]) -> None:
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    screen.keypad(True)
    screen.timeout(200)
    selected = 0
    top = 0
    query = ""
    visible = list(range(len(accounts)))
    active: int | None = None
    unlocked_account: Account | None = None
    otp = ""
    error = ""
    notice = ""
    generated_step: int | None = None
    hotp_counter: int | None = None

    while True:
        if active is not None and unlocked_account is not None and unlocked_account.otp_type == "TOTP":
            current_step = int(time.time()) // unlocked_account.period
            if current_step != generated_step:
                try:
                    otp, notice = generate_and_copy(unlocked_account)
                    error = ""
                except RuntimeError as exc:
                    otp, error, notice = "", str(exc), ""
                generated_step = current_step

        top = draw(
            screen, accounts, visible, selected, top, query,
            active, otp, error, notice, hotp_counter,
        )
        key = screen.getch()
        if key in (ord("q"), 27):
            unlocked_account = None
            return
        if key in (curses.KEY_UP, ord("k")) and visible:
            selected = max(0, selected - 1)
        elif key in (curses.KEY_DOWN, ord("j")) and visible:
            selected = min(len(visible) - 1, selected + 1)
        elif key == curses.KEY_PPAGE and visible:
            selected = max(0, selected - max(1, screen.getmaxyx()[0] - 9))
        elif key == curses.KEY_NPAGE and visible:
            selected = min(len(visible) - 1, selected + max(1, screen.getmaxyx()[0] - 9))
        elif key == curses.KEY_HOME:
            selected = 0
        elif key == curses.KEY_END and visible:
            selected = len(visible) - 1
        elif key == ord("/"):
            new_query = prompt(screen, "Search: ")
            if new_query is not None:
                query = new_query
                visible = [i for i, account in enumerate(accounts) if account_matches(account, query)]
                selected, top = 0, 0
        elif key == ord("x"):
            query = ""
            visible = list(range(len(accounts)))
            selected, top = 0, 0
        elif key in (curses.KEY_ENTER, 10, 13) and visible:
            active = visible[selected]
            account = accounts[active]
            unlocked_account = None
            try:
                if account.encrypted_secret:
                    curses.def_prog_mode()
                    curses.endwin()
                    try:
                        unlocked_account = unlock_account(account)
                    finally:
                        curses.reset_prog_mode()
                        screen.clear()
                        screen.refresh()
                else:
                    unlocked_account = account
                hotp_counter = account.counter if account.otp_type == "HOTP" else None
                otp, notice = generate_and_copy(unlocked_account, hotp_counter)
                error = ""
            except (InputError, RuntimeError) as exc:
                unlocked_account = None
                otp, error, notice = "", str(exc), ""
            generated_step = int(time.time()) // account.period if account.otp_type == "TOTP" else None
        elif key == ord("r") and active is not None and unlocked_account is not None:
            try:
                otp, notice = generate_and_copy(unlocked_account, hotp_counter)
                error = ""
            except RuntimeError as exc:
                otp, error, notice = "", str(exc), ""
            generated_step = (
                int(time.time()) // unlocked_account.period
                if unlocked_account.otp_type == "TOTP" else None
            )
        elif key == ord("c") and otp:
            try:
                backend = copy_to_clipboard(otp)
                notice = f"Copied to clipboard ({backend})"
            except RuntimeError as exc:
                notice = f"Clipboard: {exc}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Select an account and generate its OTP in a TUI.")
    parser.add_argument(
        "file", type=Path,
        help="TSV/CSV containing plaintext or individually GPG-encrypted secrets",
    )
    parser.add_argument("--check", action="store_true", help="validate the file without opening the TUI")
    args = parser.parse_args()

    try:
        accounts = load_accounts(args.file.expanduser())
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.check:
        print(f"OK: {len(accounts)} account(s)")
        return 0
    if not shutil.which("oathtool"):
        print("error: oathtool was not found; install oath-toolkit", file=sys.stderr)
        return 1
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("error: the TUI must be run in a terminal", file=sys.stderr)
        return 1
    try:
        curses.wrapper(run_tui, accounts)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
