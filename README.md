# Google Authenticator Export + oathtool TUI

These Python scripts extract OTP accounts from account-transfer QR codes exported by Google Authenticator and generate TOTP/HOTP codes in a terminal-based user interface.

OTP secrets imported from QR codes can be encrypted individually with a GPG public key. When you select an account in the TUI, you are prompted for the private-key passphrase. The decrypted secret is passed from memory directly to `oathtool`, and the generated OTP is automatically copied to the clipboard.

## Files

| File | Description |
| --- | --- |
| `google-authenticator-to-oathtool.py` | Parses QR images or `otpauth` URIs and produces CSV, TSV, or JSON output |
| `oathtool-tui.py` | Displays accounts from a CSV/TSV file, decrypts GPG-encrypted secrets, generates OTPs, and copies them to the clipboard |

## Features

- Supports Google Authenticator `otpauth-migration://` export QR codes
- Supports standard `otpauth://totp` and `otpauth://hotp` URIs
- Accepts JPEG, PNG, and other QR image formats readable by `zbarimg`
- Supports multiple accounts and multi-part export QR codes
- Produces CSV, TSV, JSON, or secret-only output
- Encrypts each OTP secret individually with GPG
- Supports TOTP, HOTP, SHA-1, SHA-256, and SHA-512
- Displays the remaining validity period of a TOTP and refreshes it automatically when it expires
- Automatically copies OTPs to the clipboard on Wayland, X11, macOS, WSL, and other supported environments
- Requires no third-party Python packages

## Requirements

### Arch Linux / Arch Linux ARM

For Wayland:

```bash
sudo pacman -S python zbar oath-toolkit gnupg wl-clipboard
```

On X11, you can use `xclip` or `xsel` instead of `wl-clipboard`.

```bash
sudo pacman -S xclip
```

### macOS

```bash
brew install zbar oath-toolkit gnupg
```

The scripts use the built-in macOS `pbcopy` command for clipboard access.

## Setup

Make the scripts executable:

```bash
chmod 755 google-authenticator-to-oathtool.py oathtool-tui.py
```

If you do not already have a GPG key, create one:

```bash
gpg --full-generate-key
```

List the available public keys and their fingerprints:

```bash
gpg --list-keys --fingerprint
```

Use the full fingerprint of the encryption recipient rather than an ambiguous name or short key ID. The corresponding private key must be available in the GPG keyring of the user running the TUI.

## Basic Usage

### 1. Export QR codes from Google Authenticator

In Google Authenticator:

1. Open **Transfer accounts** from the menu.
2. Select **Export accounts**.
3. Select the accounts to export.
4. Save the displayed QR code to your computer as a JPEG or PNG image.

The QR image contains your OTP secrets. Do not send it to anyone; handle it only in a trusted local environment.

### 2. Create a GPG-encrypted CSV file

```bash
./google-authenticator-to-oathtool.py qr.jpg \
    --format csv \
    --gpg-recipient "GPG key fingerprint" \
    --output accounts.csv
```

Files created with `--output` are assigned permissions of `0600`.

In the CSV file, the `SECRET_GPG_BASE64` column is used instead of the plaintext `SECRET_BASE32` column. Metadata such as the issuer and account name remains unencrypted.

```text
INDEX,TYPE,ISSUER,ACCOUNT,DIGITS,ALGORITHM,COUNTER,PERIOD,SECRET_GPG_BASE64
1,TOTP,Example,user@example.com,6,SHA1,0,30,hQGMA...
```

### 3. Start the TUI

```bash
./oathtool-tui.py accounts.csv
```

Select an account and press `Enter`. The following prompt appears:

```text
GPG private-key passphrase:
```

After you enter the passphrase, the OTP is generated and copied to the clipboard. The passphrase is not displayed while you type it.

## TUI Controls

| Key | Action |
| --- | --- |
| `Up` / `Down` | Move between accounts |
| `j` / `k` | Move between accounts |
| `Page Up` / `Page Down` | Move by one page |
| `Home` / `End` | Move to the first or last account |
| `Enter` | Decrypt the selected secret, generate an OTP, and copy it |
| `/` | Search by issuer or account name |
| `x` | Clear the search filter |
| `r` | Regenerate and copy the OTP |
| `c` | Copy the currently displayed OTP again |
| `q` / `Esc` | Quit |

When a TOTP expires, it is refreshed automatically and the new OTP is copied to the clipboard. The decrypted secret for the selected account remains in the Python process memory until you quit the TUI or select another account.

## Clipboard Support

The clipboard command is selected automatically according to the runtime environment.

| Environment | Command |
| --- | --- |
| Wayland | `wl-copy` |
| X11 | `xclip`, or `xsel` if `xclip` is unavailable |
| macOS | `pbcopy` |
| Termux | `termux-clipboard-set` |
| WSL | `clip.exe` |

The OTP is passed to the clipboard command through standard input and is never included in command-line arguments. If no supported clipboard command is found, OTP generation and on-screen display continue, and a clipboard error is shown in the TUI.

## Multi-Part Export QR Codes

If Google Authenticator displays several QR codes in sequence, save them as separate files such as `qr-1.png` and `qr-2.png`.

```bash
for image in qr-*.png; do
    zbarimg --quiet --raw "$image"
done | ./google-authenticator-to-oathtool.py - \
    --format csv \
    --gpg-recipient "GPG key fingerprint" \
    --output accounts.csv
```

If you provide only one image from an incomplete multi-part export, the script displays a warning.

## Plaintext Output

Omit `--gpg-recipient` if you do not want to use GPG encryption.

```bash
./google-authenticator-to-oathtool.py qr.jpg \
    --format csv \
    --output accounts-plaintext.csv
```

In this case, secrets are stored in plaintext in the `SECRET_BASE32` column. The TUI can read both encrypted and plaintext CSV files.

## Output Formats

```bash
./google-authenticator-to-oathtool.py qr.jpg --format tsv
./google-authenticator-to-oathtool.py qr.jpg --format csv
./google-authenticator-to-oathtool.py qr.jpg --format json
./google-authenticator-to-oathtool.py qr.jpg --format secret
```

The default format is TSV. When saving sensitive output to a file, use `--output` rather than shell redirection so that the script can apply secure file permissions.

## Validating CSV/TSV Files

You can validate the file format and columns without opening the TUI:

```bash
./oathtool-tui.py --check accounts.csv
```

On success:

```text
OK: 3 account(s)
```

This checks the Base64 encoding and the CSV/TSV structure but does not decrypt GPG-encrypted secrets.

## Using a Standard `otpauth` Provisioning URI

The script can also parse a standard provisioning URI instead of a QR image:

```bash
./google-authenticator-to-oathtool.py \
    'otpauth://totp/Example:user@example.com?secret=BASE32_SECRET&issuer=Example' \
    --format csv
```

Entering a URI directly on the command line may expose it through shell history or process information. For a URI containing a real secret, use a QR image or standard input instead.

## Generating an OTP Without the TUI

You can generate an OTP directly from the first account in a QR code:

```bash
./google-authenticator-to-oathtool.py qr.jpg --oathtool 1
```

This option cannot be used together with `--gpg-recipient`.

## Security Considerations

- Treat QR images, standard `otpauth` URIs, and plaintext `SECRET_BASE32` values with the same care as passwords.
- Even when GPG encryption is enabled, CSV metadata such as issuer names and email addresses remains unencrypted.
- Secrets and GPG passphrases are never passed to external commands as command-line arguments.
- Decrypted secrets are not saved to files; they remain in the Python process memory only while the corresponding account is selected.
- Generated OTPs are placed on the clipboard and may therefore be accessible to clipboard-history tools or other applications.
- After creating a protected CSV file, securely delete or store any QR images you no longer need.
- Back up the GPG private key and the encrypted CSV file separately in secure locations to protect against data loss.

## Troubleshooting

### `zbarimg was not found`

Install `zbar` on Arch Linux:

```bash
sudo pacman -S zbar
```

### `no QR code was found in the image`

- Make sure the entire QR code is visible.
- Use a higher-resolution image.
- Leave sufficient white space around the QR code.
- Reduce JPEG compression or use PNG instead.

### `gpg: ... No public key`

Verify that the public key for the specified fingerprint exists in your keyring:

```bash
gpg --list-keys --fingerprint
```

### `GPG decryption failed` or `Bad passphrase`

- Verify that the private key corresponding to the public key used for encryption is available.
- Check the private-key passphrase.
- Make sure `gpg-agent` can run in the current environment.
- Check whether loopback pinentry is disabled by the GPG Agent configuration.

### `oathtool was not found`

```bash
sudo pacman -S oath-toolkit
```

### `no clipboard command found`

On Wayland:

```bash
sudo pacman -S wl-clipboard
```

On X11:

```bash
sudo pacman -S xclip
```

### The OTP is rejected

TOTP depends on an accurate system clock. Check the time-synchronization status:

```bash
timedatectl status
```

Enable NTP synchronization if necessary:

```bash
sudo timedatectl set-ntp true
```

## Help

```bash
./google-authenticator-to-oathtool.py --help
./oathtool-tui.py --help
```

## References

- [GNU OATH Toolkit: oathtool manual](https://www.nongnu.org/oath-toolkit/man-oathtool.html)
- [GnuPG Manual](https://www.gnupg.org/documentation/manuals/gnupg/)
- [ZBar Bar Code Reader](https://github.com/mchehab/zbar)
- [wl-clipboard](https://github.com/bugaevc/wl-clipboard)
- [xclip](https://github.com/astrand/xclip)
