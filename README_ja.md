# Google Authenticator Export + oathtool TUI

Google Authenticatorでエクスポートしたアカウント移行用QRコードからOTPアカウントを抽出し、端末上のTUIでTOTP/HOTPを生成するためのPythonスクリプトです。

QRコードから取り込んだOTPシークレットはアカウント単位でGPG公開鍵暗号化できます。TUIでアカウントを選択した時に秘密鍵のパスフレーズを要求し、復号したシークレットをメモリ上から`oathtool`へ渡します。生成されたOTPは自動的にクリップボードへとコピーされます。

## ファイル

| ファイル | 役割 |
| --- | --- |
| `google-authenticator-to-oathtool.py` | QR画像または`otpauth` URIを解析し、CSV/TSV/JSONを生成 |
| `oathtool-tui.py` | CSV/TSVのアカウント一覧表示、GPG復号、OTP生成、クリップボードコピー |

## 主な機能

- Google Authenticatorの`otpauth-migration://`エクスポートQRに対応
- 通常の`otpauth://totp`および`otpauth://hotp`に対応
- JPEG、PNGなど、`zbarimg`が読み取れるQR画像に対応
- 複数アカウントおよび複数分割QRに対応
- CSV、TSV、JSON、シークレットのみの出力に対応
- OTPシークレットをアカウント単位でGPG暗号化
- TOTP、HOTP、SHA-1、SHA-256、SHA-512に対応
- TOTPの残り有効時間を表示し、期限ごとに自動更新
- Wayland、X11、macOS、WSLなどのクリップボードへ自動コピー
- Pythonの追加パッケージは不要

## 必要なソフトウェア

### Arch Linux / Arch Linux ARM

Wayland環境の場合：

```bash
sudo pacman -S python zbar oath-toolkit gnupg wl-clipboard
```

X11環境では`wl-clipboard`の代わりに`xclip`または`xsel`を使用できます。

```bash
sudo pacman -S xclip
```

### macOS

```bash
brew install zbar oath-toolkit gnupg
```

クリップボードにはmacOS標準の`pbcopy`を使用します。

## セットアップ

スクリプトへ実行権限を付けます。

```bash
chmod 755 google-authenticator-to-oathtool.py oathtool-tui.py
```

GPG鍵がない場合は作成します。

```bash
gpg --full-generate-key
```

利用可能な公開鍵とフィンガープリントを確認します。

```bash
gpg --list-keys --fingerprint
```

暗号化先には、曖昧な名前や短いキーIDではなくフィンガープリントの指定を推奨します。対応する秘密鍵は、TUIを実行するユーザーのGPG鍵リングに必要です。

## 基本的な使い方

### 1. Google AuthenticatorからQRをエクスポート

Google Authenticatorで次の操作を行います。

1. メニューから「アカウントを移行」を開く
2. 「アカウントをエクスポート」を選択
3. 対象アカウントを選択
4. 表示されたQRコードをJPEGまたはPNG画像としてPCに保存

QR画像にはOTPシークレットが含まれています。第三者へ送信せず、ローカル環境だけで取り扱ってください。

### 2. GPG暗号化されたCSVを生成

```bash
./google-authenticator-to-oathtool.py qr.jpg \
    --format csv \
    --gpg-recipient "GPG鍵のフィンガープリント" \
    --output accounts.csv
```

`--output`で作成したファイルのパーミッションは`0600`になります。

CSV内では、平文の`SECRET_BASE32`に代わって`SECRET_GPG_BASE64`列が使用されます。発行者名やアカウント名などのメタデータは平文です。

```text
INDEX,TYPE,ISSUER,ACCOUNT,DIGITS,ALGORITHM,COUNTER,PERIOD,SECRET_GPG_BASE64
1,TOTP,Example,user@example.com,6,SHA1,0,30,hQGMA...
```

### 3. TUIを起動

```bash
./oathtool-tui.py accounts.csv
```

対象アカウントを選択して`Enter`を押すと、次のプロンプトが表示されます。

```text
GPG private-key passphrase:
```

パスフレーズ入力後にOTPが生成され、クリップボードへコピーされます。入力したパスフレーズは画面に表示されません。

## TUIの操作

| キー | 動作 |
| --- | --- |
| `↑` / `↓` | アカウントを移動 |
| `j` / `k` | アカウントを移動 |
| `Page Up` / `Page Down` | ページ単位で移動 |
| `Home` / `End` | 先頭または末尾へ移動 |
| `Enter` | 選択したシークレットを復号し、OTPを生成してコピー |
| `/` | 発行者名またはアカウント名を検索 |
| `x` | 検索条件を解除 |
| `r` | OTPを再生成してコピー |
| `c` | 表示中のOTPを再度コピー |
| `q` / `Esc` | 終了 |

TOTPは有効期限が切れると自動更新され、新しいOTPがクリップボードへコピーされます。選択中のアカウントについては、TUIを終了するか別のアカウントを選択するまで、復号済みシークレットをメモリ上に保持します。

## クリップボード対応

使用するコマンドは実行環境から自動判定されます。

| 環境 | コマンド |
| --- | --- |
| Wayland | `wl-copy` |
| X11 | `xclip`、なければ`xsel` |
| macOS | `pbcopy` |
| Termux | `termux-clipboard-set` |
| WSL | `clip.exe` |

OTPはクリップボードコマンドの標準入力へ渡され、コマンドライン引数には含まれません。対応コマンドが見つからない場合もOTP生成と画面表示は継続され、TUI内にクリップボードエラーが表示されます。

## 複数に分割されたエクスポートQR

Google Authenticatorが複数のQRを順番に表示した場合は、それぞれを`qr-1.png`、`qr-2.png`のように保存します。

```bash
for image in qr-*.png; do
    zbarimg --quiet --raw "$image"
done | ./google-authenticator-to-oathtool.py - \
    --format csv \
    --gpg-recipient "GPG鍵のフィンガープリント" \
    --output accounts.csv
```

1枚だけ渡した時に分割QRの残りがある場合は、スクリプトが警告を表示します。

## 平文出力

GPG暗号化を使用しない場合は`--gpg-recipient`を省略します。

```bash
./google-authenticator-to-oathtool.py qr.jpg \
    --format csv \
    --output accounts-plaintext.csv
```

この場合は`SECRET_BASE32`列にシークレットが平文で保存されます。TUIは暗号化されたCSVと平文CSVの両方を読み込めます。

## 出力形式

```bash
./google-authenticator-to-oathtool.py qr.jpg --format tsv
./google-authenticator-to-oathtool.py qr.jpg --format csv
./google-authenticator-to-oathtool.py qr.jpg --format json
./google-authenticator-to-oathtool.py qr.jpg --format secret
```

デフォルトはTSVです。ファイルへ安全に保存する場合は、シェルのリダイレクトではなく`--output`の使用を推奨します。

## CSV/TSVの検証

TUIを開かずにファイル形式と各列を検証できます。

```bash
./oathtool-tui.py --check accounts.csv
```

正常な場合：

```text
OK: 3 account(s)
```

GPG暗号化されたシークレットの実際の復号までは行わず、Base64形式とCSV/TSV構造を検証します。

## 登録用`otpauth` URIの入力

QR画像ではなく通常の登録URIも解析できます。

```bash
./google-authenticator-to-oathtool.py \
    'otpauth://totp/Example:user@example.com?secret=BASE32_SECRET&issuer=Example' \
    --format csv
```

URIをコマンドラインへ直接記載するとシェル履歴やプロセス情報へ残る可能性があります。実際のシークレットを含むURIでは、QR画像入力または標準入力の利用を推奨します。

## TUIを使わず直接OTPを生成

QR内の1番目のアカウントから直接OTPを生成できます。

```bash
./google-authenticator-to-oathtool.py qr.jpg --oathtool 1
```

このオプションと`--gpg-recipient`は同時に指定できません。

## セキュリティ上の注意

- QR画像、通常の`otpauth` URI、平文の`SECRET_BASE32`はパスワードと同等に扱ってください。
- GPG暗号化時も、発行者名やメールアドレスなどのCSVメタデータは暗号化されません。
- シークレットとGPGパスフレーズは外部コマンドのコマンドライン引数に渡しません。
- 復号済みシークレットはファイルへ保存せず、選択中のみPythonプロセスのメモリ上に保持します。
- 生成されたOTPはクリップボードへ入るため、クリップボード履歴機能や他のアプリから参照される可能性があります。
- QRから安全なCSVを作成した後は、不要になったQR画像を適切に削除または保管してください。
- GPG秘密鍵と暗号化CSVは、障害に備えて別々の安全な場所へバックアップしてください。

## トラブルシューティング

### `zbarimg was not found`

Arch Linuxでは`zbar`をインストールします。

```bash
sudo pacman -S zbar
```

### `no QR code was found in the image`

- QR全体が欠けていないか確認する
- 画像の解像度を上げる
- QR周囲の余白を残す
- JPEGの圧縮率を下げるかPNGを使用する

### `gpg: ... No public key`

指定したフィンガープリントの公開鍵が鍵リングに存在するか確認します。

```bash
gpg --list-keys --fingerprint
```

### `GPG decryption failed`または`Bad passphrase`

- 暗号化に使用した公開鍵に対応する秘密鍵が存在するか確認する
- 秘密鍵のパスフレーズを確認する
- `gpg-agent`が起動できる環境か確認する
- GPG Agentでloopback pinentryが禁止されていないか確認する

### `oathtool was not found`

```bash
sudo pacman -S oath-toolkit
```

### `no clipboard command found`

Waylandの場合：

```bash
sudo pacman -S wl-clipboard
```

X11の場合：

```bash
sudo pacman -S xclip
```

### OTPが認証されない

TOTPはシステム時刻に依存します。時刻同期状態を確認してください。

```bash
timedatectl status
```

必要に応じてNTP同期を有効にします。

```bash
sudo timedatectl set-ntp true
```

## ヘルプ

```bash
./google-authenticator-to-oathtool.py --help
./oathtool-tui.py --help
```

## 参考資料

- [GNU OATH Toolkit: oathtool manual](https://www.nongnu.org/oath-toolkit/man-oathtool.html)
- [GnuPG Manual](https://www.gnupg.org/documentation/manuals/gnupg/)
- [ZBar Bar Code Reader](https://github.com/mchehab/zbar)
- [wl-clipboard](https://github.com/bugaevc/wl-clipboard)
- [xclip](https://github.com/astrand/xclip)
