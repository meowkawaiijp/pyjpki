# pyjpki

マイナンバーカードなどの日本の公的個人認証サービス（JPKI）スマートカードとやり取りするためのPythonモジュールです。

## 機能

- 利用可能なスマートカードリーダーの一覧表示
- カードへの接続と切断
- 利用者認証用PIN、署名用PIN、属性情報読み取り用PINの認証
- カードから認証用証明書と署名用証明書の読み取り
- 証明書情報の解析（Subject、Issuer、有効期限など）
- カードの秘密鍵を使用したデジタル署名（SHA256withRSA）の作成
- 4つの基本個人属性（氏名、住所、生年月日、性別）の読み取り
- 証明書検証とPEM変換のユーティリティ関数
- すべてのAPDUコマンドの詳細なデバッグログ

## インストール

このプロジェクトは依存関係管理に[Poetry](https://python-poetry.org/)を使用しています。

### Windows環境でのインストール

Windows環境では、以下の手順でインストールしてください：

1. **PC/SCサービスが有効になっていることを確認**
   - Windowsのサービスで「Smart Card」サービスが実行中であることを確認してください

2. **pyscardライブラリのインストール**
   ```bash
   pip install pyscard
   ```

3. **pyjpkiのインストール**
   ```bash
   pip install .
   ```

### Linux環境でのインストール

Linux環境では、まずPC/SCドライバーをインストールしてください：

**Debian/Ubuntu:**
```bash
sudo apt-get update
sudo apt-get install -y libpcsclite-dev
```

**CentOS/RHEL:**
```bash
sudo yum install pcsc-lite-devel
```

その後、ライブラリとその依存関係をインストールします：
```bash
pip install .
```

## 基本的な使用方法

`pyjpki`ライブラリの使用例を以下に示します。

### カードへの接続とPIN認証

```python
import logging
from pyjpki import CardManager, PinVerificationError

# APDUコマンドを確認するためにデバッグログを有効化
logging.basicConfig(level=logging.INFO)
logging.getLogger("pyjpki").setLevel(logging.DEBUG)

try:
    # 自動接続/切断のためにコンテキストマネージャーとして使用
    with CardManager() as manager:
        print("カードへの接続に成功しました。")

        # 個人属性読み取り用の4桁PINを認証
        pin = "1234"
        try:
            manager.verify_pin(pin, pin_type="attr")
            print("属性情報読み取り用PIN認証が成功しました。")
        except PinVerificationError as e:
            print(f"PIN認証に失敗しました。残り試行回数: {e.retries_left}")

except Exception as e:
    print(f"エラーが発生しました: {e}")
```

### 証明書の読み取り

```python
from pyjpki import CardManager

with CardManager() as manager:
    # 認証用証明書を読み取り
    auth_cert_info = manager.get_certificate_info(cert_type="auth")

    print("--- 認証用証明書 ---")
    print(f"Subject: {auth_cert_info.subject}")
    print(f"Issuer: {auth_cert_info.issuer}")
    print(f"シリアル番号: {auth_cert_info.serial_number}")
    print(f"有効開始日: {auth_cert_info.not_valid_before}")
    print(f"有効期限: {auth_cert_info.not_valid_after}")
```

### デジタル署名の作成

```python
from pyjpki import CardManager, PinVerificationError

with CardManager() as manager:
    # 署名には対応するPINの事前認証が必要
    auth_pin = "1234" # 実際のPINに置き換えてください
    try:
        manager.verify_pin(auth_pin, pin_type="auth")
        print("認証用PINが認証されました。")

        data_to_sign = b"これはテストメッセージです。"
        signature = manager.sign_data(data_to_sign, sign_type="auth")

        print(f"\nデータ: {data_to_sign}")
        print(f"署名（16進数）: {signature.hex()}")

    except PinVerificationError as e:
        print(f"PIN認証に失敗しました。残り試行回数: {e.retries_left}")
```

### 個人情報の読み取り

```python
from pyjpki import CardManager, PinVerificationError

with CardManager() as manager:
    # 属性読み取りには4桁PINの事前認証が必要
    attr_pin = "1234" # 実際のPINに置き換えてください
    try:
        manager.verify_pin(attr_pin, pin_type="attr")
        print("属性情報読み取り用PINが認証されました。")

        info = manager.read_personal_info()

        print("\n--- 個人情報 ---")
        print(f"氏名: {info.name}")
        print(f"住所: {info.address}")
        print(f"生年月日: {info.birth_date}")
        print(f"性別: {info.gender}")

    except PinVerificationError as e:
        print(f"PIN認証に失敗しました。残り試行回数: {e.retries_left}")
```