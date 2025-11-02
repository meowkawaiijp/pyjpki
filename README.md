# pyjpki
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/meowkawaiijp/pyjpki)
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

### 参考: 例示コードの追加
- 例として `examples/example.py`があります。カード接続、属性PIN認証、個人情報の読み取り、認証証明書の読み取り、データ署名の一連の動作をデモンストレーションします。

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

### 証明書チェーン検証の実用例

PEM バンドルを用いた証明書チェーン検証の使い方を示します。 leaf 証明書と中間CA・ルートCAを PEM 形式で分けて持つ場合と、CA バンドルをそのまま読み込む場合の例を示します。

```python
from pyjpki import verify_certificate_chain, verify_certificate_chain_from_pem_bundle
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# 事前に leaf や中間CA、ルートCAを PEM ファイルとして保存していると仮定
leaf_pem_path = "certs/leaf_cert.pem"
inter1_pem_path = "certs/intermediate1.pem"
root_pem_path = "certs/root.pem"

with open(leaf_pem_path, "rb") as f:
    leaf_pem = f.read()
with open(inter1_pem_path, "rb") as f:
    inter1_pem = f.read()
with open(root_pem_path, "rb") as f:
    root_pem = f.read()

leaf_cert = x509.load_pem_x509_certificate(leaf_pem, backend=default_backend())
inter1_cert = x509.load_pem_x509_certificate(inter1_pem, backend=default_backend())
root_cert = x509.load_pem_x509_certificate(root_pem, backend=default_backend())

# 1) chain 引数を使った検証
chain = [inter1_cert, root_cert]
print("verify_certificate_chain with chain:", verify_certificate_chain(leaf_cert, chain=chain))

# 2) PEM バンドルを直接検証
# leaf + inter1 + root の順で連結した PEM を bundle_pem として渡す
bundle_pem = leaf_pem + inter1_pem + root_pem
print("verify_certificate_chain_from_pem_bundle:", verify_certificate_chain_from_pem_bundle(bundle_pem, leaf_cert))
```
