"""
このモジュールは、JPKI証明書とキーを操作するための様々なユーティリティ関数を提供します。
"""
import re
from typing import List, Optional
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

def validate_certificate(cert: x509.Certificate, issuer_cert: x509.Certificate = None) -> bool:
    """
    証明書の有効期限と署名を検証します。

    Args:
        cert: 検証する証明書。
        issuer_cert: 発行者証明書。提供された場合、署名が検証されます。
                      Noneの場合、有効期限のみがチェックされます。

    Returns:
        証明書が有効な場合はTrue、そうでなければFalse。
    """
    # 有効期限をチェック
    now = datetime.utcnow()
    if now < cert.not_valid_before or now > cert.not_valid_after:
        return False

    # 発行者証明書が提供された場合、署名をチェック
    if issuer_cert:
        try:
            issuer_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except InvalidSignature:
            return False

    return True

def cert_to_pem(cert: x509.Certificate) -> bytes:
    """
    証明書オブジェクトをPEM形式に変換します。

    Args:
        cert: 変換する証明書。

    Returns:
        バイトとしてPEMエンコードされた証明書。
    """
    return cert.public_bytes(encoding=serialization.Encoding.PEM)

def public_key_to_pem(pubkey) -> bytes:
    """
    公開鍵オブジェクトをPEM形式に変換します。

    Args:
        pubkey: 変換する公開鍵（例：cert.public_key()から）。

    Returns:
        バイトとしてPEMエンコードされた公開鍵。
    """
    return pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def verify_certificate_chain(cert: x509.Certificate, chain: Optional[List[x509.Certificate]] = None, trusted_roots: Optional[List[x509.Certificate]] = None) -> bool:
    """
    証明書チェーン検証を行います。
    - chain が提供されている場合、leaf から root へ向かうチェーンの署名検証を実施します（leaf, intermediates..., root の順序を想定）。
    - chain が提供されない場合、trusted_roots が提供されればチェーン検証を実施します。
    - それらが提供されない場合は、有効期限のみを検証します。

    Args:
        cert: 検証する証明書。
        chain: leaf から root への署名連鎖を表すチェーン（root を含む場合も可）。順序は leaf, intermediates..., root。
        trusted_roots: 信頼されたルート証明書のリスト（チェーン検証が使えない場合の代替）。

    Returns:
        チェーンが信頼できる場合は True、そうでなければ False。
    """
    now = datetime.utcnow()
    # chain が提供されている場合は、それを用いた検証を優先
    if chain:
        current = cert
        for next_cert in chain:
            try:
                next_cert.public_key().verify(
                    current.signature,
                    current.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    current.signature_hash_algorithm,
                )
            except InvalidSignature:
                return False
            except Exception:
                return False
            current = next_cert

        # 最後の証明書が自己署名か、チェーンの終端がルートとして検証可能かを判定
        try:
            if current.issuer == current.subject:
                current.public_key().verify(
                    current.signature,
                    current.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    current.signature_hash_algorithm,
                )
                return True
            # trusted_roots が提供されていれば、最後の証明書を信頼ルートで検証する
            if trusted_roots:
                for root in trusted_roots:
                    if root.subject == current.issuer:
                        try:
                            root.public_key().verify(
                                current.signature,
                                current.tbs_certificate_bytes,
                                padding.PKCS1v15(),
                                current.signature_hash_algorithm,
                            )
                            return True
                        except InvalidSignature:
                            return False
                        except Exception:
                            return False
            return False
        except InvalidSignature:
            return False
        except Exception:
            return False

    # chain が無い場合は trusted_roots を使った検証を試みる
    if trusted_roots:
        issuer = cert.issuer
        for root in trusted_roots:
            if root.subject == issuer:
                try:
                    root.public_key().verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        cert.signature_hash_algorithm,
                    )
                    return True
                except InvalidSignature:
                    return False
                except Exception:
                    return False
        return False

    # それ以外は有効期限のみを検証する
    if now < cert.not_valid_before or now > cert.not_valid_after:
        return False
    return True


def _load_certs_from_pem_bundle(bundle_pem: bytes) -> List[x509.Certificate]:
    """内部ヘルパー: PEMバンドルから全証明書を読み込む。"""
    certs: List[x509.Certificate] = []
    if not bundle_pem:
        return certs
    for match in re.finditer(br"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", bundle_pem, flags=re.S):
        pem_block = match.group(0)
        cert = x509.load_pem_x509_certificate(pem_block, backend=default_backend())
        certs.append(cert)
    return certs


def verify_certificate_chain_from_pem_bundle(bundle_pem: bytes, leaf_cert: x509.Certificate) -> bool:
    """
    PEMバンドル内のCA中間証明書を用いて、leaf 証明書までのチェーン検証を行います。
    - バンドル内の証明書を順序推定してチェーンを組み立て、verify_certificate_chain で検証します。
    - leaf_cert がバンドル中に含まれていない場合でも、同等の検証を行えるようにします。
    """
    ca_certs = _load_certs_from_pem_bundle(bundle_pem)
    # 末端証明書を leaf に設定したチェーンを組む（leafは引数で与えられている）
    chain = []
    if ca_certs:
        # leaf から始まるチェーンを推定: subject/issuer を照合してつなぐ
        current = leaf_cert
        used = set()
        for _ in range(len(ca_certs)):
            next_cert = None
            for c in ca_certs:
                if c in used:
                    continue
                if current.issuer == c.subject:
                    next_cert = c
                    break
            if not next_cert:
                break
            chain.append(next_cert)
            used.add(next_cert)
            current = next_cert
            if current.issuer == current.subject:
                break

    return verify_certificate_chain(leaf_cert, chain=chain if chain else None, trusted_roots=None)
