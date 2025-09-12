"""
このモジュールは、JPKI証明書とキーを操作するための様々なユーティリティ関数を提供します。
"""
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

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
