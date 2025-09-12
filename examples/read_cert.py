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