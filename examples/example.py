#!/usr/bin/env python3
import logging

from pyjpki import CardManager, PinVerificationError


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("pyjpki.example")
    logger.info("pyjpkiのサンプルスクリプトを開始します")

    try:
        with CardManager() as manager:
            logger.info("カードの接続に成功しました")

            # 属性情報読み取り用PIN
            attr_pin = "1218"
            try:
                manager.verify_pin(attr_pin, pin_type="attr")
                logger.info("属性PINの認証に成功しました")

                # 個人情報の読み取り（4つの基本属性）
                info = manager.read_personal_info()
                logger.info(f"氏名: {info.name}")
                logger.info(f"住所: {info.address}")
                logger.info(f"生年月日: {info.birth_date}")
                logger.info(f"性別: {info.gender}")

                # 認証用証明書情報の読み取り
                auth_cert_info = manager.get_certificate_info(cert_type="auth")
                logger.info(f"認証証明書の主体者: {auth_cert_info.subject}")
                logger.info(f"認証証明書の発行者: {auth_cert_info.issuer}")
                logger.info(f"認証証明書のシリアル番号: {auth_cert_info.serial_number}")

                # 認証鍵を使用したデジタル署名の作成
                data_to_sign = b"test"
                signature = manager.sign_data(data_to_sign, sign_type="auth")
                logger.info(f"署名（16進数）: {signature.hex()}")

            except PinVerificationError as e:
                logger.error(f"PIN認証に失敗しました。残り試行回数: {e.retries_left}")

    except Exception as e:
        logger.error(f"予期しないエラーが発生しました: {e}")


if __name__ == "__main__":
    main()
