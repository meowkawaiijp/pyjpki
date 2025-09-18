#!/usr/bin/env python3
import logging
import time
import sys
import getpass

from pyjpki import CardManager, PinVerificationError


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("pyjpki.example")
    logger.info("pyjpkiのサンプルスクリプトを開始します")

    while True:
        # リーダーが接続されているか確認
        if not CardManager.get_readers():
            logger.warning("カードリーダーが接続されていません。2秒後に再確認します...")
            time.sleep(2)
            continue

        try:
            logger.info("カードリーダーを検出しました。カードを挿入してください...")
            with CardManager() as manager:
                logger.info("カードの接続に成功しました。処理を開始します。")

                # --- ここから下の処理はすべて接続が確立された with ブロック内で行う ---

                try:
                    # PINの入力を求める
                    attr_pin = getpass.getpass("属性情報参照用の暗証番号（4桁）を入力してください: ")
                    manager.verify_pin(attr_pin, pin_type="attr")
                    logger.info("属性PINの認証に成功しました")

                    # メニュー処理
                    handle_menu(manager)

                except PinVerificationError as e:
                    logger.error(f"PIN認証に失敗しました。残り試行回数: {e.retries_left}")

                except Exception as e:
                    logger.error(f"カード処理中にエラーが発生しました: {e}")

                # 正常に処理が完了したら、ループを抜けてスクリプトを終了
                break

        except RuntimeError:
            # カードが挿入されていない場合、pyscardは接続エラーを発生させる
            logger.info("カードが挿入されていません。2秒後に再試行します。")
            time.sleep(2)
        except Exception as e:
            logger.error(f"予期しないエラーが発生しました: {e}")
            sys.exit(1)


def read_personal_info_action(manager: CardManager, logger: logging.Logger):
    """個人情報を読み取り、表示する"""
    try:
        logger.info("個人情報の読み取りを開始します...")
        info = manager.read_personal_info()
        logger.info(f"  氏名: {info.name}")
        logger.info(f"  住所: {info.address}")
        logger.info(f"  生年月日: {info.birth_date}")
        logger.info(f"  性別: {info.gender}")
        logger.info("個人情報の読み取りが完了しました。")
    except Exception as e:
        logger.error(f"個人情報の読み取り中にエラーが発生しました: {e}")

def read_certificate_action(manager: CardManager, logger: logging.Logger):
    """証明書情報を読み取り、表示する"""
    try:
        logger.info("認証用証明書の読み取りを開始します...")
        auth_cert_info = manager.get_certificate_info(cert_type="auth")
        logger.info(f"  主体者: {auth_cert_info.subject}")
        logger.info(f"  発行者: {auth_cert_info.issuer}")
        logger.info(f"  シリアル番号: {auth_cert_info.serial_number}")
        logger.info("認証用証明書の読み取りが完了しました。")
    except Exception as e:
        logger.error(f"証明書の読み取り中にエラーが発生しました: {e}")

def sign_data_action(manager: CardManager, logger: logging.Logger):
    """データに署名し、結果を表示する"""
    try:
        logger.info("デジタル署名の作成を開始します...")
        data_to_sign = b"This is a test message for digital signature."
        try:
            signature = manager.sign_data(data_to_sign, sign_type="auth")
        except Exception as e:
            # PIN が必要なエラーの場合、ユーザーに PIN を入力して再試行
            pin_needed = False
            if isinstance(e, PinVerificationError):
                pin_needed = True
            if pin_needed or "PIN" in str(e):
                pin = getpass.getpass("署名用PINを入力してください: ")
                signature = manager.sign_data(data_to_sign, sign_type="auth", pin=pin)
            else:
                raise
        logger.info(f"  署名対象データ: {data_to_sign.decode()}")
        logger.info(f"  生成された署名（16進数）: {signature.hex()}")
        logger.info("デジタル署名の作成が完了しました。")
    except Exception as e:
        logger.error(f"署名中にエラーが発生しました: {e}")

def handle_menu(manager: CardManager):
    """操作選択のメニューを表示し、ユーザーの入力に応じて処理を実行する"""
    logger = logging.getLogger("pyjpki.example.menu")

    while True:
        print("\n" + "="*30)
        print("実行する操作を選択してください:")
        print("  1: 個人情報を読み取る")
        print("  2: 認証用証明書を読み取る")
        print("  3: データに署名する")
        print("  0: 終了する")
        print("="*30)
        choice = input("番号を入力してください > ")

        if choice == '1':
            read_personal_info_action(manager, logger)
        elif choice == '2':
            read_certificate_action(manager, logger)
        elif choice == '3':
            sign_data_action(manager, logger)
        elif choice == '0':
            logger.info("スクリプトを終了します。")
            break
        else:
            logger.warning("無効な選択です。もう一度入力してください。")

        input("\n続けるにはEnterキーを押してください...")


if __name__ == "__main__":
    main()
