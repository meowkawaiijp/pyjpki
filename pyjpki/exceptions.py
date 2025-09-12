"""
pyjpkiライブラリ用のカスタム例外。
"""

class JPKIError(Exception):
    """すべてのpyjpkiエラーの基底例外クラス。"""
    pass

class APDUError(JPKIError):
    """
    APDUコマンドが非9000ステータスワードを返したときに発生します。
    """
    def __init__(self, message, sw1, sw2):
        self.sw1 = sw1
        self.sw2 = sw2
        super().__init__(f"{message} (SW1: {sw1:02X}, SW2: {sw2:02X})")

class PinVerificationError(APDUError):
    """
    PIN検証が失敗したときに特に発生します。
    """
    def __init__(self, sw1, sw2):
        self.retries_left = sw2 & 0x0F if sw1 == 0x63 else 0
        message = f"PIN verification failed. Retries left: {self.retries_left}"
        super().__init__(message, sw1, sw2)
