"""
このモジュールは、pyscardライブラリを使用してスマートカードリーダーと
カードへの接続を管理するクラスを提供します。
"""
from typing import List, Optional, Tuple

import hashlib
import logging
from typing import List, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from pyasn1.type import univ, namedtype, tag
from pyasn1.codec.der import encoder as der_encoder
from smartcard.System import readers
from smartcard.pcsc.PCSCExceptions import BaseSCardException
from smartcard.CardConnection import CardConnection
from smartcard.reader.Reader import Reader


from .constants import (
    CLA_ISO7816,
    CLA_JPKI_SIGN,
    INS_SELECT,
    INS_VERIFY,
    INS_READ_BINARY,
    INS_COMPUTE_DIGITAL_SIGNATURE,
    DF_JPKI,
    DF_ATTRIBUTE,
    EF_AUTH_PIN,
    EF_SIGN_PIN,
    EF_ATTR_PIN,
    EF_AUTH_CERT,
    EF_SIGN_CERT,
    EF_AUTH_KEY,
    EF_SIGN_KEY,
    EF_4_BASIC_INFO,
    SW_SUCCESS,
    SW_VERIFY_FAIL_PREFIX,
    OID_SHA256,
)
from .exceptions import APDUError, JPKIError, PinVerificationError


logger = logging.getLogger(__name__)


class CardManager:
    """
    スマートカードへの接続を管理するクラス。

    このクラスは、スマートカードの接続と切断を処理するコンテキストマネージャーです。
    """

    def __init__(self, reader_index: int = 0):
        """
        CardManagerを初期化します。

        Args:
            reader_index: 利用可能なリーダーリストから使用するリーダーのインデックス。
        """
        self.reader_index = reader_index
        self._reader: Optional[Reader] = None
        self._connection: Optional[CardConnection] = None
        self._cert_cache: dict = {}
        logger.info("CardManager initialized for reader index %d", reader_index)

    @staticmethod
    def get_readers() -> List[str]:
        """
        利用可能なスマートカードリーダー名のリストを取得します。

        Returns:
            各文字列が接続されたリーダーの名前である文字列のリスト。
        """
        try:
            reader_list = readers()
            if not reader_list:
                logger.warning("No smart card readers found")
                return []
            
            import platform
            if platform.system() == "Windows":
                normalized_readers = []
                for reader in reader_list:
                    reader_name = str(reader)
                    if "\\" in reader_name:
                        reader_name = reader_name.split("\\")[-1]
                    normalized_readers.append(reader_name)
                return normalized_readers
            else:
                return [str(r) for r in reader_list]
                
        except BaseSCardException as e:
            logger.error(f"Error getting smart card readers: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error getting smart card readers: {e}")
            return []

    def connect(self) -> None:
        """
        選択されたリーダー内のスマートカードへの接続を確立します。

        Raises:
            RuntimeError: リーダーが見つからない場合、または指定されたリーダーインデックスが無効な場合。
            Exception: 接続中にpyscardからの例外を伝播します。
        """
        try:
            reader_list = readers()
            if not reader_list:
                raise RuntimeError("No smart card readers found.")

            if self.reader_index >= len(reader_list):
                raise RuntimeError(f"Reader index {self.reader_index} is out of bounds.")

            self._reader = reader_list[self.reader_index]
            logger.debug("Connecting to reader: %s", self._reader)
            self._connection = self._reader.createConnection()
            
            self._connection.connect()
          
            logger.info("Connected to card.")
            
        except BaseSCardException as e:
            logger.error(f"Smart card connection error: {e}")
            raise RuntimeError(f"Failed to connect to smart card: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during connection: {e}")
            raise

    def disconnect(self) -> None:
        """
        スマートカードから切断します。
        """
        if self._connection:
            self._connection.disconnect()
            self._connection = None
            self._reader = None
            logger.info("Disconnected from card.")

    @property
    def is_connected(self) -> bool:
        """
        カードへの接続がアクティブかどうかをチェックします。

        Returns:
            接続されている場合はTrue、そうでなければFalse。
        """
        return self._connection is not None

    @property
    def connection(self) -> Optional[CardConnection]:
        """
        生のpyscard CardConnectionオブジェクトを返します。

        Returns:
            接続されている場合はCardConnectionオブジェクト、そうでなければNone。
        """
        return self._connection

    def __enter__(self):
        """
        コンテキストマネージャーのエントリーポイント。カードに接続します。
        """
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        コンテキストマネージャーの終了ポイント。カードから切断します。
        """
        self.disconnect()

    def _transmit(self, apdu: List[int]) -> Tuple[List[int], int, int]:
        """
        APDUコマンドを送信し、基本的なエラーチェックを処理します。

        Args:
            apdu: 送信するAPDUコマンド。

        Returns:
            (data, sw1, sw2)のタプル。

        Raises:
            APDUError: 送信が失敗した場合、またはカードが非成功ステータスワードを返した場合。
            RuntimeError: カードに接続されていない場合。
        """
        if not self.connection:
            raise RuntimeError("Not connected to a card.")

        logger.debug("--> %s", " ".join(f"{b:02X}" for b in apdu))
        data, sw1, sw2 = self.connection.transmit(apdu)
        logger.debug("<-- %s (SW: %02X %02X)", " ".join(f"{b:02X}" for b in data), sw1, sw2)

        if (sw1, sw2) != SW_SUCCESS:
            # PIN検証失敗は別途処理される
            if sw1 != SW_VERIFY_FAIL_PREFIX:
                raise APDUError(f"APDU command failed: {apdu}", sw1, sw2)
        return data, sw1, sw2

    def verify_pin(self, pin: str, pin_type: str = "auth") -> int:
        """
        カードに対してPINを検証します。

        Args:
            pin: 検証するPIN。
            pin_type: 検証するPINのタイプ。'auth'、'sign'、または'attr'のいずれか。

        Returns:
            成功した検証後に残っているリトライ回数。

        Raises:
            PinVerificationError: PINが正しくない場合。
            APDUError: その他のカード通信エラーの場合。
            ValueError: 無効なpin_typeが提供された場合。
        """
        if pin_type == "auth":
            df = DF_JPKI
            ef = EF_AUTH_PIN
        elif pin_type == "sign":
            df = DF_JPKI
            ef = EF_SIGN_PIN
        elif pin_type == "attr":
            df = DF_ATTRIBUTE
            ef = EF_ATTR_PIN
        else:
            raise ValueError(f"Invalid pin_type: {pin_type}")

        # 1. DFを選択
        apdu = [CLA_ISO7816, INS_SELECT, 0x04, 0x0C, len(df)] + df
        self._transmit(apdu)

        # 2. EF（PINファイル）を選択
        apdu = [CLA_ISO7816, INS_SELECT, 0x02, 0x0C, len(ef)] + ef
        self._transmit(apdu)

        # 3. PINを検証
        pin_bytes = [ord(c) for c in pin]
        apdu = [CLA_ISO7816, INS_VERIFY, 0x00, 0x80, len(pin_bytes)] + pin_bytes

        if not self.connection:
            raise RuntimeError("Not connected to a card.")
        data, sw1, sw2 = self.connection.transmit(apdu)

        if (sw1, sw2) == SW_SUCCESS:
            return 3 # カウンターがリセットされるため、名目上の成功値。
        elif sw1 == SW_VERIFY_FAIL_PREFIX:
            raise PinVerificationError(sw1, sw2)
        else:
            raise APDUError("Unexpected error during PIN verification", sw1, sw2)

    def read_certificate(self, cert_type: str = "auth") -> x509.Certificate:
        """
        カードから証明書を読み取ります。
        ファイルが256バイトより大きい場合でも、チャンクで読み取りを処理します。
        """
        if cert_type in self._cert_cache:
            return self._cert_cache[cert_type]

        if cert_type == "auth":
            ef = EF_AUTH_CERT
        elif cert_type == "sign":
            ef = EF_SIGN_CERT
        else:
            raise ValueError(f"Invalid cert_type: {cert_type}")

        # 1. DF (JPKI) を選択
        apdu = [CLA_ISO7816, INS_SELECT, 0x04, 0x0C, len(DF_JPKI)] + DF_JPKI
        self._transmit(apdu)

        # 2. EF (証明書ファイル) を選択
        apdu = [CLA_ISO7816, INS_SELECT, 0x02, 0x0C, len(ef)] + ef
        self._transmit(apdu)

        # 3. 証明書データをチャンクで読み取る
        cert_data = bytearray()
        offset = 0
        chunk_size = 0xFF  # 255バイトが一般的な最大値

        while True:
            p1 = offset >> 8
            p2 = offset & 0xFF
            apdu = [CLA_ISO7816, INS_READ_BINARY, p1, p2, chunk_size]

            try:
                data, _, _ = self._transmit(apdu)

                if not data:
                    break  # データがなければ終了

                cert_data.extend(data)
                offset += len(data)

                # カードが要求より少ないデータを返した場合、ファイルの終端に達した
                if len(data) < chunk_size:
                    break

            except APDUError as e:
                # 6B 00 はオフセットが範囲外であることを意味し、ファイルの終端に達したことを示す
                if e.sw1 == 0x6B and e.sw2 == 0x00:
                    break
                else:
                    # その他のAPDUエラーは再発生させる
                    raise e

        if not cert_data:
            raise JPKIError("Failed to read any certificate data from the card.")

        # 4. DERエンコードされた証明書をパース
        cert = x509.load_der_x509_certificate(bytes(cert_data), default_backend())
        self._cert_cache[cert_type] = cert
        return cert

    def get_certificate_info(self, cert_type: str = "auth"):
        """
        カードから証明書を読み取り、簡略化されたデータ構造を返します。
        """
        from .certificate import JPKICertificate

        cert_obj = self.read_certificate(cert_type)
        return JPKICertificate.from_cryptography(cert_obj)

    def sign_data(self, data_to_sign: bytes, sign_type: str = "auth") -> bytes:
        """
        カード上の秘密鍵を使用して、与えられたデータのハッシュに署名します。
        """
        if sign_type == "auth":
            ef = EF_AUTH_KEY
        elif sign_type == "sign":
            ef = EF_SIGN_KEY
        else:
            raise ValueError(f"Invalid sign_type: {sign_type}")

        apdu = [CLA_ISO7816, INS_SELECT, 0x04, 0x0C, len(DF_JPKI)] + DF_JPKI
        self._transmit(apdu)

        apdu = [CLA_ISO7816, INS_SELECT, 0x02, 0x0C, len(ef)] + ef
        self._transmit(apdu)

        sha256_hash = hashlib.sha256(data_to_sign).digest()

        class AlgorithmIdentifier(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
                namedtype.OptionalNamedType('parameters', univ.Null())
            )

        class DigestInfo(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('digestAlgorithm', AlgorithmIdentifier()),
                namedtype.NamedType('digest', univ.OctetString())
            )

        alg_id = AlgorithmIdentifier()
        alg_id.setComponentByName('algorithm', OID_SHA256)
        alg_id.setComponentByName('parameters', univ.Null())

        digest_info = DigestInfo()
        digest_info.setComponentByName('digestAlgorithm', alg_id)
        digest_info.setComponentByName('digest', univ.OctetString(sha256_hash))

        der_encoded_digest_info = der_encoder.encode(digest_info)

        apdu = (
            [CLA_JPKI_SIGN, INS_COMPUTE_DIGITAL_SIGNATURE, 0x00, 0x80, len(der_encoded_digest_info)]
            + list(der_encoded_digest_info)
            + [0x00]
        )

        data, _, _ = self._transmit(apdu)
        return bytes(data)

    def read_personal_info(self):
        """
        カードから4つの基本個人属性を読み取ります。
        """
        from .personal_info import JPKIPersonalInfo

        apdu = [CLA_ISO7816, INS_SELECT, 0x04, 0x0C, len(DF_ATTRIBUTE)] + DF_ATTRIBUTE
        self._transmit(apdu)

        apdu = [CLA_ISO7816, INS_SELECT, 0x02, 0x0C, len(EF_4_BASIC_INFO)] + EF_4_BASIC_INFO
        self._transmit(apdu)

        apdu = [CLA_ISO7816, INS_READ_BINARY, 0x00, 0x00, 0x00]
        data, _, _ = self._transmit(apdu)

        return JPKIPersonalInfo.from_tlv_data(bytes(data))
