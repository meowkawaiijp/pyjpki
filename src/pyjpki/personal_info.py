"""
このモジュールは、解析された個人情報を保持するためのデータ構造を定義します。
"""
from dataclasses import dataclass
from typing import Dict, List

# 4つの基本属性用のタグ
TAG_HEADER = [0xDF, 0x21]
TAG_NAME = [0xDF, 0x22]
TAG_ADDRESS = [0xDF, 0x23]
TAG_BIRTH_DATE = [0xDF, 0x24]
TAG_GENDER = [0xDF, 0x25]

@dataclass
class JPKIPersonalInfo:
    """
    カードから読み取った4つの基本個人属性を保持するデータクラス。
    """
    name: str
    address: str
    birth_date: str
    gender: str

    @classmethod
    def from_tlv_data(cls, tlv_data: bytes):
        """
        TLVエンコードされたデータを解析してJPKIPersonalInfoインスタンスを作成します。
        """
        parsed_tags = _parse_tlv(tlv_data)

        name = parsed_tags.get(bytes(TAG_NAME), b'').decode('utf-8', errors='ignore')
        address = parsed_tags.get(bytes(TAG_ADDRESS), b'').decode('utf-8', errors='ignore')
        birth_date = parsed_tags.get(bytes(TAG_BIRTH_DATE), b'').decode('utf-8', errors='ignore')

        gender_byte = parsed_tags.get(bytes(TAG_GENDER), b'\x33') # デフォルトは'Other'
        if gender_byte == b'\x31':
            gender = 'Male'
        elif gender_byte == b'\x32':
            gender = 'Female'
        else:
            gender = 'Other'

        return cls(
            name=name,
            address=address,
            birth_date=birth_date,
            gender=gender,
        )

def _parse_tlv(data: bytes) -> Dict[bytes, bytes]:
    """
    個人属性データ構造用のシンプルなTLVパーサー。
    """
    parsed_data = {}
    i = 0
    # コンテナヘッダー（FF 20）と長さをスキップ
    # 調査に基づくと、実際のデータは最初の数バイト後に開始されます。
    # 一般的なパターンは `FF 20 <length> DF 21 ...` のようなヘッダーです。
    # 最初のタグ（DF 21）を見つけましょう
    try:
        header_start = data.index(bytes(TAG_HEADER))
        i = header_start
    except ValueError:
        # ヘッダータグが見つからない場合、解析できません。
        return {}

    while i < len(data):
        # タグは1バイトまたは2バイト。この特定のデータでは2バイト（例：DF 21）
        tag = data[i:i+2]
        i += 2

        # 長さは1バイトまたは2バイト
        if data[i] & 0x80: # 長形式
            len_bytes = data[i] & 0x7F
            length = int.from_bytes(data[i+1:i+1+len_bytes], 'big')
            i += 1 + len_bytes
        else: # 短形式
            length = data[i]
            i += 1

        value = data[i:i+length]
        parsed_data[tag] = value
        i += length

    return parsed_data
