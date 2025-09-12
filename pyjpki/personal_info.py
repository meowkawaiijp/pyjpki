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

def _parse_tlv_recursive(data: bytes):
    """TLVエンコードされたデータを解析する再帰的ジェネレータ。"""
    i = 0
    while i < len(data):
        # この特定のJPKIコンテキストでは、タグは2バイトです。
        tag = data[i:i+2]
        i += 2

        if i >= len(data):
            break

        # 長さの解析（短形式と長形式の両方を処理）
        length_byte = data[i]
        i += 1
        if length_byte & 0x80:
            num_len_bytes = length_byte & 0x7F
            if i + num_len_bytes > len(data):
                break
            length = int.from_bytes(data[i:i + num_len_bytes], 'big')
            i += num_len_bytes
        else:
            length = length_byte

        if i + length > len(data):
            break

        value = data[i:i + length]

        # 4つの基本属性のコンテナタグはDF 21です。
        # 見つけた場合、その内容を再帰的に解析します。
        if tag == bytes(TAG_HEADER):
            yield from _parse_tlv_recursive(value)
        else:
            yield (tag, value)

        i += length

def _parse_tlv(data: bytes) -> Dict[bytes, bytes]:
    """
    個人属性データ構造用のTLVパーサー。
    外側のコンテナを処理し、内容には再帰的パーサーを使用します。
    """
    # 研究によると、データはFF 20 <長さ>のようなヘッダーを持つ
    # コンテナでラップされている可能性があります。
    if data.startswith(b'\xFF\x20'):
        container_len = data[2]
        tlv_payload = data[3:3 + container_len]
    else:
        # ヘッダーが存在しない場合、データがペイロードであると仮定します。
        tlv_payload = data

    return dict(_parse_tlv_recursive(tlv_payload))
