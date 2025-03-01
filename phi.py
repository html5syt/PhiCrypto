import base64
import xml.etree.ElementTree as ET
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from urllib.parse import unquote, quote

class AESCipher:
    def __init__(self, hex_key, hex_iv):
        # 将十六进制字符串转换为字节
        try:
            self.key = bytes.fromhex(hex_key)
            self.iv = bytes.fromhex(hex_iv)
        except ValueError as e:
            raise ValueError("Invalid hex string") from e

        # 验证密钥和IV长度
        if len(self.key) not in (16, 24, 32):
            raise ValueError("Invalid key length. Key must be 16/24/32 bytes (32/48/64 hex chars)")
        if len(self.iv) != 16:
            raise ValueError("Invalid IV length. IV must be 16 bytes (32 hex chars)")

    def encrypt(self, plaintext):
        if isinstance(plaintext, list):
            return [self._encrypt_single(item) for item in plaintext]
        return self._encrypt_single(plaintext)

    def _encrypt_single(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        return base64.b64encode(ciphertext).decode('utf-8')

    def decrypt(self, ciphertext):
        if isinstance(ciphertext, list):
            return [self._decrypt_single(item) for item in ciphertext]
        return self._decrypt_single(ciphertext)

    def _decrypt_single(self, ciphertext):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        decoded_data = base64.b64decode(ciphertext)
        decrypted_data = cipher.decrypt(decoded_data)
        return unpad(decrypted_data, AES.block_size).decode('utf-8')

def process_xml_file(file_path, hex_key, hex_iv, mode='auto'):
    cipher = AESCipher(hex_key, hex_iv)
    
    # 解析XML文件
    tree = ET.parse(file_path)
    root = tree.getroot()
    
    # 提取键值对
    items = root.findall('string')
    keys = [item.get('name') for item in items]
    values = [item.text for item in items]
    
    # 处理保留字段
    reserved_keys = ['unity.player_session_count', 'unity.player_sessionid']
    reserved_values = {
        k: values[keys.index(k)] if k in keys else None 
        for k in reserved_keys
    }
    
    # 过滤保留字段
    filtered = [
        (k, v) for k, v in zip(keys, values) 
        if k not in reserved_keys
    ]
    proc_keys = [k for k, _ in filtered]
    proc_values = [v for _, v in filtered]

    # 自动检测模式
    if mode == 'auto':
        mode = 'decrypt' if 'bright' in keys else 'encrypt'

    # 执行加解密
    if mode == 'encrypt':
        encrypted_keys = [quote(cipher.encrypt(k), safe='') for k in proc_keys]
        encrypted_values = [quote(cipher.encrypt(v), safe='') for v in proc_values]
        return build_xml(encrypted_keys, encrypted_values, reserved_values)
    else:
        decoded_keys = [unquote(k) for k in proc_keys]
        decoded_values = [unquote(v) for v in proc_values]
        decrypted_keys = cipher.decrypt(decoded_keys)
        decrypted_values = cipher.decrypt(decoded_values)
        return build_xml(decrypted_keys, decrypted_values, reserved_values)

def build_xml(keys, values, reserved):
    xml = ['<?xml version="1.0" encoding="utf-8" standalone="yes"?>', '<map>']
    
    # 添加处理后的条目
    for k, v in zip(keys, values):
        xml.append(f'    <string name="{escape_xml(k)}">{escape_xml(v)}</string>')
    
    # 添加保留字段
    for k in ['unity.player_session_count', 'unity.player_sessionid']:
        if reserved.get(k):
            xml.append(f'    <string name="{k}">{escape_xml(reserved[k])}</string>')
    
    xml.append('</map>')
    return '\n'.join(xml)

def escape_xml(text):
    return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

# 使用示例
if __name__ == "__main__":
    # 示例密钥和IV（需要满足长度要求）
    # 请替换为自己的密钥和IV
    hex_key = "0000000000000000000000000000000000000000000000000000000000000000"  # 64 hex chars = 32 bytes
    hex_iv = "00000000000000000000000000000000"    # 32 hex chars = 16 bytes
    
    # 处理文件
    # result_xml = process_xml_file("com.PigeonGames.Phigros.v2.playerprefs.xml", hex_key, hex_iv,mode="decrypt")

    
    # # 保存结果
    # with open("out.xml", "w", encoding="utf-8") as f:
    #     f.write(result_xml)    # 保存结果
        
        # 加密
    result_xml = process_xml_file("out.xml", hex_key, hex_iv,mode="encrypt")
    with open("com.PigeonGames.Phigros.v2.playerprefs.xml", "w", encoding="utf-8") as f:
        f.write(result_xml)    
