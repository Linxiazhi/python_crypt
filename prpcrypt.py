# -*- coding: utf-8 -*-
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import json
import base64


# AES加密类
class AESCrypt(object):
    def __init__(self, key):
        self.key = key.encode('utf-8')
        # AES加密模式：ECB
        self.mode = AES.MODE_ECB
        # block size
        self.bs = 16
        # 加密串长度必须为16的倍数, 如果不满足, 则补齐
        self.PADDING = lambda s: s + (self.bs - len(s) % self.bs) * b'\0'

    # 加密
    def encrypt(self, data):
        data = data.encode('utf-8')
        cipher = AES.new(self.key, self.mode)
        encrypt_data = base64.b64encode(cipher.encrypt(self.PADDING(data)))
        encrypt_data = encrypt_data.decode()
        return encrypt_data

    # 解密
    def decrypt(self, encrypt_data):
        cipher = AES.new(self.key, self.mode)
        encrypt_data += (len(encrypt_data) % 4) * '='
        data = str(cipher.decrypt(base64.b64decode(encrypt_data)).rstrip(b'\0'), encoding='utf-8')
        return data


# RSA加密类
class RSACrypt(object):

    def __init__(self, key):
        self.key = RSA.importKey(key)

    @staticmethod
    def _sign_data(data_dict):
        sign_data = ''
        for key in sorted(data_dict.keys()):
            value = data_dict[key]
            if isinstance(value, dict) or isinstance(value, list):
                sign_data += json.dumps(data_dict[key], sort_keys=True)
            else:
                sign_data += str(value)
        return sign_data


# RSA公钥
class RSAPubCrypt(RSACrypt):

    # RSA公钥加密
    def encrypt(self, data, length=200):
        try:
            # 1024bit的证书用100，2048bit证书用200位
            data = data.encode('utf-8')
            cipher = PKCS1_v1_5.new(self.key)
            res = []
            for i in range(0, len(data), length):
                res.append(cipher.encrypt(data[i:i + length]))
            return str(base64.b64encode(b"".join(res)), encoding='utf-8')
        except:
            return False

    # RSA公钥验证签名
    def verify_sign(self, data, signature):
        try:
            if isinstance(data, dict):
                data = self._sign_data(data)
            data = data.encode('utf-8')
            h = SHA256.new(data)
            pkcs1_15.new(self.key).verify(h, base64.b64decode(signature))
            return True
        except (ValueError, TypeError):
            return False


# RSA私钥
class RSAPrvCrypt(RSACrypt):

    # RSA私钥解密
    def decrypt(self, encrypt_data, length=256):
        # 1024bit的证书用128，2048bit证书用256位
        try:
            cipher = PKCS1_v1_5.new(self.key)
            encrypt_data = base64.b64decode(encrypt_data)
            data = []
            for i in range(0, len(encrypt_data), length):
                data.append(cipher.decrypt(encrypt_data[i:i + length], 'xyz'))
            return str(b"".join(data), encoding='utf-8')
        except:
            return False

    # RSA私钥生成签名
    def sign(self, data):
        try:
            if isinstance(data, dict):
                data = self._sign_data(data)
            data = data.encode('utf-8')
            h = SHA256.new(data)
            signature = pkcs1_15.new(self.key).sign(h)
            return str(base64.b64encode(signature), encoding='utf-8')
        except:
            return False
