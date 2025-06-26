```markdown
#### USERNAME:Harry_Attempt
# Cryptohack Solutions

## INTRODUCTION
### 1. Finding Flags
```python
flag = "crypto{y0ur_f1rst_fl4g}"
print(flag)
```

### 2. Great Snakes
```python
flag = "crypto{z3n_0f_pyth0n}"
print(flag)
```

### 3. Network Attacks
```python
import socket
import json

def network_attack_no_pwntools():
    host = "socket.cryptohack.org"
    port = 11112
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    data = {"buy": "flag"}
    s.send(json.dumps(data).encode())
    response = s.recv(1024)
    print(response.decode())
    s.close()
network_attack_no_pwntools()
```

## GENERAL
### ENCODING
#### ASCII
```python
def ascii_challenge():
    return "".join([chr(x) for x in [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]])
```

#### Hex
```python
def hex_challenge():
    hex_str = "63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d"
    return bytes.fromhex(hex_str).decode()
```

#### Base64
```python
import base64
def base64_challenge():
    hex_str = "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"
    bytes_data = bytes.fromhex(hex_str)
    return base64.b64encode(bytes_data).decode()
```

#### Bytes and Big Integers
```python
from Crypto.Util.number import long_to_bytes
def bytes_bigint_challenge():
    big_int = 11515195063862318899931685488813747395775516287289682636499965282714637259206269
    return long_to_bytes(big_int).decode()
```

#### Encoding Challenge
```python
from pwn import remote
from json import loads, dumps
from base64 import b64decode
from codecs import encode
from Crypto.Util.number import long_to_bytes

io = remote('socket.cryptohack.org', 13377)
while 'flag' not in (encoded := loads(io.recvline().decode())):
    io.sendline(dumps({"decoded": {
        'base64': lambda e: b64decode(e).decode(),
        'hex': lambda e: bytes.fromhex(e).decode(),
        'rot13': lambda e: encode(e, 'rot_13'),
        'bigint': lambda e: long_to_bytes(int(e, 16)).decode(),
        'utf-8': lambda e: ''.join([chr(c) for c in e])
    }[encoded['type']](encoded['encoded'])}))
print(encoded['flag'])
```

### XOR
#### XOR Starter
```python
def xor_starter():
    s = "label"
    xor_key = 13
    return "".join([chr(ord(c) ^ xor_key) for c in s])
```

#### XOR Properties
```python
from pwn import xor
def xor_properties():
    key1 = bytes.fromhex("a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313")
    key2_key1 = bytes.fromhex("37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e")
    key2 = xor(key1, key2_key1)
    key3_key2 = bytes.fromhex("c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1")
    key3 = xor(key2, key3_key2)
    flag_key1_key2_key3 = bytes.fromhex("04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf")
    return xor(key1, key2, key3, flag_key1_key2_key3).decode()
```

#### Favourite byte
```python
def favourite_byte():
    encrypted = bytes.fromhex("73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d")
    for byte in range(256):
        decrypted = bytes([b ^ byte for b in encrypted])
        if decrypted.startswith(b"crypto"):
            return decrypted.decode()
```

#### You either know, XOR you don't
```python
from pwn import xor
enc = bytes.fromhex('0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104')
key = xor(enc[:7], 'crypto{') + xor(enc[-1], '}')
print(xor(enc, key))
```

#### Lemur XOR
```python
from PIL import Image
lemur = Image.open("lemur.png")
flag = Image.open("flag.png")
result = Image.new("RGB", lemur.size)
for x in range(lemur.width):
    for y in range(lemur.height):
        l = lemur.getpixel((x, y))
        f = flag.getpixel((x, y))
        result.putpixel((x, y), tuple([l[i] ^ f[i] for i in range(3)]))
result.save("result.png")
```

### MATHEMATICS
#### Greatest Common Divisor
```python
import math
def gcd_challenge():
    a = 66528
    b = 52920
    return math.gcd(a, b)
```

#### Extended GCD
```python
def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)
def extended_gcd_challenge():
    p = 26513
    q = 32321
    g, u, v = extended_gcd(p, q)
    return min(u, v)
```

#### Modular Arithmetic 1
```python
x = 11 % 6
y = 8146798528947 % 17
print(min(x, y))
```

#### Modular Arithmetic 2
```python
print(pow(3, 17, 17))
print(pow(5, 17, 17))
print(pow(7, 16, 17))
print(pow(273246787654, 65536, 65537))
```

#### Modular Inverting
```python
print(pow(3, 11, 13))
```

## SYMMETRIC CIPHERS
### HOW AES WORKS
#### Keyed Permutations
```python
def keyed_permutations():
    return "crypto{bijection}"
```

#### Resisting Bruteforce
```python
def resisting_bruteforce():
    return "crypto{biclique}"
```

#### Structure of AES
```python
def bytes2matrix(text):
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]
def matrix2bytes(matrix):
    return bytes(sum(matrix, []))
matrix = [
    [99, 114, 121, 112],
    [116, 111, 123, 105],
    [110, 109, 97, 116],
    [114, 105, 120, 125],
]
print(str(matrix2bytes(matrix).decode('utf-8')))
```

## RSA
### STARTER
#### RSA Starter 1
```python
def rsa_starter_1():
    return pow(101, 17, 22663)
```

#### RSA Starter 2
```python
def rsa_starter_2():
    e = 65537
    p = 17
    q = 23
    N = p * q
    return pow(12, e, N)
```

#### RSA Starter 3
```python
def rsa_starter_3():
    p = 857504083339712752489993810777
    q = 1029224947942998075080348647219
    return (p - 1) * (q - 1)
```

#### RSA Starter 4
```python
def rsa_starter_4():
    e = 65537
    p = 857504083339712752489993810777
    q = 1029224947942998075080348647219
    phi = (p - 1) * (q - 1)
    return pow(e, -1, phi)
```

#### RSA Starter 5
```python
def rsa_starter_5():
    N = 882564595536224140639625987659416029426239230804614613279163
    e = 65537
    c = 77578995801157823671636298847186723593814843845525223303932
    p = 857504083339712752489993810777
    q = 1029224947942998075080348647219
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return pow(c, d, N)
```

#### RSA Starter 6
```python
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long
N = 15216583654836731327639981224133918855895948374072384050848479908982286890731769486609085918857664046075375253168955058743185664390273058074450390236774324903305663479046566232967297765731625328029814055635316002591227570271271445226094919864475407884459980489638001092788574811554149774028950310695112688723853763743238753349782508121985338746755237819373178699343135091783992299561827389745132880022259873387524273298850340648779897909381979714026837172003953221052431217940632552930880000919436507245150726543040714721553361063311954285289857582079880295199632757829525723874753306371990452491305564061051059885803
d = 11175901210643014262548222473449533091378848269490518850474399681690547281665059317155831692300453197335735728459259392366823302405685389586883670043744683993709123180805154631088513521456979317628012721881537154107239389466063136007337120599915456659758559300673444689263854921332185562706707573660658164991098457874495054854491474065039621922972671588299315846306069845169959451250821044417886630346229021305410340100401530146135418806544340908355106582089082980533651095594192031411679866134256418292249592135441145384466261279428795408721990564658703903787956958168449841491667690491585550160457893350536334242689
hash = SHA256.new(data=b'crypto{Immut4ble_m3ssag1ng}')
S = pow(bytes_to_long(hash.digest()), d, N)
print(hex(S)[2:])
```

### PUBLIC EXPONENT
#### Salty
```python
from Crypto.Util.number import long_to_bytes
ct = 44981230718212183604274785925793145442655465025264554046028251311164494127485
print(long_to_bytes(ct))
```
