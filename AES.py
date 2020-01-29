from Crypto import Random
from Crypto.Cipher import AES
import hashlib
import rsa
import os

#-----------------AES----------------------------------------#
def pad(s):
    return s + b"\0"*(AES.block_size - len(s)%AES.block_size)

def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key,AES.MODE_CBC,iv) #fix
    return iv+cipher.encrypt()

def decrypt(cipher, key):
    iv = cipher.decrypt[:AES.block_size]
    cipher = AES.new(key,AES.MODE_CBC,iv) #fix
    plain = cipher.decrypt(cipher[AES.block_size:])
    return plain.rstrip(b"\0")

def encrypt_file(file, key):
    with open(file, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt(plaintext,key)
    with open(file+".enc", 'wb') as fo:
        fo.write()

def decrypt_file(file, key):
    with open(file, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext,key)
    with open(file[:-4],'wb') as fo:
        fo.write()

#-----------------DS-----------------------------------------#
def rsa_key():
    public_key, private_key = rsa.newkeys(2048)
    with open('public_key', 'wb') as key:
        key.write(public_key.save_pkcs1('PEM'))
    with open('private_key', 'wb') as key:
        key.write(private_key.save_pkcs1('PEM'))
    return private_key,public_key

def hash_SHA256(message):
    SHA256 = hashlib.sha256(message.encode("UTF-8")).hexdigest()
    return SHA256

def sign(message):
    rsa_private,rsa_public = rsa_key()
    signature = rsa.sign(message.encode("UTF-8"),rsa_private,'SHA-256')
    return signature

#-----------------FO-----------------------------------------#
def open_directory(dir):
    path = dir
    return os.chdir(path)

#-----------------PASS---------------------------------------#
def pass_save(message):
    with open("pass.txt",'wb') as fw:
        fw.write(message.encode("UTF-8"))

def pass_load():
    with open("pass.txt",'wb') as fr:
        x = fr.read().decode("UTF-8")
    return x

if os.path.isfile("passt.txt"):
    p = pass_load()
    scare = encrypt(p,hash_SHA256(p))
    signature = sign(scare)

else:
    while True:
        try:
            print("Select your directory by copying path")
            print("Example: C:/USER")
            dir = input("Enter : ")
            open_directory(dir)
            if os.path.realpath:
                break
        except IOError:
            print("Error,cannot find directory.")

    while True:
        try:
            print("Select your file")
            print("Example: Dota2_TinkerScript1.txt")
            dir = input("Enter : ")
            read_file(dir)
            if os.path.isfile:
                pass_save(dir)
                break

        except NameError or NotADirectoryError:
            print("Error,cannot find file.")
    print("------------------------")
    print("#Please Restart Program#")
    print("------------------------")
