from Crypto import Random
from Crypto.Cipher import AES
import hashlib
import rsa
import os
import time

#-----------------AES----------------------------------------#
def pad(s):
    return s + b"\0"*(AES.block_size - len(s)%AES.block_size)

def encryption(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    key = hashlib.sha256(key.encode("utf-8")).digest()
    ciphertext = AES.new(key,AES.MODE_CBC,iv)
    return iv+ciphertext.encrypt(message)

def decryption(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    key = hashlib.sha256(key.encode("utf-8")).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)  # fix
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

def encrypt_file(file, key):
    with open(file, 'rb') as fo:
        plaintext = fo.read()
    enc = encryption(plaintext,key)
    with open(file+".enc", 'wb') as fo:
        fo.write(enc)
    os.remove(file)

def decrypt_file(file, key):
    with open(file, 'rb') as fo:
        ciphertext = fo.read()
    dec = decryption(ciphertext,key)
    with open(file[:-4],'wb') as fo:
        fo.write(dec)
    os.remove(file)

#-----------------DS-----------------------------------------#
def rsa_key():
    public_key, private_key = rsa.newkeys(2048)
    with open('public.key', 'wb') as key:
        key.write(public_key.save_pkcs1('PEM'))
    with open('private.key', 'wb') as key:
        key.write(private_key.save_pkcs1('PEM'))
    return private_key,public_key

def hash_SHA256(message):
    SHA256 = hashlib.sha256(message).digest()
    return SHA256

def DS_encryption(message):
    public = rsa.PublicKey.load_pkcs1(readfile("public.key"))
    hash_message = hash_SHA256(message)
    with open("hash.txt",'wb') as fs:
        fs.write(hash_message)
    return rsa.encrypt(hash_message,public)

def DS_decryption(message):
    private = rsa.PrivateKey.load_pkcs1(readfile("private.key"))
    y = rsa.decrypt(message,private).decode("latin-1")
    return y

def verify(message):
    x = open("hash.key",'rb')
    if hash_SHA256(message) == x:
        return True
    else:
        return False
#-----------------Directory----------------------------------#
def open_directory(dir):
    path = dir
    return os.chdir(path)

def readfile(file):
    text = open(file,'rb')
    text_encode = text.read()
    text.close()
    return text_encode

#-----------------PASS---------------------------------------#
def pass_save(message):
    with open("pass.txt",'wb') as fw:
        fw.write(message.encode("UTF-8"))
#-----------------RUN----------------------------------------#
while True:
    try:
        print("Select your directory that contain target file")
        print("Example: C:/USER")
        dir = input("Enter : ")
        open_directory(dir)
        if os.path.realpath:
            break
    except IOError:
        print("Error,cannot find directory.")

if os.path.isfile("pass.txt.enc"):
    iden = input(str("Enter Password: "))
    decrypt_file("pass.txt.enc",iden)
    conf = open("pass.txt").readline()
    encrypt_file("pass.txt", conf)
    if iden==conf:
        print("Second is choose your file")
        while True:
            try:
                print("Select your file")
                print("Example: Dota2_TinkerScript1.txt")
                dir = input("Enter : ")
                if os.path.isfile:
                    with open(dir,'rb') as fo:
                        key = fo.read()
                    break

            except NameError or FileNotFoundError:
                print("Error,cannot find file.")

        print('select number what you want to do')
        print('1 --> encrypt file with aes ')
        print('2 --> decrypt aes encryption file ')
        print('3 --> digital sign')
        print('4 --> verify digital signature')
        print('5 --> exit program')
        while True:
            num_select = str(input("Your Choice: "))

            if num_select == '1':
                encrypt_file(dir,iden)
                print("What you want to do next?")
            elif num_select == '2':
                if os.path.isfile(dir+".enc"):
                    decrypt_file(dir+".enc",iden)
                else:
                    decrypt_file(dir,iden)
                print("What you want to do next?")
            elif num_select == '3':
                rsa_key()
                with open(dir, 'r+') as fo:
                    text = fo.read()
                s = DS_encryption(text.encode("utf-8"))
                with open(dir, 'wb')as fo:
                    fo.write(s)
                print("What you want to do next?")
            elif num_select == '4':
                with open(dir, 'rb') as fo:
                    text = fo.read()
                    s = DS_decryption(text)
                with open(dir, 'w+') as fo:
                    fo.write(s)
            elif num_select == '5':
                print("Thank You ^^ ")
                break
            else:
                print("Error Choice")

    else:
        print("Password Incorrect")
        encrypt_file("pass.txt", conf)
        print("Closing in 3 second")
        time.sleep(3)


else:
    while True:
        px = str(input("Enter Setup Password: "))
        py = str(input("Confirm Password: "))
        if px == py:
            pass_save(px)
            with open("pass.txt",'w+') as s:
                s.write(px)
            encrypt_file("pass.txt",px)
            print("Password Created!!")
            print("Please Restart Program")
            break
        else:
            print("Password mismatch!!")