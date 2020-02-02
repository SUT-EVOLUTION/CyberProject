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
    SHA256 = hashlib.sha256(message.encode("UTF-8")).hexdigest()
    return SHA256

def sign(message):
    rsa_private,rsa_public = rsa_key()
    signature = rsa.sign(message.encode("utf-8"),rsa_private,'SHA-256')
    return signature

def verify(message,signature):
    k = open("public.key",'rb').read()
    public = rsa.PublicKey.load_pkcs1(k)
    message = message.encode("utf-8")
    try:
        w = rsa.verify(message,signature,public)
        print("Successfull Verification")
    except:
        print("Failed Verification")
#-----------------Directory----------------------------------#
def open_directory(dir):
    path = dir
    return os.chdir(path)

#-----------------PASS---------------------------------------#
def pass_save(message):
    with open("pass.txt",'wb') as fw:
        fw.write(message.encode("UTF-8"))
#-----------------RUN----------------------------------------#
if os.path.isfile("pass.txt.enc"):
    iden = input(str("Enter Password: "))
    decrypt_file("pass.txt.enc",iden)
    conf = open("pass.txt").readline()
    if iden==conf:
        print("First thing please choose directory of file")
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
            num_select = input(str("your choice: "))

            if num_select == '1':
                message_file = open(dir).readline()
                encrypt_file(dir,iden)
                print("What you want to do next?")
            elif num_select == '2':
                if os.path.isfile(dir+".enc"):
                    decrypt_file(dir+".enc",iden)
                else:
                    decrypt_file(dir,iden)
                print("What you want to do next?")
            elif num_select == '3':
                text = open(dir).read()
                s = sign(text)
                with open('signed.txt', 'wb')as fo:
                    fo.write(s)
                print("What you want to do next?")
            elif num_select == '4':
                x = open(dir).read()
                z = open('signed.txt', 'rb').read()
                verify(x, z)
                print("What you want to do next?")
            elif num_select == '5':
                print("Thank You ^^ ")
                encrypt_file("pass.txt",iden)
                if os.path.isfile("message_v.txt"):
                    encrypt_file("message_v.txt", iden)
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

