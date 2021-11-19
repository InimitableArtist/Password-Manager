from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import scrypt
import sys
import os
import base64
import json

SIG_SIZE  = SHA256.digest_size

#U save.txt: <adresa>;<password>;<salt>;<iv>

MASTER_PASSWORD_SAVE_PATH = 'master.txt'
ALL_PASSWORDS = 'save.json'

#Provjera dali je upisani password ispravan.
def verify_password(master_password):
    with open(MASTER_PASSWORD_SAVE_PATH, 'rb') as bf:
        p = bf.readlines()[0].split(b';')

    #Ako je upisani password ispravan, njegov šifrat ce biti jednak šifratu zapisanom u datoteci master.txt
    master_password = encrypt_password(master_password, master_password, p[1], p[2])
    if master_password == p[0]:
        return True
    return False

#Glavna funkcija za enkripciju.
def encrypt_password(master_password, password, salt, iv):
    key = scrypt(master_password, salt, 64, N=2**14, r = AES.block_size, p = 1)

    enc_key = key[:-SIG_SIZE]    
    mac_key = key[-SIG_SIZE:]
    
    
    
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    
    ciphertext = cipher.encrypt(pad(password, AES.block_size))
    sig = HMAC.new(mac_key, ciphertext, SHA256).digest()
    ciphertext = sig + ciphertext    
    encoded = base64.b64encode(ciphertext)
    return encoded

def encrypt_website(master_password, web_site, salt, iv):
    key = scrypt(master_password, salt, 16, N=2**14, r = AES.block_size, p = 1)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(web_site, AES.block_size))
    
    encoded = base64.b64encode(ciphertext)
    return encoded

#Glavna funkcija za dekripciju.
def decrypt_password(master_password, encoded, salt, iv):
    encoded = encoded
    ciphertext = base64.b64decode(encoded)
    key = scrypt(master_password, salt, 64, N=2**14, r = AES.block_size, p = 1)
        
    enc_key = key[:-SIG_SIZE]    
    mac_key = key[-SIG_SIZE:]

    password_cipher = ciphertext[32:]
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    sig = HMAC.new(mac_key, password_cipher, SHA256).digest()

    
    
    if sig != ciphertext[0:32]:
        print('Pogreska!')
        sys.exit()

    decrypted = cipher.decrypt(password_cipher)
    decrypted = unpad(decrypted, AES.block_size)
    return decrypted


def register(password):
    salt = os.urandom(AES.block_size)
    iv = Random.new().read(AES.block_size)
    
    
    encoded = encrypt_password(password, password, salt, iv)

    #U tekst file se zapisuje sifrirani master password, salt i iv.
    with open(MASTER_PASSWORD_SAVE_PATH, 'wb') as bf:
        bf.write(encoded)
        bf.write(b';')
        bf.write(salt)
        bf.write(b';')
        bf.write(iv)
    
    with open(MASTER_PASSWORD_SAVE_PATH, 'rb') as f:
        lines = f.readlines()
    if len(lines) > 1:
        register(password)
    else:
        print('registracija uspješno završena.')

def init(master_password):

    #Ako ništa nije zapisano u master password fileu, stvori novog korisnika.
    if not os.path.isfile(MASTER_PASSWORD_SAVE_PATH):
        register(master_password)

        if not os.path.isfile(ALL_PASSWORDS):
            with open(ALL_PASSWORDS, 'w') as f:
                f.write(json.dumps({}))

    else:
        if verify_password(master_password):
            
            print('Prijava uspješna!')
            
        else: print('Pogrešan password.')
    

def check_if_already_added(master_password, web_site, data, new_password):
    for d in data.keys():
        encrypted_website = encrypt_website(master_password, web_site, base64.b64decode(data[d][1]), base64.b64decode(data[d][2]))
        
        if encrypted_website == base64.b64decode(d):
            del data[d]

            salt = os.urandom(AES.block_size)
            iv = Random.new().read(AES.block_size)

            encrypted_website = encrypt_website(master_password, web_site, salt, iv)
            encrypted_password = encrypt_password(master_password, new_password, salt, iv)

            data[base64.b64encode(encrypted_website).decode('utf-8')] = [base64.b64encode(encrypted_password).decode('utf-8'), 
            base64.b64encode(salt).decode('utf-8'), base64.b64encode(iv).decode('utf-8')]
            
            return data
    
    return False

        
def put(master_password, web_site, web_site_password):
    if verify_password(master_password):
        salt = os.urandom(AES.block_size)
        iv = Random.new().read(AES.block_size)

        encoded = encrypt_password(master_password, web_site_password, salt, iv)
        encoded_address = encrypt_website(master_password, web_site, salt, iv)

        json_k = [base64.b64encode(encoded_address).decode('utf-8')]
        json_v = [[base64.b64encode(encoded).decode('utf-8'), base64.b64encode(salt).decode('utf-8'), base64.b64encode(iv).decode('utf-8')]]
        
        #result = json.dumps(dict(zip(json_k, json_v)))
        result = dict(zip(json_k, json_v))
        with open(ALL_PASSWORDS) as bf: 
            data = json.load(bf)
    
        chk = check_if_already_added(master_password, web_site, data, web_site_password)
        if chk:
            print('password promijenjen.')
            data = chk
            #data[chk] = [base64.b64encode(encoded).decode('utf-8'), base64.b64encode(salt).decode('utf-8'), base64.b64encode(iv).decode('utf-8')]
                
        else:
            data.update(result)
            print('Password za: ' + str(web_site) + ' dodan.')


        with open(ALL_PASSWORDS, 'w') as f:
            json.dump(data, f, indent = 4)

    else: print('Pogresan master password.')

def get(master_password, web_site):
    if verify_password(master_password):
        with open(ALL_PASSWORDS, 'r') as of:
            json_object = json.load(of)
        for p in json_object.keys():
            
            web_site_encoded = encrypt_website(master_password, web_site, base64.b64decode(json_object[p][1]), 
            base64.b64decode(json_object[p][2]))

            if web_site_encoded == base64.b64decode(p):
                decrypted_password = decrypt_password(master_password, base64.b64decode(json_object[p][0]), 
                base64.b64decode(json_object[p][1]), base64.b64decode(json_object[p][2]))
            
                print('Password for ' + str(web_site) + ' is: ' + str(decrypted_password))
                return
        print('Password nije pronađen.')
                
        
def main():

    if sys.argv[1] == 'init':
        init(bytes(sys.argv[2], 'utf-8'))
    elif sys.argv[1] == 'put':
        put(bytes(sys.argv[2], 'utf-8'), bytes(sys.argv[3], 'utf-8'), bytes(sys.argv[4], 'utf-8'))
    elif sys.argv[1] == 'get':
        get(bytes(sys.argv[2], 'utf-8'), bytes(sys.argv[3], 'utf-8'))
    else:
        print('Neispravno korištenje.')

if __name__ == '__main__':
    main()