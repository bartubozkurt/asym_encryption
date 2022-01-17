import os,base64
import time
import sys
from Crypto import Signature
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import binascii
from termcolor import colored, cprint
from cryptography.fernet import Fernet

# Bartu BOZKURT - 2017280013 - Computer Science


'''
    __SOURCES__
1) https://pycryptodome.readthedocs.io/en/latest/src/installation.html
2) https://pypi.org/project/crypto/
3) https://pypi.org/project/termcolor/
4) https://www.ascii-art-generator.org/
5) https://www.youtube.com/watch?v=4zahvcJ9glg
6) https://www.youtube.com/watch?v=oOcTVTpUsPQ
7) https://www.programiz.com/python-programming/file-operation
8)https://stackoverflow.com/questions/3603714/asymmetric-encryption
9)https://piraveenaparalogarajah.medium.com/understanding-encryption-signing-and-verification-fc256f6b763b
10)https://tr.wikipedia.org/wiki/RSA_(%C5%9Fifreleme_y%C3%B6netimi)
11)https://tr.wikipedia.org/wiki/SHA-2
'''

def key_pair_gen():
    # RSA 2048 public \ private key çifti oluşturdum
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()

    print('\npublic\private RSA Anahtar çifti Oluşturuluyor . . . . . ')
    # bunları public.pub | private.pub adında dosyalara ayrı ayrı yazdırdım.
    with open('public_key.pub', 'wb') as pb_key: 
        pb_key.write(public_key.export_key())

    with open('private_key.pub', 'wb') as pv_key:
        pv_key.write(private_key.export_key())

    print('public\private Anahtar çifti başarıyla oluşturuldu.\n')


def encryption(): #Şifreleme(encryption)
    print('\n[+] Dosya Konumu Giriniz: ')
    file_location = input('> ')
    filename, file_extension = os.path.splitext(file_location)

    # verilen dosya konumundaki verileri okuyup ve kaydettim.
    try:
        in_file = open(file_location, "rb")
        data = in_file.read()
        in_file.close()
    except FileNotFoundError as fnf_error:
        print('\n')
        sys.exit(fnf_error)

    print('\n[+] Public key in konumunu giriniz: ')
    pub_key_location = input('> ')

    # alıcını public keyini okudum.
    try:
        key_in = open(pub_key_location, "rb")
        public_key = RSA.import_key(key_in.read())
        key_in.close()
    except FileNotFoundError as fnf_error:
        print('\n')
        sys.exit(fnf_error)

    # 16 bit'lik random key oluşturdum
    key = get_random_bytes(16)
    # bu keyle public keyi encrypte ettim.
    key_cipher = PKCS1_OAEP.new(key=public_key)
    key_encrypted = key_cipher.encrypt(key)

    try:
        # GCM modunu kullanarak anahtarla şifrelenmiş bir AES şifreleme nesnesi oluşturdum.
        cipher = AES.new(key, AES.MODE_GCM)
        nonce = cipher.nonce

        # encrypte sonucu çıktı dosyasının başlığını ayarladım.
        output_file = filename + '_encrypted' + file_extension
        file_out = open(output_file, "wb")
        print('\nÇıktı, dosyasına yazılıyor . . . . . . . .')
        file_out.write(key_encrypted)
        file_out.write(nonce)
        file_out.write(get_random_bytes(16))

        print('\nŞifreleniyor . . . . . . . . . . . . . . . .\n')
        start_time = time.time()
        ciphertext = cipher.encrypt(data)
        print("\n[+] Dosya Başarı ile %s saniye de şifrelendi.\n" % (time.time() - start_time))

        # çıktı dosyasına encrypte edilmiş datayı yazdım.
        print('Şifrelenmiş veri dosyaya yazılıyor . . . .')
        file_out.write(ciphertext)

        # MAC etiketi oluşturdum ve onu şifreli metnin başına ve sonuna ekledim.
        file_out.seek(272)  
        tag = cipher.digest()
        file_out.write(tag)
        file_out.close()
    
    except ValueError:
        sys.exit('\n[!] Dosya şifrelenirken bir hata oluştu.\n')


def decryption():
    print('\n[+]  Dosya Konumu Giriniz: ')
    input_file = input('> ')
    filename, file_extension = os.path.splitext(input_file)
    file_name_orig = str(filename).replace('_encrypted', '')
    print('\n[+] Private key konumunu giriniz: ')
    key_location = input('> ')

    # verilen dosya konumundaki verileri okuyup ve kaydettim.
    try:
        key_in = open(key_location, 'rb')
        private_key = RSA.import_key(key_in.read())
        key_in.close()
    except FileNotFoundError as fnf_error:
        print('\n')
        sys.exit(fnf_error)

    key_cipher = PKCS1_OAEP.new(key=private_key)

    # Encrypte edilmiş dosyadaki verileri okuyup kaydettim.
    print('Şifrelenmiş dosya okunuyor. . . . . . . .')
    try:
        file_in = open(input_file, 'rb')
        key = key_cipher.decrypt(file_in.read(256))
        nonce = file_in.read(16)
        tag = file_in.read(16)
        ciphered_data = file_in.read()
        file_in.close()
    except FileNotFoundError as fnf_error:
        print('\n')
        sys.exit(fnf_error)

    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        print('\nŞifre Çözülüyor . . . . . . . . . . . . . . . .\n')
        start_time = time.time()
        original_data = cipher.decrypt(ciphered_data)
        print("\n[+] Dosya başarı ile  %s saniyede Deşifre edildi.\n" % (time.time() - start_time))

        # şifresi çözülen verilerin geçerli olup olmadığını kontrol ettim.
        print('Deşifre edilen veriler doğrulanıyor. . . . . . . . .')
        cipher.verify(tag)

    except ValueError as val_error:
        sys.exit('\n[!] Dosya deşifre edilirken bir hata oluştu!\n')

    # decrypte edilmiş data için çıktı dosyası ayarladım ve içine dataları yazdım.
    try:
        print('Deşifre edilen veriler dosyaya yazılıyor. . . .\n')
        output_file = file_name_orig + '_decrypted' + file_extension
        output_file = open(output_file, "wb")
        output_file.write(original_data)
        output_file. close()
    except AssertionError as error:
        sys.exit('\n[!] Veriler dosyaya yazılırken bir hata oluştu file\n')

def sign():
    filename = 'info.txt'
    file = open(filename,'rb')
    message = file.read()

    # PKCS1_15 imza şemasını kullanarak mesajı imzaladım.

    key = RSA.import_key(open('private_key.pub').read())
    h = SHA256.new(message)

    signer = pkcs1_15.new(key)
    signature = signer.sign(h)
    print(signature.hex())

    # daha sonra bu imzayı bir dosyaya yazdım.

    file_out = open('signature.pub','wb')
    file_out.write(signature)
    file_out.close()

    file_out = open(filename,'wb')
    file_out.write(message)
    file_out.close()

def verify():
    key = RSA.import_key(open('public_key.pub').read())

    filename = 'info.txt'

    file_in = open(filename,'rb')
    message = file_in.read()
    file_in.close()

    # İmzanın geçerli olup olmadığını PKCS1_15 imza şemasını kullanarak test ettim.

    file_in = open('signature.pub','rb')
    signature = file_in.read()
    file_in.close()
    h =  SHA256.new(message)

    try:
        pkcs1_15.new(key).verify(h, signature)
        print('İmza geçerli !')
    except (ValueError, TypeError):
        print('İmza geçerli değil !')

def header():
    header_menu= ("""
 __  __ _____ _   _ _   _ 
|  \/  | ____| \ | | | | |
| |\/| |  _| |  \| | | | |
| |  | | |___| |\  | |_| |
|_|  |_|_____|_| \_|\___/    
                            by Bartu Bozkurt, 2021
----------------------------------------------------
    """)
    cprint(header_menu,color='green',attrs=['bold'])

def menu_options():
    print('[+] Aşağıdaki menüden seçiminizi yapınız')
    print('1) Anahtar üretimi için [K] ye basın')
    print('2) Dosya Şifreleme için [E] ye basın')
    print('3) Dosya Deşifreleme için [D] ye basın')
    print('4) Dosya imzalamak için [S] ye basın')
    print('5) Dosya Doğrulama için [V] ye Basın')
    print('6) Çıkış için [Q] ya basın')
    print('--------------------------------')
    print('*(büyük-küçük harf duyarlıdır)*')

def menu():
    menu_options()

    while 1:
        print('\n[+] Seçiminizi Giriniz: ')
        option = input('> ')
        if (option == 'K') or (option == 'k'):

            logo_key = '''
_  __              ____                           _             
| |/ /___ _   _   / ___| ___ _ __   ___ _ __ __ _| |_ ___  _ __ 
| ' // _ \ | | | | |  _ / _ \ '_ \ / _ \ '__/ _` | __/ _ \| '__|
| . \  __/ |_| | | |_| |  __/ | | |  __/ | | (_| | || (_) | |   
|_|\_\___|\__, |  \____|\___|_| |_|\___|_|  \__,_|\__\___/|_|   
          |___/                                                                
                                by Bartu Bozkurt, 2021
------------------------------------------------------'''
            cprint(logo_key,color='green',attrs=['bold'])

            key_pair_gen()
        elif (option == 'E') or (option == 'e'):
            
            logo_dec = '''

 _____                             _   _             
| ____|_ __   ___ _ __ _   _ _ __ | |_(_) ___  _ __  
|  _| | '_ \ / __| '__| | | | '_ \| __| |/ _ \| '_ \ 
| |___| | | | (__| |  | |_| | |_) | |_| | (_) | | | |
|_____|_| |_|\___|_|   \__, | .__/ \__|_|\___/|_| |_|
                       |___/|_|                                      
                                by Bartu Bozkurt, 2021
------------------------------------------------------'''

            cprint(logo_dec,color='green',attrs=['bold'])

            encryption()
        elif (option == 'D') or (option == 'd'):
            logo_enc = '''      
 ____                             _   _             
|  _ \  ___  ___ _ __ _   _ _ __ | |_(_) ___  _ __  
| | | |/ _ \/ __| '__| | | | '_ \| __| |/ _ \| '_ \ 
| |_| |  __/ (__| |  | |_| | |_) | |_| | (_) | | | |
|____/ \___|\___|_|   \__, | .__/ \__|_|\___/|_| |_|
                      |___/|_|                                  
                                by Bartu Bozkurt, 2021
------------------------------------------------------'''
                  
            cprint(logo_enc,color='green',attrs=['bold'])
            
            decryption()
        elif (option == 'S') or (option == 's'):

            logo_sign = '''      
 ____  _             
/ ___|(_) __ _ _ __ 
\___ \| |/ _` | '_ \ 
 ___) | | (_| | | | |
|____/|_|\__, |_| |_|
         |___/           
                            by Bartu Bozkurt, 2021
------------------------------------------------------'''
            cprint(logo_sign,color='green',attrs=['bold'])

            sign()
        elif (option == 'V') or (option == 'v'):

            logo_verify = '''      
__     __        _  __       
\ \   / /__ _ __(_)/ _|_   _ 
 \ \ / / _ \ '__| | |_| | | |
  \ V /  __/ |  | |  _| |_| |
   \_/ \___|_|  |_|_|  \__, |
                       |___/     
                            by Bartu Bozkurt, 2021
------------------------------------------------------'''

            cprint(logo_verify,color='green',attrs=['bold'])
            
            verify()
        elif (option == 'Q') or (option == 'q'):
            sys.exit('Güle Güle :)\n')

        else:
            print('\n[!] Geçersiz Giriş\n')
print('------------------------------------------------')

        

def main():
    header()
    menu()

if __name__ == '__main__':
    main()
