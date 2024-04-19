from Cryptodome.Cipher import AES, PKCS1_OAEP 
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from io import BytesIO
import base64
import zlib
import getopt, sys

# generate RSA's public and private keys
def generate():
    new_key = RSA.generate(2048)
    private_key = new_key.exportKey()
    public_key = new_key.publickey().exportKey()

    with open('key.pri','wb') as f:
        f.write(private_key)

    with open('key.pub','wb') as f:
        f.write(public_key) 

#grab key.pri or key.pub
def get_rsa_cipher(keytype):
    with open(f'key.{keytype}') as f :
        key=f.read()
    rsakey = RSA.importKey(key)
    return (PKCS1_OAEP.new(rsakey), rsakey.size_in_bytes())

def encrypt(plaintext):
    #compress textfile
    compressed_text = zlib.compress(plaintext)

    session_key = get_random_bytes(16)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag =cipher_aes.encrypt_and_digest(compressed_text)

    cipher_rsa , _  = get_rsa_cipher('pub')
    encrypted_session_key = cipher_rsa.encrypt(session_key)

    msg_payload= encrypted_session_key + cipher_aes.nonce + tag + ciphertext
    encrypted = base64.encodebytes(msg_payload)
    return(encrypted)

def decrypt(encrypted):
    encrypted_bytes=BytesIO(base64.decodebytes(encrypted))
    cipher_rsa, keysize_in_bytes = get_rsa_cipher('pri')

    encrypted_session_key=encrypted_bytes.read(keysize_in_bytes)
    nonce = encrypted_bytes.read(16)
    tag= encrypted_bytes.read(16)
    ciphertext = encrypted_bytes.read()

    session_key = cipher_rsa.decrypt(encrypted_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX,nonce)
    decrypted=cipher_aes.decrypt_and_verify(ciphertext,tag)

    plaintext = zlib.decompress(decrypted)
    return plaintext
 
argumentList = sys.argv[1:]
# Options
options = "ged"
# Long options
long_options = ["generate", "encode", "decrypt="]
 
try:
    # Parsing argument
    arguments, values = getopt.getopt(argumentList, options, long_options)
     
    # checking each argument
    for currentArgument, currentValue in arguments:
 
        if currentArgument in ("-g", "--generate"):#-----------------------------------generate key------------------------------------------
            print ("Generating Keys")
            generate()
             
        elif currentArgument in ("-e", "--encode"): #-----------------------------------encode------------------------------------------
            print ("encoding....")

            text= input("enter yout text :")
            encrptedText= encrypt(bytes(text,'utf-8'))
            print(type(encrptedText))
            print(encrptedText)
            with open('encryptedTEXT','wb') as f:
                f.write(encrptedText)

            print("--- Done ! ---")


        elif currentArgument in ("-d", "--decrypt"): #------------------------------------decrypt-----------------------
            print("decrypting ... " )
            encryptedFile= input("enter encrypted File's name : ")
            
            with open(f'{encryptedFile}', mode="rb") as f :
                code=f.read()
           
            plainText=decrypt(code)
            print(plainText)
            with open('decryptedFile','wb') as f:
                f.write(plainText)
             

except getopt.error as err:
    # output error, and return with an error code
    print (str(err))

