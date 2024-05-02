
# Ver https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode
import os


def cifraMensagem(plaintext : str, key : bytes) -> bytes:
    '''
    Criptografa uma mensagem usando o AES
    - plaintext: string com a mensagem
    - key: chave SECRETA em bytes 
    - RETORNO: mensagem cifrada em base64 (tipo bytes)
    '''
    cipher = Cipher(algorithms.AES(key), modes.ECB())     
    cifrador = cipher.encryptor()
    plainbytes = plaintext.encode()
    
    padder = padding.PKCS7(128).padder()
    plainbytes = padder.update(plainbytes) + padder.finalize()
    
    cipherbytes = cifrador.update(plainbytes) + cifrador.finalize()
    ciphertext = b64encode(cipherbytes)   
    return ciphertext


def decifraMensagem(ciphertext : bytes, key : bytes) -> str : 
    '''
    Descriptografa uma mensagem cifrada com o AES
    - ciphertext: mensagem cifrada em base64
    - key: chave SECRETA em bytes
    - RETORNO: string com a mensagem decifrada
    '''   
    cipher = Cipher(algorithms.AES(key), modes.ECB()) 
    decifrador = cipher.decryptor()
    cipherbytes = b64decode(ciphertext)

    plainbytes = decifrador.update(cipherbytes) + decifrador.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plainbytes = unpadder.update(plainbytes) + unpadder.finalize()

    plaintext = plainbytes.decode()
    return plaintext


def geraChave(tamanho : int) -> tuple[bytes, bytes] :
    '''
    Gera uma chave SECRETA para ser usada pelo AES
    - tamanho: quantidade de bits da chave (128, 192 ou 256)
    - RETORNO: tupla com dois valores: chave em bytes e a chave em base64
    '''
    embytes = int(tamanho/8)
    chave = os.urandom(embytes)
    chavePEM = b64encode(chave)
    return chave, chavePEM


# Use essa porção do código para testar as funções da biblioteca

if __name__ == "__main__":
   
    # Gera a chave secreta randômica (chave de sessão)
    chavesecreta, chavePEM = geraChave(128)
    print(f'\nChave em PEM (BASE64) com tipo {type(chavePEM)}', chavePEM, sep='\n')

    # Criptografa uma mensagem com a chave secreta
    plaintext = 'isto é um teste de qualquer tamanho'
    ciphertext = cifraMensagem(plaintext, chavesecreta)   
    print(f'\nMensagem cifrada em BASE64 com tipo {type(ciphertext)}', ciphertext, sep='\n')

    # Descriptografa uma mensagem com a chave secreta
    plaintext2 = decifraMensagem(ciphertext, chavesecreta)
    print(f'\nMensagem recuperada com tipo {type(plaintext2)}', plaintext2, sep='\n')
