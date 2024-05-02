# ver RSA: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/


from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
from base64 import b64encode, b64decode


def geraChavePrivada(tamanho : int, arquivo : str = None) -> tuple[object, bytes]:
    '''
    Gera a chave privada e salva (opcionalmente) em arquivo se o nome for fornecido
    - tamanho: quantidade de bits da chave privada (1024, 2048 ou superior)
    - arquivo (opcional): nome do arquivo onde a chave privada será salva (usar a extensão .pem)
    - RETORNO: tupla com dois valores: chave privada como objeto e como base64
    '''

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=tamanho,
    )

    if arquivo is not None:
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
            )
        with open(arquivo, "wb") as key_file:
            key_file.write(private_pem)
        
    return private_key, private_pem

def geraChavePublica(private_key : object, arquivo : str = None) -> tuple[object, bytes]:
    '''
    Calcula (extrai) a chave pública a partir da chave privada e salva (opcionalmente) em arquivo se o nome for fornecido
    - private_key: chave privada como objeto 
    - arquivo (opcional): nome do arquivo onde a chave pública será salva (usar a extensão .pem)
    - RETORNO: tupla com dois valores: chave pública como objeto e como base64
    '''
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    if arquivo is not None:
        with open(arquivo, "wb") as key_file:
            key_file.write(public_pem)

    return public_key, public_pem

 
def carregaChavePrivada(arquivo : str) -> object :
    '''
    Carrega a chave privada a partir de um arquivo (a chave não deve ser gerada a cada vez que o algoritmo é executado)
    - arquivo: nome do arquivo com a chave privada (deve estar na mesma pasta que o script)
    - RETORNO: objeto com a chave privada
    '''
    with open(arquivo, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    return private_key

def converteChavePublica(public_pem : bytes) -> object:
    '''
    Converte a chave pública do formato PEM (quando é recebida pela rede) para objeto 
    - public_pem: chave pública em formato PEM (base64)
    - RETORNO: objeto com a chave publica
    '''
    public_key = serialization.load_pem_public_key(public_pem)
    return public_key


def cifraComPublica(plaintext : str | bytes, public_key : object) -> bytes:
    '''
    - Cifra uma string ou bytes usando a chave pública.
    - plaintext: dados que serão cifrados, fornecidos como string ou como bytes
    - public_key: chave pública no formato de objeto
    - RETORNO: dados cifrados como base64
    '''

    plainbytes = plaintext.encode() if type(plaintext) == str else plaintext
    
    cipherbytes = public_key.encrypt(
        plainbytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    ciphertext = b64encode(cipherbytes)

    return ciphertext

def decifraComPrivada(ciphertext : bytes, private_key : object, text : bool =True) -> str | bytes:
    '''
    Decifra dados criptografados com a chave pública, usando a chave privada correspondente.
    - ciphertext: dados criptografados com a chave pública em formato base64
    - private_key: chave privada no formato de objeto
    - text: controla se os dados serão retornados como string (True, default) ou como bytes (False)
    - RETORNO: dados cifrados como string ou bytes de acordo com o parâmetro text
    '''

    cipherbytes = b64decode(ciphertext)
    plainbytes = private_key.decrypt(
        cipherbytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


    plaintext = plainbytes.decode() if text else plainbytes

    return plaintext


# Use essa porção do código para testar as funções da biblioteca

if __name__ == "__main__":

    # As chaves serão salvas nesta pasta
    print("Diretorio:", os.getcwd(), '\n')

    # Obj são estruturas usadas pelo algoritmo em Python, PEM são chaves transportáveis (serializadas) em formato base64
    # Observe que o formato PEM é um formato padrão independente da linguagem, mas Obj é um formato do Python
    chavePriObj, chavePriPEM = geraChavePrivada(2048, "chavepriva.pem")
    chavePubObj, chavePubPEM = geraChavePublica(chavePriObj, "chavepublica.pem")

    print(chavePriPEM.decode(), '\n' )
    print(chavePubPEM.decode(), '\n')      

    # A chave publica virá pela rede pelo formato PEM, então é necessário convertê-la antes de usar
    chavePubObj2 = converteChavePublica(chavePubPEM)

    # Criptografa com a chave pública (o resultado é base64)
    ciphertext = cifraComPublica('YAHOO, deu certo!!!', chavePubObj2 )

    print('MENSAGEM CIFRADA')
    print(ciphertext.decode(), '\n')

    # Descriptografa com a chave privada (o resultado é texto)
    plaintext = decifraComPrivada(ciphertext, chavePriObj)
    
    print('MENSAGEM DECIFRADA')
    print(plaintext)






