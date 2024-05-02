import socket
import time
import RSALib as RSA
import AESLib as AES

ipServidor = '127.0.0.1'
portaServidor = 9999
destino = (ipServidor, portaServidor)

print('ESTA TELA PERTENCE A BOB')

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

# Neste loop BOB tenta contato com Alice
while True:
    # Tenta contato com Alice
    s.sendto('HELLO'.encode(), destino )
   
    print('Aguardando chave pública ...')

    try:
        chavePubPEM, addr = s.recvfrom(1024) 
        print('Recebi uma chave pública')
        print('Chave Publica:', chavePubPEM)

        # 1) BOB RECEBE A CHAVE PÚBLICA DE ALICE
        chavePubObj = RSA.converteChavePublica(chavePubPEM)

        # 2) BOB GERA UMA CHAVE SECRETA ALEATÓRIA
        chavesecreta, chavePEM = AES.geraChave(128)

        # 3) BOB CRIPTOGRAFA A CHAVE SECRETA (EM BYTES) COM A CHAVE PÚBLICA DA ALICE
        chaveCifrada = RSA.cifraComPublica(chavesecreta, chavePubObj)

        # 4) BOB ENVIA A CHAVE SECRETA CRIPTOGRAFADA PARA ALICE
        s.sendto(chaveCifrada, destino )
        print(f'Enviei uma chave secreta para {addr}')
        print('Chave Cifrada:', chaveCifrada)

        # 5) BOB DESCRIPTOGRAFA UMA MENSAGEM CIFRADA DA ALICE
        ciphertext, addr = s.recvfrom(1024) 
        print(f'Recebi uma mensagem cifrada de {addr}')
        print('Ciphertext:', ciphertext)

        # Descriptografa a mensagem usando a chave secreta
        plaintext = AES.decifraMensagem(ciphertext, chavesecreta)
        
        # SE VOCE FEZ TUDO CERTO A MENSAGEM DA ALICE VAI SER IMPRESSA AQUI
        print('Plaintext:', plaintext)
        break

    except Exception as e:
        print(e)
        print('Alice não responde!')
        time.sleep(5)
