"""
SecureMessaging.py

NAMES: Ally Yu and Ivan 

Run as client: python3 SecureMessaging.py [Server IP] [Server Port]
Run as server: python3 SecureMessaging.py [Server Port]

"""

import sys
import socket
import os
from threading import Thread
import Crypto
import pyDH
from Crypto.Cipher import AES


QUEUE_LENGTH = 1
SEND_BUFFER_SIZE = 2048
AES_KEY_SIZE = 32
SERVER_TO_CLIENT_KEY = 0
CLIENT_TO_SERVER_KEY = 0
SERVER_OR_CLIENT = True
BYTE_SIZE = 16


class SecureMessage:
    
    def __init__(self, server_ip=None, server_port=None):
        """Initialize SecureMessage object, create & connect socket,
           do key exchange, and start send & receive loops"""
        
        # create IPv4 TCP socket
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # connect as client
        if server_ip and server_port:
            self.s.connect((server_ip, server_port))
            self.name = "client"

        # connect as server
        elif server_port and not server_ip:
            self.s.bind(('', server_port))
            self.s.listen(QUEUE_LENGTH)
            self.s, _ = self.s.accept()
            self.name = "server"
        
        # Run Diffie-Hellman key exchange
        self.key_exchange()

        # start send and receive loops
        self.recv_thread = Thread(target=self.recv_loop, args=())
        self.recv_thread.start()
        self.send_loop()

    def send_loop(self):
        """Loop to check for user input and send messages"""
        while True:
            try:
                user_input = input().encode()
                sys.stdout.flush()
                message = self.process_user_input(user_input)
                self.s.send(message[:SEND_BUFFER_SIZE])
            except EOFError:
                self.s.shutdown(socket.SHUT_RDWR)
                os._exit(0)

    def recv_loop(self):
        """Loop to receive and print messages"""
        while True:
            #recv_msg = self.s.recv(SEND_BUFFER_SIZE).decode()
            recv_msg = self.s.recv(SEND_BUFFER_SIZE)
            if recv_msg:
                message = self.process_received_message(recv_msg)
                sys.stdout.write("\t" + message + "\n")
                sys.stdout.flush()
            else:
                os._exit(0)
    

    def key_exchange(self):
        """TODO: Diffie-Hellman key exchange"""

        port = self.s.getsockname()
      
        print(port[0])
        print(port[1])
        print(self.name)
        # make the public keys for client and server and send
        #
        server = pyDH.DiffieHellman()
        server_to_client_pubkey = server.gen_public_key()
        server_to_client_pubkey = str(server_to_client_pubkey).encode()
      
        self.s.send(server_to_client_pubkey[:SEND_BUFFER_SIZE])
        data = self.s.recv(SEND_BUFFER_SIZE).decode()
        #
        # print("Client public key: \n", data)
        # print("***")
        intdata = int(data)
        #whats used from server to client
        #key 1
        server_to_client_sharedkey = server.gen_shared_key(intdata)
        # print("Shared Key: \n", server_to_client_sharedkey)

        client = pyDH.DiffieHellman()
        client_to_server_pubkey = client.gen_public_key()
        client_to_server_pubkey = str(client_to_server_pubkey).encode()
        self.s.send(client_to_server_pubkey[:SEND_BUFFER_SIZE])
        data2 = self.s.recv(SEND_BUFFER_SIZE).decode()
        # print("Server public key: \n", data2)
        # print("***")
        intdata2 = int(data2)
        
        #
        
        #second key 
        client_to_server_sharedkey = client.gen_shared_key(intdata)
        #print("Shared Key: \n", client_to_server_sharedkey)


        #store as class variables
        self.SERVER_TO_CLIENT_KEY = server_to_client_sharedkey
        self.CLIENT_TO_SERVER_KEY = server_to_client_sharedkey
        if(self.name == "server"):
            SERVER_OR_CLIENT = True
        else:
            SERVER_OR_CLIENT = False

  
        pass

    def process_user_input(self, user_input):
        """TODO: Add authentication and encryption"""
    
        if(SERVER_OR_CLIENT):
            key = self.SERVER_TO_CLIENT_KEY
        else:
            key = self.CLIENT_TO_SERVER_KEY
        
        key = key[:BYTE_SIZE].encode()
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(user_input)
        nonce = cipher.nonce

        concatenated_info = ciphertext + b'  ' + tag + b'  ' + nonce
        
        return concatenated_info


    def process_received_message(self, recv_msg):
        """TODO: Check message integrity and decrypt"""
        if(SERVER_OR_CLIENT):
            key = self.SERVER_TO_CLIENT_KEY
        else:
            key = self.CLIENT_TO_SERVER_KEY
        
        key = key[:BYTE_SIZE].encode()
        split_info = recv_msg.split(b'  ')
        cipherText = split_info[0]
        tag = split_info[1]
        nonce = split_info[2]
        

        try:
            cipher = AES.new(key, AES.MODE_EAX, nonce)
            plainText = cipher.decrypt_and_verify(cipherText, tag)
            plainText = plainText.decode()
        except ValueError:
            ValueError("Incorrect decryption")

        try:
            cipher.verify(tag)
            print("NoMessageModificationDetected: ", plainText)
        except ValueError:
            ValueError("MessageModificationDetecteed")

        return plainText


def main():
    """Parse command-line arguments and start client/server"""
    

    # too few arguments
    if len(sys.argv) < 2:
        sys.exit(
            "Usage: python3 SecureMessaging.py [Server IP (for client only)] [Server Port]")

    # arguments for server
    elif len(sys.argv) == 2:
        server_ip = None
        server_port = int(sys.argv[1])

    # arguments for client
    else:
        server_ip = sys.argv[1]
        server_port = int(sys.argv[2])

    

    # create SecureMessage object
    secure_message = SecureMessage(
        server_ip=server_ip, server_port=server_port)


if __name__ == "__main__":
    main()

   
