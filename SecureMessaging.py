"""
SecureMessaging.py

NAMES: [Your full names here]

Run as client: python3 SecureMessaging.py [Server IP] [Server Port]
Run as server: python3 SecureMessaging.py [Server Port]

"""

import sys
import socket
import os
from threading import Thread
import Crypto
import pyDH


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
            recv_msg = self.s.recv(SEND_BUFFER_SIZE).decode()
            if recv_msg:
                message = self.process_received_message(recv_msg)
                sys.stdout.write("\t" + message + "\n")
                sys.stdout.flush()
            else:
                os._exit(0)
    def mysend(self, msg):
        totalsent = 0
        while totalsent < len(msg):
            sent = self.s.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
            totalsent = totalsent + sent

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
        server_to_client_pubkey = (str(server_to_client_pubkey)+"\n").encode()
        #self.mysend(server_to_client_pubkey)
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
        client_to_server_pubkey = (str(client_to_server_pubkey)+"\n").encode()
        self.s.send(client_to_server_pubkey[:SEND_BUFFER_SIZE])
        data2 = self.s.recv(SEND_BUFFER_SIZE).decode()
        # print("Server public key: \n", data2)
        # print("***")
        intdata2 = int(data2)
        
        #
        
        #second key 
        client_to_server_sharedkey = client.gen_shared_key(intdata)
        print("Shared Key: \n", client_to_server_sharedkey)


        #store as class variables
        self.SERVER_TO_CLIENT_KEY = server_to_client_sharedkey
        self.CLIENT_TO_SERVER_KEY = server_to_client_sharedkey
        if(self.name == "server"):
            SERVER_OR_CLIENT = True
        else:
            SERVER_OR_CLIENT = False



        '''
        if(self.name == "server"):
            server = pyDH.DiffieHellman()
            server_pubkey = server.gen_public_key()
            server_pubkey = (str(server_pubkey)+"\n").encode()
            #self.mysend(b'server public key:')
            self.mysend(server_pubkey) this is one key 
            data = self.s.recv(SEND_BUFFER_SIZE).decode()
            print("Client public key: \n", data)
            print("***")
            intdata = int(data)
            server_sharedkey = server.gen_shared_key(intdata)
            print("Shared Key: \n", server_sharedkey)
        #client
        else:
            data = self.s.recv(SEND_BUFFER_SIZE).decode()
            print("Server public key: \n", data)
            print("***")
            intdata = int(data)
            #bytedata = bytes(data, 'utf-8')
            #self.mysend(b'client recieved public key')
            client = pyDH.DiffieHellman()
            client_pubkey = client.gen_public_key()
            client_pubkey = (str(client_pubkey)+"\n").encode()
            #self.mysend(b'client public key:')
            self.mysend(client_pubkey)
            client_sharedkey = client.gen_shared_key(intdata)
            print("Shared Key: \n", client_sharedkey)
        '''
        """
        
        server_sentkey = int(self.s.recv(SEND_BUFFER_SIZE).decode())

        self.server_sharedkey = server.gen_shared_key(server_sentkey)
        self.s.send(client[:SEND_BUFFER_SIZE])

        client_sentkey = int(self.s.recv(SEND_BUFFER_SIZE).decode())

        self.client_sharedkey = client.gen_shared_key(client_sentkey)

        #we will be using AES later and AES only takes keys max 32 bits 
        self.client_sharedkey = self.str(client_sharedkey[:AES_KEY_SIZE])
       
        self.client_key = str.encode(self.client_sharedkey)
        self.server_key = str.encode(self.server_sharedkey)
        """    
  
        pass

    def process_user_input(self, user_input):
        """TODO: Add authentication and encryption"""
        #is the self the key? 
        #cipher = AES.new(key, AES.MODE_EAX) key is going to be whether or not it is is server or client
        #now that key is a class variable encode it to bytes
        #if true it is server
        if(SERVER_OR_CLIENT):
            key = self.SERVER_TO_CLIENT_KEY
        else:
            key = self.CLIENT_TO_SERVER_KEY
        
        key = key[:BYTE_SIZE].encode()
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(user_input)
        nonce = cipher.nonce

        concatenated_info = ciphertext + b' ' + tag + b' ' + nonce
        return concatenated_info


    def process_received_message(self, recv_msg):
        """TODO: Check message integrity and decrypt"""
        if(SERVER_OR_CLIENT):
            key = self.SERVER_TO_CLIENT_KEY
        else:
            key = self.CLIENT_TO_SERVER_KEY
        
        key = key[:BYTE_SIZE].encode()
        split_info = recv_msg.split(b' ')
        cipherText = split_info[0]
        tag = split_info[1]
        nonce - split_info[2]

        try:
            cipher = AES.new(key, AES.MODE_EAX, nonce)
            plaintext = cipher.decrypt_and_verify(cipherText, tag)
            plaintext = plaintext.decode()
        except ValueError:
            print("Incorrect decryption")

        try:
            cipher.verify(tag)
            print("NoMessageModificationDetected: ", plainText)
        except ValueError:
            ValueError("MessageModificationDetecteed")

        return recv_msg


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

   
