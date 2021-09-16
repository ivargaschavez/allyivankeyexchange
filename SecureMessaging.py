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

        #server
        
        if(self.name == "server"):
            server = pyDH.DiffieHellman()
            server_pubkey = server.gen_public_key()
            server_pubkey = (str(server_pubkey)+"\n").encode()
            self.mysend(b'server public key:')
            self.mysend(server_pubkey)
            
            
        #client
        else:
       
            client = pyDH.DiffieHellman()
            client_pubkey = client.gen_public_key()
            client_pubkey = (str(client_pubkey)+"\n").encode()
            self.mysend(b'client public key:')
            self.mysend(client_pubkey)
        """

        self.s.send(server_pubkey[:SEND_BUFFER_SIZE])
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
        #generate shared keys 

        #self.s.send(str(server_pubkey).encode('utf8'))
        #self.mysend(client_pubkey)
        #server_sentkey = self.s.recv(SEND_BUFFER_SIZE).decode()
        #print("sent key")
        #print(server_sentkey)
              
        pass

    def process_user_input(self, user_input):
        """TODO: Add authentication and encryption"""

        return user_input

    def process_received_message(self, recv_msg):
        """TODO: Check message integrity and decrypt"""
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

   
    """ print("server key:")
    print(server_pubkey)
    server_1 = "This is the servers public key:\n"
    self.s.sendall(str(server_1).encode('utf8'))

    #need to send this key to client: python3 SecureMessaging.py [Server IP] [Server Port]        self.s.sendall(str(server_pubkey).encode('utf8'))
    print("server public key sent to client")
    msg = "Do you have a public key? (Yes / No)"
    self.s.sendall(str(msg).encode('utf8'))
    data = self.s.recv(SEND_BUFFER_SIZE)
    print(data)
    print("did we get it")
    #bytes to str
    """
