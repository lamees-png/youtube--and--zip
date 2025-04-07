import socket  
import threading  
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend  


SHIFT_KEY = 3  

def caesar_encrypt(data: bytes, shift: int) -> bytes:
    return bytes([(b + shift) % 256 for b in data])  

def caesar_decrypt(data: bytes, shift: int) -> bytes:
    return bytes([(b - shift) % 256 for b in data])  

def generate_keys():
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def handle_client(client_socket):
    
    private_key, public_key = generate_keys()
    
    
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.send(public_key_bytes)

    
    client_public_key_bytes = client_socket.recv(4096)
    client_public_key = serialization.load_pem_public_key(
        client_public_key_bytes,
        backend=default_backend()
    )

    def receive():
        while True:
            try:
                encrypted_data = client_socket.recv(1024) 
                if not encrypted_data:  
                    print("Client has disconnected.")  
                    break
                decrypted_data = caesar_decrypt(encrypted_data, SHIFT_KEY)  
                message = decrypted_data.decode('utf-8')  
                print(f"Client says: {message}")  
            except Exception as e:
                print(f"Error receiving: {e}")  
                break
        client_socket.close()  

    def send():
        while True:
            message = input("")  
            if message.strip() == "":  
                continue
            try:
                encrypted_data = caesar_encrypt(message.encode('utf-8'), SHIFT_KEY)  
                client_socket.send(encrypted_data)  
            except Exception as e:
                print(f"Error sending: {e}")  
                break
        client_socket.close  

    receive_thread = threading.Thread(target=receive)  
    send_thread = threading.Thread(target=send)  
    receive_thread.start()  
    send_thread.start()  
    receive_thread.join()  
    send_thread.join()  

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    server.bind(('localhost', 5555)) 
    server.listen(5)  
    print("Server listening on port 5555...")  

    while True:
        client_socket, addr = server.accept()  
        print(f"Connected to {addr}")  
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))  
        client_thread.start()  

if __name__ == "__main__":  
    start_server()  