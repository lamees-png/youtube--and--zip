import socket  
import threading  
from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives.asymmetric import rsa, padding  
from cryptography.hazmat.primitives import serialization, hashes  


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

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    client.connect(('localhost', 5555))  
    print("Connected to server!")  

    
    private_key, public_key = generate_keys()  

    
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,  
        format=serialization.PublicFormat.SubjectPublicKeyInfo  
    )
    client.send(public_key_bytes)  

    
    server_public_key_bytes = client.recv(4096)  
    server_public_key = serialization.load_pem_public_key(
        server_public_key_bytes,  
        backend=default_backend()  
    )

    def receive():
        
        while True:
            try:
                encrypted_data = client.recv(1024)  
                if not encrypted_data:  
                    print("Server has disconnected.")  
                    break
                decrypted_data = caesar_decrypt(encrypted_data, SHIFT_KEY)  
                message = decrypted_data.decode('utf-8')  
                print(f"Server says: {message}")  
            except Exception as e:
                print(f"Error receiving: {e}")  
                break
        client.close()  

    def send():
        
        while True:
            message = input("")  
            if message.strip() == "":  
                continue
            try:
                encrypted_data = caesar_encrypt(message.encode('utf-8'), SHIFT_KEY)  
                client.send(encrypted_data)  
            except Exception as e:
                print(f"Error sending: {e}")  
                break
        client.close()  

    receive_thread = threading.Thread(target=receive)  
    send_thread = threading.Thread(target=send)  
    receive_thread.start()  
    send_thread.start()  
    receive_thread.join()  
    send_thread.join()  

if __name__ == "__main__":  
    start_client()  