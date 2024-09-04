# network.py

import socket
import time
from encryption import encrypt_message, decrypt_message
from integrity import generate_hash, verify_hash
from validation import validate_input
from constants import BUFFER_SIZE

def safe_receive(sock):
    data = sock.recv(BUFFER_SIZE)
    if len(data) > BUFFER_SIZE:
        raise ValueError("Buffer overflow attempt detected!")
    return data

def send_message(sock, message):
    validated_message = validate_input(message)
    encrypted_message = encrypt_message(validated_message)
    hash_value = generate_hash(validated_message)
    sock.sendall(encrypted_message + hash_value.encode())

def receive_message(sock):
    data = safe_receive(sock)
    received_message, received_hash = data[:-64], data[-64:]
    decrypted_message = decrypt_message(received_message)
    if verify_hash(decrypted_message, received_hash.decode()):
        return decrypted_message
    else:
        return "Message Integrity Failed"

def start_server(host='127.0.0.1', port=65432):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"Server listening on {host}:{port}")
        
        conn, addr = server_socket.accept()
        with conn:
            print(f"Connected by {addr}")
            while True:
                message = receive_message(conn)
                yield f"Client: {message}"
                if message.lower() == 'bye':
                    break

def start_client(host='127.0.0.1', port=65432):
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((host, port))
                yield "connected"
                while True:
                    message = yield
                    send_message(client_socket, message)
                    if message.lower() == 'bye':
                        break
                    response = receive_message(client_socket)
                    yield f"Server: {response}"
        except ConnectionRefusedError:
            print("Connection failed, retrying in 5 seconds...")
            time.sleep(5)  # Retry after 5 seconds


