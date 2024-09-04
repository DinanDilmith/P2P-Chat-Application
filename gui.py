import tkinter as tk
from threading import Thread
import socket
from network import encrypt_message, decrypt_message, generate_hash, verify_hash, validate_input, BUFFER_SIZE

class ChatApp:
    def __init__(self, root, role):
        self.root = root
        self.root.title("Chat App")
        self.role = role
        self.client_socket = None
        self.server_socket = None
        self.conn = None

        # GUI elements
        self.chat_log = tk.Text(root, state='disabled', width=50, height=20)
        self.chat_log.pack(pady=10)

        self.message_entry = tk.Entry(root, width=40)
        self.message_entry.pack(pady=5)

        self.send_button = tk.Button(root, text="Send", command=self.send_message)
        self.send_button.pack(pady=5)

        # Start server or client based on the role
        if self.role == 's':
            self.server_thread = Thread(target=self.start_server)
            self.server_thread.daemon = True
            self.server_thread.start()
        elif self.role == 'c':
            self.client_thread = Thread(target=self.start_client)
            self.client_thread.daemon = True
            self.client_thread.start()

    # server and client configuration
    def start_server(self):
        host = '127.0.0.1'
        port = 65432
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen()
        self.update_chat_log(f"Server listening on {host}:{port}")
        
        self.conn, addr = self.server_socket.accept()
        self.update_chat_log(f"Connected by {addr}")

        while True:
            try:
                data = self.conn.recv(BUFFER_SIZE)
                if not data:
                    break
                received_message, received_hash = data[:-64], data[-64:]
                decrypted_message = decrypt_message(received_message)
                if verify_hash(decrypted_message, received_hash.decode()):
                    self.update_chat_log(f"Client: {decrypted_message}")
                else:
                    self.update_chat_log("Message Integrity Failed")
            except Exception as e:
                self.update_chat_log(f"Error: {e}")
                break
        
        self.server_socket.close()

    def start_client(self):
        host = '127.0.0.1'
        port = 65432
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))

        while True:
            try:
                data = self.client_socket.recv(BUFFER_SIZE)
                if not data:
                    break
                received_message, received_hash = data[:-64], data[-64:]
                decrypted_message = decrypt_message(received_message)
                if verify_hash(decrypted_message, received_hash.decode()):
                    self.update_chat_log(f"Server: {decrypted_message}")
                else:
                    self.update_chat_log("Message Integrity Failed")
            except Exception as e:
                self.update_chat_log(f"Error: {e}")
                break
        
        self.client_socket.close()

    def send_message(self):
        message = self.message_entry.get()
        if message:
            self.update_chat_log(f"You: {message}")
            validated_message = validate_input(message)
            encrypted_message = encrypt_message(validated_message)
            hash_value = generate_hash(validated_message)
            if self.role == 's' and self.conn:
                self.conn.sendall(encrypted_message + hash_value.encode())
            elif self.role == 'c' and self.client_socket:
                self.client_socket.sendall(encrypted_message + hash_value.encode())
            self.message_entry.delete(0, tk.END)

    def update_chat_log(self, message):
        self.chat_log.config(state='normal')
        self.chat_log.insert(tk.END, message + '\n')
        self.chat_log.config(state='disabled')
        self.chat_log.yview(tk.END)

def main():
    role = input("Do you want to start as server or client? (s/c): ").strip().lower()
    if role not in ['s', 'c']:
        print("Invalid choice!")
        return

    root = tk.Tk()
    app = ChatApp(root, role)
    root.mainloop()

if __name__ == "__main__":
    main()
