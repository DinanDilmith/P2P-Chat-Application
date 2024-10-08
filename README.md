1. **constants.py**
   - **Purpose**: Stores essential constants used throughout the application.
   - **Important Details**:
     - **AES_KEY**: A 16-byte key used for AES encryption. AES keys can be 16, 24, or 32 bytes long, corresponding to 128-bit, 192-bit, or 256-bit encryption.
     - **AES_IV**: A 16-byte initialization vector (IV) used in AES encryption to ensure the same plaintext encrypts differently each time.
     - **BUFFER_SIZE**: Set to 1024 bytes, this defines the maximum amount of data the application will read at a time. It helps prevent buffer overflow attacks by limiting the data received.

2. **encryption.py**
   - **Purpose**: Handles the encryption and decryption of messages.
   - **Important Details**:
     - **Encryption**: Uses AES (Advanced Encryption Standard) in CBC (Cipher Block Chaining) mode to encrypt messages. The message is padded to match the AES block size (16 bytes).
     - **Decryption**: Reverses the encryption process, using the same key and IV to retrieve the original message after removing the padding.

3. **integrity.py**
   - **Purpose**: Ensures message integrity using hashing.
   - **Important Details**:
     - **Hashing**: Generates a SHA-256 hash for a message. SHA-256 produces a 256-bit (32-byte) hash value, which is a unique fingerprint of the data.
     - **Verification**: Compares the hash of the received message with the hash sent to ensure the message wasn't tampered with.

4. **network.py**
   - **Purpose**: Manages the network communication between server and client.
   - **Important Details**:
     - **Safe Receive**: Ensures that no more data than the BUFFER_SIZE is received at once, protecting against buffer overflow.
     - **Sending Messages**: Validates, encrypts, and sends messages along with their hash.
     - **Receiving Messages**: Decrypts and verifies messages after ensuring they haven't been tampered with during transmission.

5. **validation.py**
   - **Purpose**: Ensures that only allowed characters are sent in messages.
   - **Important Details**:
     - **Validation**: Filters out any characters not in the allowed set (letters, numbers, and basic punctuation) to prevent injection attacks or malformed data from being sent.

6. **chat_app.py (Main Script)**
   - **Purpose**: The main script that runs the chat application, handling both server and client roles and providing a graphical user interface (GUI) for communication.
   - **Important Details**:
     - **Role-based Functionality**: Starts either a server or a client based on user input, handling the respective networking tasks.
     - **GUI**: Uses tkinter to create a simple interface with a text area for chat history, a text entry field for typing messages, and a send button.
     - **Threading**: Uses threads to manage sending and receiving messages concurrently without freezing the GUI.

Important Technical Details:
- **AES Encryption**: 128-bit encryption (due to the 16-byte key) ensures that the message is securely encrypted.
- **Buffer Size**: 1024 bytes is a standard size, providing a balance between performance and security. This size helps manage data flow efficiently while preventing buffer overflow attacks.
- **Hashing with SHA-256**: Ensures message integrity by generating a unique 256-bit hash. This hash helps detect any changes made to the message during transmission.
