from Crypto.Cipher import ChaCha20
import binascii

def decryptMessage(encrypted_message, key, iv):
    cipher = ChaCha20.new(key=key, nonce=iv)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message

if __name__ == "__main__":
    with open("out.txt", "r") as f:
        lines = f.readlines()
        iv = bytes.fromhex(lines[0].strip())  # Parse IV from the first line
        encrypted_message = bytes.fromhex(lines[1].strip())  # Parse encrypted message from the second line
        encrypted_flag = bytes.fromhex(lines[2].strip())  # Parse encrypted flag from the third line

    # Assuming you have the key already, if not, you should have it generated the same way as in the encryption process
    key = b'your_key_here'  # Replace 'your_key_here' with the actual key

    decrypted_message = decryptMessage(encrypted_message, key, iv)
    decrypted_flag = decryptMessage(encrypted_flag, key, iv)

    print("Decrypted Message:", decrypted_message.decode())
    print("Decrypted Flag:", decrypted_flag.decode())
