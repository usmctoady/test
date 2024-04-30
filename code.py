from Crypto.Cipher import ChaCha20
from secret import FLAG
import os
 
 def encryptMessage(message, key, nonce):
	 cipher = ChaCha20.new(key=key, nonce=iv)
	 ciphertext = cipher.encrypt(message)
		return ciphertext
 
 def writeData(data):
     with open("out.txt", "w") as f:
       f.write(data)

 if __name__ == "__main__":
 message = b" this is just dummy text, the real secret will be appended at the end of it. Decrypt it as usual to find out what I've discovered"
	key, iv = os.urandom(32), os.urandom(12) 
	encrypted_message = encryptMessage(message, key, iv)
	encrypted_flag = encryptMessage(FLAG, key, iv)

  data = iv.hex() + "\n" + encrypted_message.hex() + "\n" + encrypted_flag.hex()
	writeData(data)
