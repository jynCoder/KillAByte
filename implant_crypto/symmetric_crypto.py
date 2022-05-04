#!/usr/bin/python3
# Used within C2 to encrypt config, etc.

def xorCipher(str_in, KEY):
	str_out = ""

	for i in range(len(str_in)):
		idx = i % len(KEY)
		str_out += chr(ord(str_in[i]) ^ ord(KEY[idx]))

	return str_out

if __name__ == "__main__":
	# Test XOR cipher
	KEY = "Testing123"
	msg = "Test message"

	print("Encrypting: \"" + msg + "\"")
	print("KEY = " + KEY)

	encrypted_msg = xorCipher(msg, KEY)
	print("Encrypted message: " + encrypted_msg)

	decrypted_msg = xorCipher(encrypted_msg, KEY)
	print("Decrypted message: " + decrypted_msg)