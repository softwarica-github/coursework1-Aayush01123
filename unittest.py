import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk, simpledialog, messagebox
import unittest

KEY = "secret"
USERNAME = "admin123"
PASSWORD = "9988"
LOG_KEY = "logkey123"

def xor_cipher(data, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

# ... [rest of your provided code] ...

class TestServerFunctions(unittest.TestCase):

    def test_xor_cipher_encryption_and_decryption(self):
        # Test encryption
        data = "Hello, World!"
        encrypted = xor_cipher(data, KEY)
        self.assertNotEqual(encrypted, data, "Encrypted data should not match the original data")

        # Test decryption
        decrypted = xor_cipher(encrypted, KEY)
        self.assertEqual(decrypted, data, "Decrypted data should match the original data")

# This conditional ensures that the tests are only run when the script is executed as a standalone file.
if __name__ == "__main__":
    unittest.main()