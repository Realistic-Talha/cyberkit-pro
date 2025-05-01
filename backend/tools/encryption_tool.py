import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend
import os
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

class EncryptionTool:
    def __init__(self):
        self.algorithms = {
            'fernet': self._fernet_encrypt,
            'aes': self._aes_encrypt,
            'rsa': self._rsa_encrypt
        }
        
        self.decryption_methods = {
            'fernet': self._fernet_decrypt,
            'aes': self._aes_decrypt,
            'rsa': self._rsa_decrypt
        }

    def encrypt(self, text, key, algorithm='fernet'):
        try:
            if not text:
                raise ValueError("No text provided for encryption")
            if not key:
                raise ValueError("No key provided for encryption")
            if algorithm not in self.algorithms:
                raise ValueError(f"Unsupported algorithm: {algorithm}")

            # Convert text to bytes if it's a string
            if isinstance(text, str):
                text = text.encode()

            # Get the encryption method
            encrypt_method = self.algorithms[algorithm]
            
            # Perform encryption
            result = encrypt_method(text, key)
            
            return {
                'encrypted': result['encrypted'],
                'algorithm': algorithm,
                'nonce': result.get('nonce'),  # Only for AES
                'auth_tag': result.get('auth_tag'),  # Only for AES
                'success': True
            }
            
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")

    def decrypt(self, encrypted_text, key, algorithm='fernet', nonce=None, auth_tag=None):
        try:
            # Input validation
            if not encrypted_text:
                raise ValueError("No text provided for decryption")
            if not key:
                raise ValueError("No key provided for decryption")
            if algorithm not in self.decryption_methods:
                raise ValueError(f"Unsupported algorithm: {algorithm}")

            # Log received parameters
            print("Decrypt method parameters:")
            print(f"Algorithm: {algorithm}")
            print(f"Has nonce: {bool(nonce)}")
            print(f"Has auth_tag: {bool(auth_tag)}")

            # Additional validation for AES
            if algorithm == 'aes':
                if not nonce:
                    raise ValueError("Nonce is required for AES decryption")
                if not auth_tag:
                    raise ValueError("Authentication tag is required for AES decryption")

            # Get decryption method and decrypt
            decrypt_method = self.decryption_methods[algorithm]
            decrypted = decrypt_method(encrypted_text, key, nonce, auth_tag)

            # Return result
            return {
                'decrypted': decrypted.decode('utf-8'),
                'algorithm': algorithm
            }

        except Exception as e:
            print(f"Decryption error: {str(e)}")
            raise

    def _fernet_encrypt(self, data, key):
        try:
            # Normalize the key to ensure it's properly formatted
            if not isinstance(key, bytes):
                key = key.encode()
            # Ensure key is properly padded to 32 bytes and base64-encoded
            key = base64.urlsafe_b64encode(key.ljust(32)[:32])
            
            f = Fernet(key)
            encrypted = f.encrypt(data)
            return {
                'encrypted': base64.urlsafe_b64encode(encrypted).decode(),
                'algorithm': 'fernet'
            }
        except Exception as e:
            raise Exception(f"Fernet encryption failed: {str(e)}")

    def _fernet_decrypt(self, encrypted_data, key, nonce=None, auth_tag=None):
        try:
            # Normalize the key
            if not isinstance(key, bytes):
                key = key.encode()
            # Ensure key is properly padded and base64-encoded
            key = base64.urlsafe_b64encode(key.ljust(32)[:32])
            
            # Handle the encrypted data
            if isinstance(encrypted_data, str):
                try:
                    # First decode the urlsafe base64 wrapper
                    encrypted_data = base64.urlsafe_b64decode(encrypted_data)
                except Exception:
                    raise ValueError("Invalid encrypted data format")
            
            f = Fernet(key)
            return f.decrypt(encrypted_data)
            
        except Exception as e:
            raise Exception(f"Fernet decryption failed: {str(e)}")

    def _aes_encrypt(self, data, key):
        try:
            key = key.encode().ljust(32)[:32]
            nonce = os.urandom(16)
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Encrypt without padding for GCM mode
            encrypted = encryptor.update(data) + encryptor.finalize()
            
            # Get authentication tag
            auth_tag = encryptor.tag
            
            return {
                'encrypted': base64.b64encode(encrypted).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'auth_tag': base64.b64encode(auth_tag).decode(),  # Add this line
                'algorithm': 'aes'
            }
        except Exception as e:
            raise Exception(f"AES encryption failed: {str(e)}")

    def _aes_decrypt(self, encrypted_data, key, nonce, auth_tag):
        try:
            # Input validation
            if not nonce or not auth_tag:
                raise ValueError("Both nonce and auth_tag are required for AES decryption")

            # Normalize inputs
            if isinstance(key, str):
                key = key.encode()
            key = key.ljust(32)[:32]

            # Base64 decode inputs
            try:
                nonce = base64.b64decode(nonce)
                auth_tag = base64.b64decode(auth_tag)
                encrypted = base64.b64decode(encrypted_data)
            except Exception as e:
                raise ValueError(f"Invalid base64 encoding: {str(e)}")

            print(f"AES Decryption Parameters:")
            print(f"Key length: {len(key)}")
            print(f"Nonce length: {len(nonce)}")
            print(f"Auth tag length: {len(auth_tag)}")
            print(f"Encrypted data length: {len(encrypted)}")

            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, auth_tag),
                backend=default_backend()
            )
            
            # Decrypt
            decryptor = cipher.decryptor()
            return decryptor.update(encrypted) + decryptor.finalize()
            
        except Exception as e:
            raise Exception(f"AES decryption failed: {str(e)}")

    def _rsa_encrypt(self, data, key):
        try:
            # Deserialize public key
            public_key = serialization.load_pem_public_key(
                key.encode(),
                backend=default_backend()
            )
            
            # RSA encryption with padding
            encrypted = public_key.encrypt(
                data,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return {
                'encrypted': base64.b64encode(encrypted).decode(),
                'algorithm': 'rsa'
            }
        except Exception as e:
            raise Exception(f"RSA encryption failed: {str(e)}")

    def _rsa_decrypt(self, encrypted_data, key, nonce=None, auth_tag=None):
        try:
            # Deserialize private key
            private_key = serialization.load_pem_private_key(
                key.encode(),
                password=None,
                backend=default_backend()
            )
            
            # Convert from base64 if needed
            if isinstance(encrypted_data, str):
                encrypted_data = base64.b64decode(encrypted_data)
            
            # RSA decryption with padding
            decrypted = private_key.decrypt(
                encrypted_data,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return decrypted
        except Exception as e:
            raise Exception(f"RSA decryption failed: {str(e)}")

    def generate_key(self, algorithm='fernet'):
        """Generate a new encryption key for the specified algorithm."""
        try:
            if algorithm == 'fernet':
                return Fernet.generate_key().decode()
            elif algorithm == 'aes':
                return base64.b64encode(os.urandom(32)).decode()
            elif algorithm == 'rsa':
                # Generate RSA key pair
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
                
                # Get public key
                public_key = private_key.public_key()
                
                # Serialize keys to PEM format
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode()
                
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
                
                return {
                    'private_key': private_pem,
                    'public_key': public_pem
                }
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
        except Exception as e:
            raise Exception(f"Key generation failed: {str(e)}")

@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.get_json()
        encryption_tool = EncryptionTool()
        result = encryption_tool.encrypt(
            text=data['text'],
            key=data['key'],
            algorithm=data.get('algorithm', 'fernet')
        )
        return jsonify({'success': True, 'data': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.get_json()
        print("Decrypt Request Data:", {
            'algorithm': data.get('algorithm'),
            'has_nonce': 'nonce' in data,
            'has_auth_tag': 'auth_tag' in data,
            'text_length': len(data.get('text', '')),
        })
        
        encryption_tool = EncryptionTool()
        result = encryption_tool.decrypt(
            encrypted_text=data['text'],
            key=data['key'],
            algorithm=data.get('algorithm', 'fernet'),
            nonce=data.get('nonce'),
            auth_tag=data.get('auth_tag')
        )
        return jsonify({'success': True, 'data': result})
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/generate-key', methods=['POST'])
def generate_key():
    try:
        data = request.get_json()
        encryption_tool = EncryptionTool()
        key = encryption_tool.generate_key(algorithm=data.get('algorithm', 'fernet'))
        return jsonify({'success': True, 'data': {'key': key}})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
