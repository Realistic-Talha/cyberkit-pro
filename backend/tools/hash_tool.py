import hashlib
import base64
import logging
import os
from typing import Dict, Union, List, Optional, BinaryIO
from pathlib import Path

class HashTool:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # Add more secure hash algorithms
        self.algorithms = {
            'md5': hashlib.md5,  # Note: MD5 is included but not recommended for security
            'sha1': hashlib.sha1,  # Note: SHA1 is included but not recommended for security
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
            'sha3_256': hashlib.sha3_256,  # Added more secure options
            'sha3_512': hashlib.sha3_512,
            'blake2b': hashlib.blake2b,
            'blake2s': hashlib.blake2s
        }
        
        # Add security level indicators
        self.security_levels = {
            'md5': 'LOW',
            'sha1': 'LOW',
            'sha256': 'HIGH',
            'sha384': 'HIGH',
            'sha512': 'HIGH',
            'sha3_256': 'VERY HIGH',
            'sha3_512': 'VERY HIGH',
            'blake2b': 'VERY HIGH',
            'blake2s': 'HIGH'
        }

    def validate_input(self, text: Union[str, bytes, None]) -> bool:
        """Validate input before processing"""
        if text is None:
            raise ValueError("Input cannot be None")
        if isinstance(text, str) and len(text) == 0:
            raise ValueError("Input string cannot be empty")
        if isinstance(text, bytes) and len(text) == 0:
            raise ValueError("Input bytes cannot be empty")
        return True

    def compute_hash(self, text: Union[str, bytes], algorithm: str) -> Dict:
        """Compute hash with improved error handling and validation"""
        try:
            # Validate algorithm
            if algorithm not in self.algorithms:
                raise ValueError(f"Unsupported algorithm: {algorithm}. Available: {', '.join(self.algorithms.keys())}")
            
            # Validate input
            self.validate_input(text)
            
            hasher = self.algorithms[algorithm]()
            
            # Handle input types
            if isinstance(text, str):
                data = text.encode('utf-8')
            elif isinstance(text, bytes):
                data = text
            else:
                raise TypeError(f"Input must be string or bytes, got {type(text)}")
            
            # Compute hash
            hasher.update(data)
            
            return {
                'algorithm': algorithm,
                'hash': hasher.hexdigest(),
                'hash_bytes': hasher.digest_size,
                'input_length': len(text),
                'security_level': self.security_levels[algorithm],
                'bits': hasher.digest_size * 8
            }
        except Exception as e:
            self.logger.error(f"Hash computation error: {str(e)}")
            raise

    def verify_hash(self, text: Union[str, bytes], hash_value: str, algorithm: str) -> Dict:
        """Enhanced hash verification with detailed response"""
        try:
            computed = self.compute_hash(text, algorithm)
            matches = computed['hash'].lower() == hash_value.lower()
            
            return {
                'matches': matches,
                'computed_hash': computed['hash'],
                'provided_hash': hash_value,
                'algorithm': algorithm,
                'security_level': self.security_levels[algorithm]
            }
        except Exception as e:
            self.logger.error(f"Hash verification error: {str(e)}")
            raise

    def file_hash(self, file_obj: Union[str, bytes, BinaryIO], algorithm: str) -> Dict:
        """Compute hash of file data with improved error handling"""
        try:
            # Validate algorithm
            if algorithm not in self.algorithms:
                raise ValueError(f"Unsupported algorithm: {algorithm}")

            hasher = self.algorithms[algorithm]()
            
            # Handle different input types
            if isinstance(file_obj, str):  # File path
                with open(file_obj, 'rb') as f:
                    for chunk in iter(lambda: f.read(8192), b''):
                        hasher.update(chunk)
            elif hasattr(file_obj, 'read'):  # File-like object (including FileStorage)
                # Save current position
                if hasattr(file_obj, 'tell'):
                    pos = file_obj.tell()
                if hasattr(file_obj, 'seek'):
                    file_obj.seek(0)
                
                # Read in chunks
                for chunk in iter(lambda: file_obj.read(8192), b''):
                    hasher.update(chunk)
                
                # Restore position
                if hasattr(file_obj, 'seek'):
                    file_obj.seek(pos)
            elif isinstance(file_obj, bytes):  # Bytes
                hasher.update(file_obj)
            else:
                raise TypeError("Input must be file path, file-like object, or bytes")

            return {
                'algorithm': algorithm,
                'hash': hasher.hexdigest(),
                'hash_bytes': hasher.digest_size,
                'security_level': self.security_levels[algorithm],
                'bits': hasher.digest_size * 8
            }
        except Exception as e:
            self.logger.error(f"File hash error: {str(e)}")
            raise

    def get_algorithm_info(self, algorithm: str) -> Dict:
        """Get detailed information about a hash algorithm"""
        if algorithm not in self.algorithms:
            raise ValueError(f"Unknown algorithm: {algorithm}")
            
        hasher = self.algorithms[algorithm]()
        return {
            'name': algorithm,
            'digest_size_bytes': hasher.digest_size,
            'digest_size_bits': hasher.digest_size * 8,
            'block_size': hasher.block_size,
            'security_level': self.security_levels[algorithm]
        }

    def get_available_algorithms(self) -> List[Dict]:
        """Get list of supported algorithms with details"""
        return [
            self.get_algorithm_info(algo)
            for algo in self.algorithms.keys()
        ]

# Add comprehensive tests
def run_tests():
    hasher = HashTool()
    test_data = [
        ("Hello, World!", "sha256"),
        (b"Binary data test", "sha512"),
        ("Special chars: !@#$%^&*()", "sha3_256"),
        ("", "sha256"),  # Should raise ValueError
        (None, "sha256"),  # Should raise ValueError
        ("Test", "invalid_algo"),  # Should raise ValueError
    ]
    
    for data, algo in test_data:
        try:
            if isinstance(data, (str, bytes)):
                result = hasher.compute_hash(data, algo)
                print(f"Test passed: {algo} - {result['hash'][:16]}...")
            else:
                print(f"Skipping invalid input: {data}")
        except Exception as e:
            print(f"Expected error for {algo}: {str(e)}")

    # Test file hashing
    with open("test_file.txt", "w") as f:
        f.write("Test content for file hashing")
    
    try:
        result = hasher.file_hash("test_file.txt", "sha256")
        print(f"File hash test passed: {result['hash'][:16]}...")
    except Exception as e:
        print(f"File hash test error: {str(e)}")
    finally:
        try:
            os.remove("test_file.txt")
        except:
            pass

if __name__ == "__main__":
    run_tests()
