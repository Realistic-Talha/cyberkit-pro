import hashlib
import itertools
import string
import threading
import queue
import time
from pathlib import Path

class PasswordCracker:
    def __init__(self):
        self.common_passwords = self._load_wordlist()
        self.stop_flag = False
        self.progress_queue = queue.Queue()
        self.current_task = None
        self.start_time = None  # Add this line

    def _load_wordlist(self):
        try:
            # Get the absolute path to the backend directory
            backend_dir = Path(__file__).parent.parent
            wordlist_path = backend_dir / 'tools' / 'wordlists' / 'common_passwords.txt'
            
            print(f"Attempting to load wordlist from: {wordlist_path}")  # Debug print
            
            if not wordlist_path.exists():
                print(f"Wordlist file not found at: {wordlist_path}")  # Debug print
                return ['password', '123456', 'admin']  # Fallback list
                
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
                
        except Exception as e:
            print(f"Error loading wordlist: {str(e)}")  # Debug print
            return ['password', '123456', 'admin']  # Fallback list

    def calculate_hash(self, password: str, hash_type: str) -> str:
        hash_funcs = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }
        
        if hash_type not in hash_funcs:
            raise ValueError(f"Unsupported hash type: {hash_type}")
            
        return hash_funcs[hash_type](password.encode()).hexdigest()

    def dictionary_attack(self, target_hash: str, hash_type: str):
        total_words = len(self.common_passwords)
        print(f"Starting dictionary attack for hash: {target_hash}, type: {hash_type}")
        
        for idx, password in enumerate(self.common_passwords):
            if self.stop_flag:
                break
                
            current_hash = self.calculate_hash(password, hash_type)
            print(f"Trying password: {password}, hash: {current_hash}")
            
            if current_hash.lower() == target_hash.lower():
                print(f"Password found: {password}")
                result = {
                    'attempts': idx + 1,
                    'progress': 100,
                    'found': True,
                    'password': password,
                    'time': f"{time.time() - self.start_time:.2f} seconds",
                    'finished': True  # Changed to True
                }
                self.progress_queue.put(result)
                return result
                
            progress = (idx + 1) / total_words * 100
            self.progress_queue.put({
                'attempts': idx + 1,
                'progress': progress,
                'found': False,
                'time': f"{time.time() - self.start_time:.2f} seconds",
                'finished': False
            })
        
        print("Password not found in dictionary")
        return None

    def bruteforce_attack(self, target_hash: str, hash_type: str, max_length: int = 8):
        charset = string.ascii_letters + string.digits + string.punctuation
        attempts = 0
        total = sum(len(charset) ** i for i in range(1, max_length + 1))

        for length in range(1, max_length + 1):
            for guess in itertools.product(charset, repeat=length):
                if self.stop_flag:
                    return None
                    
                password = ''.join(guess)
                current_hash = self.calculate_hash(password, hash_type)
                attempts += 1
                elapsed = time.time() - self.start_time
                
                progress = (attempts / total) * 100
                self.progress_queue.put({
                    'attempts': attempts,
                    'progress': progress,
                    'found': False,
                    'time': f"{elapsed:.2f} seconds"
                })
                
                if current_hash.lower() == target_hash.lower():
                    result = {
                        'attempts': attempts,
                        'progress': 100,
                        'found': True,
                        'password': password,
                        'time': f"{elapsed:.2f} seconds"
                    }
                    self.progress_queue.put(result)
                    return password
                    
        return None

    def crack_password(self, target_hash: str, hash_type: str, method: str = 'dictionary', max_length: int = 8):
        try:
            self.stop_flag = False
            self.start_time = time.time()
            
            result = None
            if method == 'dictionary':
                result = self.dictionary_attack(target_hash, hash_type)
            else:
                result = self.bruteforce_attack(target_hash, hash_type, max_length)
            
            if not result:
                elapsed = time.time() - self.start_time
                self.progress_queue.put({
                    'attempts': 0,
                    'progress': 100,
                    'found': False,
                    'time': f"{elapsed:.2f} seconds",
                    'finished': True  # Add this line
                })
            
            return result
            
        except Exception as e:
            current_time = time.time() - self.start_time
            self.progress_queue.put({
                'error': str(e),
                'progress': 100,
                'found': False,
                'time': f"{current_time:.2f} seconds"
            })
            return None
            
        finally:
            self.stop_flag = True

    def stop_cracking(self):
        self.stop_flag = True

    def get_progress(self):
        try:
            return self.progress_queue.get_nowait()
        except queue.Empty:
            return None
