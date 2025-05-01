import hashlib
import os
import json
from datetime import datetime
import sqlite3
from pathlib import Path

class FileIntegrityChecker:
    def __init__(self, db_path="file_integrity.db"):
        self.db_path = db_path
        self.algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }
        self._init_db()

    def _init_db(self):
        """Initialize SQLite database for file integrity history."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS file_hashes
                    (file_path TEXT, hash_value TEXT, algorithm TEXT, 
                     timestamp TEXT, size INTEGER)''')
        conn.commit()
        conn.close()

    def compute_hash(self, file_path, algorithm='sha256', chunk_size=8192):
        """Compute hash of a file using specified algorithm."""
        hasher = self.algorithms[algorithm]()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(chunk_size), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            raise ValueError(f"Error computing hash: {str(e)}")

    def verify_integrity(self, file_path, algorithm='sha256'):
        """Verify file integrity against previous hash."""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('''SELECT hash_value, timestamp FROM file_hashes 
                        WHERE file_path = ? AND algorithm = ?
                        ORDER BY timestamp DESC LIMIT 1''', 
                     (file_path, algorithm))
            result = c.fetchone()
            conn.close()

            current_hash = self.compute_hash(file_path, algorithm)
            current_size = os.path.getsize(file_path)
            current_time = datetime.now().isoformat()

            if result is None:
                # First time seeing this file
                self._store_hash(file_path, current_hash, algorithm, 
                               current_time, current_size)
                return {
                    'status': 'new',
                    'hash': current_hash,
                    'algorithm': algorithm,
                    'timestamp': current_time,
                    'size': current_size
                }

            previous_hash, previous_time = result
            status = 'unchanged' if current_hash == previous_hash else 'modified'
            
            if status == 'modified':
                self._store_hash(file_path, current_hash, algorithm, 
                               current_time, current_size)

            return {
                'status': status,
                'current_hash': current_hash,
                'previous_hash': previous_hash,
                'algorithm': algorithm,
                'last_verified': previous_time,
                'current_time': current_time,
                'size': current_size
            }

        except Exception as e:
            raise RuntimeError(f"Verification failed: {str(e)}")

    def _store_hash(self, file_path, hash_value, algorithm, timestamp, size):
        """Store file hash in database."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''INSERT INTO file_hashes 
                    (file_path, hash_value, algorithm, timestamp, size)
                    VALUES (?, ?, ?, ?, ?)''',
                 (file_path, hash_value, algorithm, timestamp, size))
        conn.commit()
        conn.close()

    def monitor_directory(self, directory_path, algorithm='sha256'):
        """Monitor a directory for file changes."""
        results = []
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    result = self.verify_integrity(file_path, algorithm)
                    result['file_path'] = file_path
                    results.append(result)
                except Exception as e:
                    results.append({
                        'file_path': file_path,
                        'status': 'error',
                        'error': str(e)
                    })
        
        return {
            'directory': directory_path,
            'files_checked': len(results),
            'results': results
        }
