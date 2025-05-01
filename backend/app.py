from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import json  # Add this import
import logging
import base64  # Add missing import
import threading
import time
from tools.encryption_tool import EncryptionTool
from tools.port_scanner import PortScanner  # Add this import
from tools.hash_tool import HashTool  # Add this import
from tools.log_analyzer import LogAnalyzer  # Add this import
from tools.password_cracker import PasswordCracker  # Add this import
from tools.web_crawler import WebCrawler  # Add this import
from tools.phishing_detector import PhishingDetector  # Add this import

app = Flask(__name__)
# Update CORS configuration to be more permissive during development
CORS(app, resources={
    r"/api/*": {
        "origins": "*",  # Allow all origins during development
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Accept", "Origin"],
        "expose_headers": ["Content-Type"],
        "supports_credentials": True,
        "send_wildcard": False,
        "max_age": 86400
    }
})

# Configure logging
logging.basicConfig(level=logging.DEBUG)  # Change to DEBUG for more info
logger = logging.getLogger(__name__)

# Initialize encryption tool
encryption_tool = EncryptionTool()

# Initialize port scanner
port_scanner = PortScanner()

# Initialize hash tool
hash_tool = HashTool()

# Initialize log analyzer
log_analyzer = LogAnalyzer()

# Initialize password cracker
password_cracker = PasswordCracker()

# Initialize web crawler
web_crawler = WebCrawler()

# Initialize phishing detector
phishing_detector = PhishingDetector()

@app.route('/api/generate-key', methods=['POST'])
def generate_key():
    try:
        data = request.get_json()
        logger.debug(f"Received key generation request: {data}")
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        algorithm = data.get('algorithm', 'fernet')
        key = encryption_tool.generate_key(algorithm)
        
        # Handle RSA key pair differently
        if algorithm == 'rsa':
            if not isinstance(key, dict) or 'private_key' not in key or 'public_key' not in key:
                raise ValueError('Invalid RSA key pair generated')
                
            response = {
                'success': True,
                'data': {
                    'key': {
                        'private_key': key['private_key'],
                        'public_key': key['public_key']
                    }
                }
            }
        else:
            response = {
                'success': True,
                'data': {
                    'key': key
                }
            }
            
        logger.debug(f"Sending key generation response: {response}")
        return jsonify(response)
        
    except Exception as e:
        logger.exception("Key generation error")
        return jsonify({
            'success': False, 
            'error': str(e)
        }), 400

@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        text = data.get('text')
        key = data.get('key')
        algorithm = data.get('algorithm', 'fernet')
        
        result = encryption_tool.encrypt(text, key, algorithm)
        return jsonify({'success': True, 'data': result})
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.get_json()
        logger.debug("Received decrypt request data: %s", {
            'algorithm': data.get('algorithm'),
            'has_nonce': 'nonce' in data,
            'has_auth_tag': 'auth_tag' in data,
            'text_length': len(data.get('text', '')),
            'payload_keys': list(data.keys())  # Debug what keys are actually present
        })

        # Required fields validation
        if not all(key in data for key in ['text', 'key', 'algorithm']):
            return jsonify({
                'success': False,
                'error': 'Missing required fields'
            }), 400

        # AES-specific validation
        if data['algorithm'] == 'aes':
            if not data.get('nonce'):
                return jsonify({
                    'success': False,
                    'error': 'Nonce is required for AES decryption'
                }), 400
            if not data.get('auth_tag'):
                return jsonify({
                    'success': False,
                    'error': 'Authentication tag is required for AES decryption'
                }), 400

            logger.debug("AES Decryption Parameters: %s", {
                'nonce_length': len(data['nonce']),
                'auth_tag_length': len(data['auth_tag'])
            })

        # Perform decryption
        result = encryption_tool.decrypt(
            encrypted_text=data['text'],
            key=data['key'],
            algorithm=data['algorithm'],
            nonce=data.get('nonce'),
            auth_tag=data.get('auth_tag')
        )

        return jsonify({
            'success': True,
            'data': result
        })

    except Exception as e:
        logger.exception("Decryption failed")
        return jsonify({
            'success': False,
            'error': f"Decryption failed: {str(e)}"
        }), 400

@app.route('/api/file/encrypt', methods=['POST'])
def encrypt_file():
    try:
        if 'file' not in request.files:
            return jsonify({
                'success': False, 
                'error': 'No file provided'
            }), 400
            
        file = request.files['file']
        algorithm = request.form.get('algorithm', 'fernet')
        key = request.form.get('key')
        
        # Read file as binary
        file_data = file.read()
        # Always use base64 for files to preserve binary data
        file_content = base64.b64encode(file_data).decode('utf-8')
        
        # Encrypt the content
        result = encryption_tool.encrypt(file_content, key, algorithm)
        
        return jsonify({
            'success': True,
            'data': result,
            'originalFileName': file.filename
        })
    except Exception as e:
        logger.error(f"File encryption error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/file/decrypt', methods=['POST'])
def decrypt_file():
    try:
        if 'file' not in request.files:
            logger.error("No file provided in request")
            return jsonify({
                'success': False, 
                'error': 'No file provided'
            }), 400
            
        file = request.files['file']
        algorithm = request.form.get('algorithm', 'fernet')
        key = request.form.get('key')
        nonce = request.form.get('nonce')
        
        logger.debug(f"Decrypting file with algorithm: {algorithm}")
        
        # Read file as binary
        file_data = file.read()
        try:
            # Assume the file content is base64 encoded
            file_content = file_data.decode('utf-8')
            logger.debug("File read successfully")
        except UnicodeDecodeError as e:
            logger.error(f"File decode error: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'Invalid file format'
            }), 400

        # Decrypt the content
        try:
            result = encryption_tool.decrypt(file_content, key, algorithm, nonce=nonce)
            logger.debug("File decrypted successfully")
            
            # Convert decrypted base64 back to binary
            try:
                binary_data = base64.b64decode(result['decrypted'])
                logger.debug("Successfully converted decrypted data to binary")
                
                # Return binary data
                return jsonify({
                    'success': True,
                    'data': {
                        'decrypted': base64.b64encode(binary_data).decode('utf-8'),
                        'algorithm': algorithm
                    }
                })
            except Exception as e:
                logger.error(f"Binary conversion error: {str(e)}")
                return jsonify({
                    'success': False,
                    'error': 'Failed to process decrypted data'
                }), 400
                
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            return jsonify({
                'success': False,
                'error': f'Decryption failed: {str(e)}'
            }), 400
            
    except Exception as e:
        logger.exception(f"File processing error: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"File processing failed: {str(e)}"
        }), 400

@app.route('/api/port-scan', methods=['POST'])
def scan_ports():
    try:
        data = request.get_json()
        logger.debug(f"Received scan request: {data}")  # Add logging
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        target = data.get('target')
        port_range = data.get('portRange')
        
        if not target or not port_range:
            return jsonify({'error': 'Missing required parameters'}), 400

        logger.info(f"Starting port scan for {target} on ports {port_range}")  # Add logging
        results = port_scanner.scan(target, port_range)
        logger.debug(f"Scan results: {results}")  # Add logging
        
        return jsonify({
            'success': True,
            'data': results
        })
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Scan failed: ' + str(e)
        }), 500

@app.route('/api/hash', methods=['POST', 'OPTIONS'])
def compute_hash():
    if request.method == 'OPTIONS':
        response = jsonify({'message': 'OK'})
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Accept, Origin'
        return response

    try:
        data = request.get_json(force=True)
        logger.debug(f"Received hash request data: {data}")
        
        text = data.get('text', '').strip()
        algorithm = data.get('algorithm', 'sha256')
        
        if not text:
            return jsonify({
                'success': False, 
                'error': 'No text provided'
            }), 400
            
        result = hash_tool.compute_hash(text, algorithm)
        
        response = jsonify({
            'success': True, 
            'data': result
        })
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response
        
    except Exception as e:
        logger.exception(f"Hash computation error: {str(e)}")
        return jsonify({
            'success': False, 
            'error': str(e)
        }), 400

@app.route('/api/hash/algorithms', methods=['GET'])
def get_algorithms():
    return jsonify({
        'success': True,
        'data': hash_tool.get_available_algorithms()
    })

@app.route('/api/hash/verify', methods=['POST'])
def verify_hash():
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400

        text = data.get('text')
        hash_value = data.get('hash')
        algorithm = data.get('algorithm', 'sha256')
        
        result = hash_tool.verify_hash(text, hash_value, algorithm)
        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        logger.error(f"Hash verification error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/hash/file', methods=['POST'])
def hash_file():
    try:
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No file provided'
            }), 400

        file = request.files['file']
        algorithm = request.form.get('algorithm', 'sha256')
        
        # Pass the file object directly
        result = hash_tool.file_hash(file, algorithm)
        
        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        logger.error(f"File hash error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/analyze-logs', methods=['POST', 'OPTIONS'])
def analyze_logs():
    if request.method == 'OPTIONS':
        response = jsonify({'message': 'OK'})
        response.headers.update({
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Accept'
        })
        return response

    try:
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'message': 'No file provided'
            }), 400

        file = request.files['file']
        content = file.read().decode('utf-8')
        
        # Parse options with default empty dict
        options = {}
        if 'options' in request.form:
            try:
                options = json.loads(request.form['options'])
            except json.JSONDecodeError:
                logger.warning("Invalid options format, using defaults")

        # Call analyze_log with two arguments
        result = log_analyzer.analyze_log(content, options)
        
        return jsonify({
            'success': True,
            'data': result
        })

    except Exception as e:
        logger.exception("Log analysis failed")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 400

@app.route('/api/health', methods=['GET', 'OPTIONS'])
def health_check():
    if request.method == 'OPTIONS':
        # Handle preflight request
        response = jsonify({'message': 'OK'})
        response.headers.add('Access-Control-Allow-Origin', 'http://localhost:8080')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'GET, OPTIONS')
        return response
    return jsonify({'status': 'healthy'})

@app.route('/api/test', methods=['GET'])
def test_endpoint():
    return jsonify({
        'success': True,
        'message': 'Backend is reachable'
    })

@app.route('/api/crack-password', methods=['POST'])
def crack_password():
    try:
        data = request.get_json()
        logger.debug(f"Received crack request: {data}")  # Add debug logging
        
        hash_value = data.get('hash')
        hash_type = data.get('type')
        method = data.get('method', 'dictionary')
        max_length = data.get('maxLength', 8)
        
        # Clear any existing progress
        while not password_cracker.progress_queue.empty():
            password_cracker.progress_queue.get()

        def crack_task():
            try:
                password_cracker.start_time = time.time()  # Set start time here
                logger.debug(f"Starting crack task at: {password_cracker.start_time}")
                password_cracker.crack_password(
                    hash_value, 
                    hash_type,
                    method,
                    max_length
                )
            except Exception as e:
                logger.exception("Cracking task error")

        # Stop any existing task
        if password_cracker.current_task and password_cracker.current_task.is_alive():
            password_cracker.stop_cracking()
            password_cracker.current_task.join()

        password_cracker.current_task = threading.Thread(target=crack_task, daemon=True)
        password_cracker.current_task.start()
        
        return jsonify({'success': True, 'message': 'Password cracking started'})
        
    except Exception as e:
        logger.exception("Password cracking error")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/crack-status')
def crack_status():
    def generate():
        while True:
            try:
                progress = password_cracker.get_progress()
                if progress:
                    print(f"Sending progress update: {progress}")  # Debug line
                    yield f"data: {json.dumps(progress)}\n\n"
                    # If this is a final update (found or finished), break
                    if progress.get('finished', False):
                        break
                time.sleep(0.1)
            except Exception as e:
                print(f"Error in generate: {e}")  # Debug line
                break

    return Response(generate(), mimetype='text/event-stream')

@app.route('/api/stop-crack', methods=['POST'])
def stop_crack():
    try:
        password_cracker.stop_cracking()
        return jsonify({
            'success': True,
            'message': 'Password cracking stopped'
        })
    except Exception as e:
        logger.exception("Error stopping password cracker")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/available-hash-types', methods=['GET'])
def get_hash_types():
    return jsonify({
        'success': True,
        'data': [
            'md5',
            'sha1',
            'sha256',
            'sha512'
        ]
    })

@app.route('/api/crawl', methods=['POST'])
def start_crawl():
    try:
        data = request.get_json()
        url = data.get('url')
        max_depth = data.get('max_depth', 2)
        max_pages = data.get('max_pages', 100)
        respect_robots = data.get('respect_robots', True)

        # Clear any existing progress
        web_crawler.clear_progress()

        def crawl_task():
            web_crawler.crawl(url, max_depth, max_pages, respect_robots)

        thread = threading.Thread(target=crawl_task)
        thread.daemon = True
        thread.start()

        return jsonify({'success': True, 'message': 'Crawling started'})

    except Exception as e:
        logger.exception("Crawling error")
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/crawl-status')
def crawl_status():
    def generate():
        while True:
            progress = web_crawler.get_progress()
            if progress:
                yield f"data: {json.dumps(progress)}\n\n"
                if progress.get('finished', False):
                    break
            time.sleep(0.1)

    return Response(generate(), mimetype='text/event-stream')

@app.route('/api/stop-crawl', methods=['POST'])
def stop_crawl():
    try:
        web_crawler.stop()
        return jsonify({'success': True, 'message': 'Crawler stopped'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/analyze-url', methods=['POST'])  # Fix: Add square brackets
def analyze_url():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({
                'success': False,
                'error': 'No URL provided'
            }), 400

        url = data['url']
        result = phishing_detector.analyze_url(url)
        
        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        logger.exception("URL analysis failed")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000, threaded=True, ssl_context=None)
