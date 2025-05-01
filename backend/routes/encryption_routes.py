from flask import request, jsonify
# ...existing imports...

@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.get_json()
        
        # Debug log the incoming request
        print("Decrypt Request Data:", {
            'algorithm': data.get('algorithm'),
            'has_nonce': 'nonce' in data,
            'has_auth_tag': 'auth_tag' in data,
            'text_length': len(data.get('text', '')),
        })

        # Required fields
        required_fields = ['text', 'key', 'algorithm']
        if not all(field in data for field in required_fields):
            return jsonify({
                'success': False,
                'error': 'Missing required fields'
            }), 400

        # For AES, ensure both nonce and auth_tag are provided
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

        # Initialize encryption tool
        encryption_tool = EncryptionTool()

        # Attempt decryption
        result = encryption_tool.decrypt(
            encrypted_text=data['text'],
            key=data['key'],
            algorithm=data['algorithm'],
            nonce=data.get('nonce'),
            auth_tag=data.get('auth_tag')  # Make sure this is passed correctly
        )

        return jsonify({
            'success': True,
            'data': result
        })

    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"Decryption failed: {str(e)}"
        }), 400
