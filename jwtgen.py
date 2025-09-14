from flask import Flask, request, jsonify
import requests
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define the target API endpoint
TARGET_API = "https://ff-token-generator.vercel.app/token"

@app.route('/token', methods=['GET'])
def get_token():
    uid = request.args.get('uid')
    password = request.args.get('password')
    
    if not uid or not password:
        logger.error("Missing uid or password in request")
        return jsonify({"error": "error"}), 400
    
    try:
        target_url = f"{TARGET_API}?uid={uid}&password={password}"
        logger.info(f"Requesting target API: {target_url}")
        
        response = requests.get(target_url, timeout=10)
        response.raise_for_status()
        
        # Check if response is valid JSON
        try:
            target_response = response.json()
        except ValueError:
            logger.error("Target API returned invalid JSON")
            return jsonify({"error": "error"}), 502
        
        # Extract only the token from the response
        token = target_response.get('token')
        if not token:
            logger.error("Token not found in target API response")
            return jsonify({"error": "error"}), 502
        
        # Return only the token
        logger.info("Successfully fetched token from target API")
        return jsonify({"token": token}), 200
        
    except (requests.exceptions.HTTPError, requests.exceptions.Timeout, 
            requests.exceptions.ConnectionError, requests.exceptions.RequestException):
        logger.error("Error fetching token from target API")
        return jsonify({"error": "error"}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok", "message": "Server is running"}), 200

if __name__ == '__main__':
    app.run(debug=True)
