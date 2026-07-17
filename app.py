from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
import threading
import time
import os
from datetime import datetime, timedelta

app = Flask(__name__)

# Token management
TOKEN_CACHE = {}
TOKEN_CACHE_TIME = {}
TOKEN_REFRESH_INTERVAL = 7200  # 2 hours in seconds

def load_accounts(server_name):
    """Load accounts from text file"""
    try:
        if server_name == "IND":
            filename = "account.ind.txt"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            filename = "account.br.txt"
        else:
            filename = "account.bd.txt"
        
        accounts = []
        if os.path.exists(filename):
            with open(filename, "r") as f:
                for line in f:
                    line = line.strip()
                    if ':' in line:
                        uid, password = line.split(':', 1)
                        accounts.append({"uid": uid.strip(), "password": password.strip()})
        return accounts
    except Exception as e:
        app.logger.error(f"Error loading accounts for {server_name}: {e}")
        return []

def save_tokens(server_name, tokens):
    """Save tokens to JSON file"""
    try:
        if server_name == "IND":
            filename = "token_ind.json"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            filename = "token_br.json"
        else:
            filename = "token_bd.json"
        
        with open(filename, "w") as f:
            json.dump(tokens, f, indent=2)
        return True
    except Exception as e:
        app.logger.error(f"Error saving tokens for {server_name}: {e}")
        return False

def fetch_token_from_api(uid, password):
    """Fetch token from the API"""
    try:
        url = f"https://mafu-token-converter-production.up.railway.app/token?uid={uid}&password={password}"
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success' and 'jwt_token' in data:
                return {
                    "token": data['jwt_token'],
                    "uid": data.get('account_uid', uid),
                    "region": data.get('region', ''),
                    "access_token": data.get('access_token', ''),
                    "open_id": data.get('open_id', '')
                }
        return None
    except Exception as e:
        app.logger.error(f"Error fetching token for UID {uid}: {e}")
        return None

def refresh_tokens_for_server(server_name):
    """Refresh all tokens for a specific server"""
    try:
        accounts = load_accounts(server_name)
        if not accounts:
            app.logger.warning(f"No accounts found for {server_name}")
            return False
        
        new_tokens = []
        for account in accounts:
            token_data = fetch_token_from_api(account['uid'], account['password'])
            if token_data:
                new_tokens.append(token_data)
                app.logger.info(f"Token refreshed for UID {account['uid']} on {server_name}")
            else:
                app.logger.error(f"Failed to refresh token for UID {account['uid']} on {server_name}")
        
        if new_tokens:
            # Load existing tokens to preserve any that might not have been refreshed
            existing_tokens = load_tokens(server_name)
            if existing_tokens:
                # Merge: keep existing tokens for accounts that failed to refresh
                existing_uids = {t.get('uid') for t in existing_tokens if 'uid' in t}
                for token in existing_tokens:
                    if token.get('uid') not in {t.get('uid') for t in new_tokens}:
                        new_tokens.append(token)
            
            save_tokens(server_name, new_tokens)
            # Update cache
            TOKEN_CACHE[server_name] = new_tokens
            TOKEN_CACHE_TIME[server_name] = datetime.now()
            return True
        
        return False
    except Exception as e:
        app.logger.error(f"Error refreshing tokens for {server_name}: {e}")
        return False

def load_tokens(server_name):
    """Load tokens with auto-refresh if needed"""
    try:
        # Check if cache is valid
        if server_name in TOKEN_CACHE and server_name in TOKEN_CACHE_TIME:
            time_diff = (datetime.now() - TOKEN_CACHE_TIME[server_name]).total_seconds()
            if time_diff < TOKEN_REFRESH_INTERVAL:
                return TOKEN_CACHE[server_name]
        
        # Try to load from file
        if server_name == "IND":
            filename = "token_ind.json"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            filename = "token_br.json"
        else:
            filename = "token_bd.json"
        
        if os.path.exists(filename):
            with open(filename, "r") as f:
                tokens = json.load(f)
                # Update cache
                TOKEN_CACHE[server_name] = tokens
                TOKEN_CACHE_TIME[server_name] = datetime.now()
                return tokens
        
        # If file doesn't exist, generate new tokens
        app.logger.info(f"No token file found for {server_name}, generating new tokens...")
        if refresh_tokens_for_server(server_name):
            return load_tokens(server_name)
        
        return None
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

def auto_refresh_tokens():
    """Background thread to automatically refresh tokens"""
    while True:
        try:
            servers = ["IND", "BR", "US", "SAC", "NA", "BD"]
            for server in servers:
                app.logger.info(f"Auto-refreshing tokens for {server}...")
                refresh_tokens_for_server(server)
                time.sleep(5)  # Small delay between servers
            app.logger.info("Token refresh cycle completed. Next refresh in 2 hours.")
            time.sleep(TOKEN_REFRESH_INTERVAL)
        except Exception as e:
            app.logger.error(f"Error in auto_refresh_tokens: {e}")
            time.sleep(300)  # Wait 5 minutes on error

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB54"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Request failed with status code: {response.status}")
                    return response.status
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            app.logger.error("Failed to create protobuf message.")
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            app.logger.error("Encryption failed.")
            return None
        tasks = []
        tokens = load_tokens(server_name)
        if tokens is None:
            app.logger.error("Failed to load tokens.")
            return None
        for i in range(1000):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def make_request(encrypt, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB54"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        decode = decode_protobuf(binary)
        if decode is None:
            app.logger.error("Protobuf decoding returned None.")
        return decode
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        app.logger.error(f"Error decoding Protobuf data: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error during protobuf decoding: {e}")
        return None

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    try:
        def process_request():
            tokens = load_tokens(server_name)
            if tokens is None:
                raise Exception("Failed to load tokens.")
            token = tokens[0]['token']
            encrypted_uid = enc(uid)
            if encrypted_uid is None:
                raise Exception("Encryption of UID failed.")

            before = make_request(encrypted_uid, server_name, token)
            if before is None:
                raise Exception("Failed to retrieve initial player info.")
            try:
                jsone = MessageToJson(before)
            except Exception as e:
                raise Exception(f"Error converting 'before' protobuf to JSON: {e}")
            data_before = json.loads(jsone)
            before_like = data_before.get('AccountInfo', {}).get('Likes', 0)
            try:
                before_like = int(before_like)
            except Exception:
                before_like = 0
            app.logger.info(f"Likes before command: {before_like}")

            if server_name == "IND":
                url = "https://client.ind.freefiremobile.com/LikeProfile"
            elif server_name in {"BR", "US", "SAC", "NA"}:
                url = "https://client.us.freefiremobile.com/LikeProfile"
            else:
                url = "https://clientbp.ggpolarbear.com/LikeProfile"

            asyncio.run(send_multiple_requests(uid, server_name, url))

            after = make_request(encrypted_uid, server_name, token)
            if after is None:
                raise Exception("Failed to retrieve player info after like requests.")
            try:
                jsone_after = MessageToJson(after)
            except Exception as e:
                raise Exception(f"Error converting 'after' protobuf to JSON: {e}")
            data_after = json.loads(jsone_after)
            after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
            player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
            player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', ''))
            like_given = after_like - before_like
            status = 1 if like_given != 0 else 2
            result = {
                "LikesGivenByAPI": like_given,
                "LikesafterCommand": after_like,
                "LikesbeforeCommand": before_like,
                "PlayerNickname": player_name,
                "UID": player_uid,
                "status": status
            }
            return result

        result = process_request()
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/refresh_tokens', methods=['POST'])
def refresh_tokens_endpoint():
    """Manual endpoint to refresh tokens"""
    server_name = request.args.get("server_name", "").upper()
    if not server_name:
        return jsonify({"error": "server_name is required"}), 400
    
    if refresh_tokens_for_server(server_name):
        return jsonify({"success": True, "message": f"Tokens refreshed for {server_name}"})
    else:
        return jsonify({"success": False, "message": f"Failed to refresh tokens for {server_name}"}), 500

@app.route('/token_status', methods=['GET'])
def token_status():
    """Check token status for all servers"""
    servers = ["IND", "BR", "US", "SAC", "NA", "BD"]
    status = {}
    for server in servers:
        tokens = load_tokens(server)
        if tokens:
            status[server] = {
                "count": len(tokens),
                "last_refresh": TOKEN_CACHE_TIME.get(server, "Never").isoformat() if server in TOKEN_CACHE_TIME else "Never"
            }
        else:
            status[server] = {"count": 0, "status": "No tokens found"}
    return jsonify(status)

if __name__ == '__main__':
    # Start auto-refresh thread
    refresh_thread = threading.Thread(target=auto_refresh_tokens, daemon=True)
    refresh_thread.start()
    app.logger.info("Auto-token refresher started. Tokens will be refreshed every 2 hours.")
    
    app.run(debug=True, use_reloader=False, host='0.0.0.0', port=5000)