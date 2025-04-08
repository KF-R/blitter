#!/usr/bin/env python3
APP_VERSION = '0.2.3' 
PROTOCOL_VERSION = "0002"  # Version constants defined before imports for visibility
import os
import json
import time
import datetime
import sys  # Added for stderr
import base64  # Added for key encoding
import atexit  # Added for cleanup
import string
import requests  # Added for fetching subscriptions
import concurrent.futures  # Added for async fetching
import threading  # Added for background task feedback and timer
import shutil  # Added for directory removal
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session, abort
from markupsafe import escape
import re  # Added for parsing markdown
import hashlib  # For authentication

# --- Tor Integration Imports ---
try:
    from stem.control import Controller
    from stem import Signal, ProtocolError
    STEM_AVAILABLE = True
except ImportError:
    STEM_AVAILABLE = False
    print("Warning: 'stem' library not found. Tor integration will be disabled.", file=sys.stderr)
    print("Install it using: pip install stem", file=sys.stderr)

app = Flask(__name__)
# Secret key for session management (replace with a real secret key in production)
app.secret_key = os.urandom(24)

# --- Constants and Configuration ---
PROFILE_FILE = 'profile.json'
FEED_FILE = 'feed.json'
SUBSCRIPTIONS_DIR = 'subscriptions'
KEYS_DIR = 'keys'
LOG_DIR = 'log'
SECRET_WORD_FILE = 'secret_word'
ONION_PORT = 80  # Virtual port the onion service will listen on
FLASK_HOST = "127.0.0.1"  # Host Flask should listen on for Tor
FLASK_PORT = 5000  # Port Flask should listen on for Tor
MAX_MSG_LENGTH = 512
SOCKS_PROXY = "socks5h://127.0.0.1:9050"  # SOCKS proxy for Tor requests
FETCH_TIMEOUT = 30  # Timeout in seconds for fetching subscription feeds
FETCH_CYCLE = 300  # Automatic fetch interval in seconds
NULL_REPLY_ADDRESS = '0'*56 + ':' + '0'*16

# --- Global Variables ---
SITE_NAME = "tor_setup_pending"  # Placeholder until Tor setup
# --- Tor Globals ---
tor_controller = None
tor_service_id = None
onion_address = None
# --- Fetching Globals ---
fetch_executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)  # Executor for background fetches
active_fetches = {}  # Track active fetch tasks (optional for status, might be less useful with lock)
fetch_lock = threading.Lock()  # Lock to prevent concurrent manual/auto fetch cycles
fetch_timer = None  # Timer object for rescheduling background fetches

# --- Helper Functions ---

def is_valid_onion_address(addr):
    # Matches 56 characters from a-z and 2-7, optionally followed by ".onion"
    return bool(re.fullmatch(r'[a-z2-7]{56}(?:\.onion)?', addr))

def load_bip39_wordlist(filename='bip39_english.txt'):
    """
    Load the BIP-0039 word list from a file.
    The file should contain exactly 2048 words (one per line).
    """
    # Try finding the file relative to the script first
    script_dir = os.path.dirname(os.path.abspath(__file__))
    filepath = os.path.join(script_dir, filename)
    if not os.path.exists(filepath):
        # Fallback to current working directory if not found next to script
        filepath = filename

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            words = [line.strip() for line in f if line.strip()]
        if len(words) != 2048:
            raise ValueError(f"BIP-0039 word list must contain exactly 2048 words (found {len(words)} in {filepath})")
        return words
    except FileNotFoundError:
        print(f"FATAL ERROR: BIP-0039 wordlist '{filename}' not found in {script_dir} or current directory.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"FATAL ERROR: Failed to load BIP-0039 wordlist '{filepath}': {e}", file=sys.stderr)
        sys.exit(1)

def load_json(filename):
    """Loads JSON data from a file."""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        if 'feedcache.json' not in filename and 'notes.json' not in filename:
             print(f"Info: File not found {filename}, returning None.", file=sys.stderr)
        return None
    except json.JSONDecodeError as e:
        print(f"Warning: Could not decode JSON from {filename}: {e}", file=sys.stderr)
        return None
    except Exception as e:
         print(f"Error loading JSON from {filename}: {e}", file=sys.stderr)
         return None

def save_json(filename, data):
    """Saves JSON data to a file."""
    try:
        dir_name = os.path.dirname(filename)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except IOError as e:
        print(f"Error: Could not write JSON to {filename}: {e}", file=sys.stderr)
    except Exception as e:
        print(f"Unexpected error saving JSON to {filename}: {e}", file=sys.stderr)

def is_logged_in():
    """Checks if the user is logged in via session."""
    return 'logged_in' in session and session['logged_in']

def get_current_timestamp_hex():
    """Gets the current time as a 16-byte hex timestamp using full nanosecond precision."""
    ns_timestamp = time.time_ns()
    return f'{ns_timestamp:016x}'

def format_timestamp_for_display(hex_timestamp):
    """Formats a hex timestamp (stored in nanoseconds) for display."""
    try:
        ns_timestamp = int(hex_timestamp, 16)
        if ns_timestamp > 4102444800000000000:
            return "Invalid Timestamp (Future)"
        if ns_timestamp <= 0:
            return "Invalid Timestamp (Past)"
        dt_object = datetime.datetime.fromtimestamp(ns_timestamp / 1_000_000_000, tz=datetime.timezone.utc)
        day = dt_object.day
        if 11 <= day <= 13:
            suffix = 'th'
        else:
            suffixes = {1: 'st', 2: 'nd', 3: 'rd'}
            suffix = suffixes.get(day % 10, 'th')
        formatted = dt_object.strftime(f'%d{suffix} %b \'%y %H:%M:%S.%f')[:-3] + ' (UTC)'
        return formatted
    except (ValueError, TypeError, OverflowError):
        return "Invalid Timestamp"

def parse_message_string(msg_str):
    """Parses a message string into a dictionary, returns None if invalid."""
    if not isinstance(msg_str, str) or not msg_str.startswith('|') or not msg_str.endswith('|'):
        return None
    parts = msg_str.strip('|').split('|')
    if len(parts) != 8:
        return None
    protocol, site, timestamp, reply_id, expiration, flag_int, length_field, content = parts
    if len(protocol) != 4 or not all(c in string.hexdigits for c in protocol): return None
    if len(site) != 56 or not all(c in string.ascii_lowercase + string.digits + '234567' for c in site): return None
    if len(timestamp) != 16 or not all(c in string.hexdigits for c in timestamp): return None
    reply_parts = reply_id.split(':')
    if len(reply_parts) != 2: return None
    if len(reply_id) != len(NULL_REPLY_ADDRESS): return None
    if len(expiration) != 16 or not all(c in string.hexdigits for c in expiration): return None
    if len(flag_int) != 16 or not all(c in string.hexdigits for c in flag_int): return None
    if len(length_field) != 3 or not length_field.isdigit(): return None
    try:
        expected_len = int(length_field)
        actual_len = len(content.encode('utf-8', errors='ignore'))
        if actual_len != expected_len:
            print(f"Warning: Message length field {expected_len} does not match UTF-8 byte length {actual_len}. Content: '{content[:50]}...'", file=sys.stderr)
            pass
    except ValueError:
        return None
    return {
        'protocol': protocol,
        'site': site,
        'timestamp': timestamp,
        'display_timestamp': format_timestamp_for_display(timestamp),
        'reply_id': reply_id,
        'content': content,
        'display_content': content,
        'expiration': expiration,
        'flags': flag_int,
        'len': length_field,
        'raw_message': msg_str
    }

def create_message_string(content, reply_id=NULL_REPLY_ADDRESS):
    """Creates a message string:
    |<protocol_version>|<sitename>|<timestamp>|<reply-id>|<expiration>|<flag_int>|<len>|<content>|
    """
    global SITE_NAME, PROTOCOL_VERSION
    if SITE_NAME.startswith("tor_"):
         print("Error: Cannot create message, Tor setup incomplete/failed.", file=sys.stderr)
         return None, None

    timestamp = get_current_timestamp_hex()
    if not isinstance(content, str):
         print("Error: Message content must be a string.", file=sys.stderr)
         return None, None

    content_bytes = content.encode('utf-8', errors='ignore')
    content_length = len(content_bytes)

    if content_length > MAX_MSG_LENGTH:
        truncated_bytes = content_bytes[:MAX_MSG_LENGTH]
        content = truncated_bytes.decode('utf-8', errors='ignore')
        content_length = len(content.encode('utf-8', errors='ignore'))
        print(f"Warning: Message content truncated to {content_length} bytes (max {MAX_MSG_LENGTH}).", file=sys.stderr)

    expiration = 'f'*16
    flag_int = '0'*16

    len_field = f"{content_length:03d}"

    if not reply_id:
        reply_id=NULL_REPLY_ADDRESS

    message = f"|{PROTOCOL_VERSION}|{SITE_NAME}|{timestamp}|{reply_id}|{expiration}|{flag_int}|{len_field}|{content}|"
    return message, timestamp

def load_subscriptions():
    """
    Utility function to load subscription data and cached feed messages.
    Returns a tuple: (subscriptions_with_nicknames, subscription_raw_feed, nicknames_map)
    """
    subscriptions_with_nicknames = []
    subscription_raw_feed = []
    nicknames_map = {}
    try:
        if os.path.isdir(SUBSCRIPTIONS_DIR):
            subscription_dirs_list = sorted([d for d in os.listdir(SUBSCRIPTIONS_DIR) if os.path.isdir(os.path.join(SUBSCRIPTIONS_DIR, d))])
            for site_dir in subscription_dirs_list:
                nickname = None
                notes_file = os.path.join(SUBSCRIPTIONS_DIR, site_dir, 'notes.json')
                notes_data = load_json(notes_file)
                if notes_data and isinstance(notes_data, dict) and notes_data.get('nickname'):
                    nickname = notes_data['nickname']
                subscriptions_with_nicknames.append({'site': site_dir, 'nickname': nickname})
                nicknames_map[site_dir] = nickname
                cache_file = os.path.join(SUBSCRIPTIONS_DIR, site_dir, 'feedcache.json')
                cached_data = load_json(cache_file) or []
                if isinstance(cached_data, list):
                    for msg_str in cached_data:
                        parsed_msg = parse_message_string(msg_str)
                        if parsed_msg:
                            if parsed_msg['site'] == site_dir:
                                subscription_raw_feed.append(parsed_msg)
                            else:
                                print(f"Warning: Message site '{parsed_msg['site']}' in cache file '{cache_file}' does not match directory '{site_dir}'. Skipping display.", file=sys.stderr)
                        else:
                            print(f"Noped: {msg_str}")
                elif cached_data is not None:
                    print(f"Warning: Cache file '{cache_file}' is not a valid JSON list. Skipping.", file=sys.stderr)
    except Exception as e:
         print(f"Error loading subscription data or notes: {e}", file=sys.stderr)
         subscriptions_with_nicknames = []
         subscription_raw_feed = []
         nicknames_map = {}
    return subscriptions_with_nicknames, subscription_raw_feed, nicknames_map

def bmd2html(bmd_string):
    """Converts a Blitter Markdown string to valid html"""
    if not isinstance(bmd_string, str):
        return ""
    html_string = escape(bmd_string)
    def replace_link(match):
        text = match.group(1)
        url = match.group(2)
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        safe_url = escape(url)
        return f'<a href="{safe_url}" target="_blank">{escape(text)}</a>'
    html_string = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', replace_link, html_string)
    html_string = re.sub(r'\*\*\*([^\*]+)\*\*\*', r'<strong><em>\1</em></strong>', html_string)
    html_string = re.sub(r'\*\*([^\*]+)\*\*', r'<strong>\1</strong>', html_string)
    html_string = re.sub(r'\*([^\*]+)\*', r'<em>\1</em>', html_string)
    return html_string

def get_passphrase(service_dir, secret_word) -> list:
    """
    Reads the last 64 bytes of the binary file,
    combines it with the secret_word and computes the SHA-256 hash,
    truncates it to 66 bits (6 x 11 bits), and maps each 11-bit segment
    to a word in the BIP-0039 word list.
    """
    bip39 = load_bip39_wordlist()
    key_file_path = os.path.join(service_dir, "hs_ed25519_secret_key")
    try:
        with open(key_file_path, "rb") as f:
            f.seek(-64, os.SEEK_END)
            payload = f.read(64)
            if len(payload) != 64:
                raise IOError(f"Could not read the last 64 bytes from {key_file_path}")
    except FileNotFoundError:
        print(f"Error: Key file not found at {key_file_path}", file=sys.stderr)
        raise
    except IOError as e:
        print(f"Error reading key file {key_file_path}: {e}", file=sys.stderr)
        raise

    digest = hashlib.sha256(payload + secret_word.encode("utf-8")).digest()
    digest_int = int.from_bytes(digest, byteorder="big")
    truncated = digest_int >> (256 - 66)
    words = []
    for i in range(6):
        shift = (6 - i - 1) * 11
        index = (truncated >> shift) & 0x7FF
        words.append(bip39[index])
    return words

# --- Tor Integration Functions ---

def find_first_onion_service_dir(keys_dir):
    if not os.path.isdir(keys_dir):
        print(f"Error: Keys directory '{keys_dir}' not found.", file=sys.stderr)
        return None
    try:
        items = sorted(os.listdir(keys_dir))
    except OSError as e:
        print(f"Error listing keys directory '{keys_dir}': {e}", file=sys.stderr)
        return None
    for item in items:
        service_dir = os.path.join(keys_dir, item)
        key_file = os.path.join(service_dir, "hs_ed25519_secret_key")
        if os.path.isdir(service_dir) and os.path.isfile(key_file):
            print(f"Found key directory: {service_dir}")
            return service_dir
    print(f"Info: No suitable key directories found in '{keys_dir}'.", file=sys.stderr)
    return None

def get_key_blob(service_dir):
    key_file_path = os.path.join(service_dir, "hs_ed25519_secret_key")
    try:
        with open(key_file_path, 'rb') as f:
            key_data = f.read()
        is_new_format = key_data.startswith(b'== ed25519v1-secret: type0 ==\x00\x00\x00')
        is_old_format = key_data.startswith(b'== ed25519v1-secret: type0 ==') and len(key_data) == 96
        if not (is_new_format or is_old_format):
             raise ValueError(f"Key file format is incorrect. Header mismatch.")
        if is_new_format and len(key_data) < 64+32:
             raise ValueError(f"Key file size is incorrect for new format ({len(key_data)} bytes found)")
        elif is_old_format and len(key_data) != 96:
             raise ValueError(f"Key file size is incorrect for old format ({len(key_data)} bytes found)")
        key_material_64 = key_data[-64:]
        key_blob = base64.b64encode(key_material_64).decode('ascii')
        return f"ED25519-V3:{key_blob}"
    except FileNotFoundError:
        print(f"Error: Secret key file not found: {key_file_path}", file=sys.stderr)
        return None
    except ValueError as ve:
        print(f"Error reading key file {key_file_path}: {ve}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error processing key file {key_file_path}: {e}", file=sys.stderr)
        return None

def start_tor_hidden_service(key_blob_with_type):
    if not STEM_AVAILABLE:
        print("Error: Cannot start Tor service, 'stem' library is missing.", file=sys.stderr)
        return False
    global tor_controller, tor_service_id, onion_address, SITE_NAME
    try:
        print("Connecting to Tor controller...")
        controller = Controller.from_port()
        controller.authenticate()
        print("Authenticated with Tor controller.")
        command = (
            f"ADD_ONION {key_blob_with_type} "
            f"Flags=Detach "
            f"Port={ONION_PORT},{FLASK_HOST}:{FLASK_PORT}"
        )
        print("Sending ADD_ONION command to Tor...")
        response = controller.msg(command)
        if not response.is_ok():
            raise ProtocolError(f"ADD_ONION command failed:\n{response}")
        parsed_service_id = None
        parsed_onion_address = None
        for line in response.content():
            line_text = ''
            if isinstance(line, (tuple, list)) and len(line) >= 3 and isinstance(line[2], str):
                line_text = line[2]
            elif isinstance(line, str):
                 line_text = line
            if line_text.startswith("ServiceID="):
                parsed_service_id = line_text.split("=", 1)[1]
                if len(parsed_service_id) == 56 and all(c in string.ascii_lowercase + string.digits + '234567' for c in parsed_service_id):
                     parsed_onion_address = f"{parsed_service_id}.onion"
                     break
                else:
                     print(f"Warning: Received unexpected ServiceID format: {parsed_service_id}", file=sys.stderr)
                     parsed_service_id = None
        if not parsed_service_id or not parsed_onion_address:
            raw_response_content = response.content(decode=False)
            raise ValueError(f"ADD_ONION command seemed to succeed, but failed to parse valid ServiceID/OnionAddress from response. Raw content: {raw_response_content}")
        print(f"Successfully created/attached service: {parsed_onion_address}")
        print(f"Service points to http://{FLASK_HOST}:{FLASK_PORT}")
        tor_controller = controller
        tor_service_id = parsed_service_id
        onion_address = parsed_onion_address
        SITE_NAME = parsed_service_id
        atexit.register(cleanup_tor_service)
        return True
    except ProtocolError as pe:
         print(f"Tor Protocol Error: {pe}", file=sys.stderr)
         print("Ensure Tor is running with ControlPort 9051 enabled and accessible.", file=sys.stderr)
         print("Check Tor logs for more details.", file=sys.stderr)
         if tor_controller:
             try: tor_controller.close()
             except: pass
         tor_controller = None
         return False
    except Exception as e:
        print(f"Error communicating with Tor controller: {e}", file=sys.stderr)
        print("Ensure Tor is running with ControlPort enabled (e.g., ControlPort 9051) and", file=sys.stderr)
        print("CookieAuthentication is enabled (CookieAuthentication 1).", file=sys.stderr)
        if tor_controller:
            try: tor_controller.close()
            except: pass
        tor_controller = None
        return False

def cleanup_tor_service():
    global tor_controller, tor_service_id, fetch_timer, fetch_executor
    if fetch_timer:
        print("Cancelling background fetch timer...")
        fetch_timer.cancel()
        fetch_timer = None
    print("Shutting down background fetch executor...")
    fetch_executor.shutdown(wait=True, cancel_futures=True)
    print("Fetch executor shut down.")
    if tor_controller and tor_service_id:
        print(f"\nCleaning up Tor service: {tor_service_id}")
        try:
            if tor_controller.is_authenticated() and tor_controller.is_alive():
                 print(f"Attempting DEL_ONION for {tor_service_id} (may fail if service is detached)...")
                 response = tor_controller.msg(f"DEL_ONION {tor_service_id}")
                 if response.is_ok():
                     print(f"Successfully removed service {tor_service_id}")
                 else:
                     print(f"Info: DEL_ONION command response for {tor_service_id}: {response.status_type} {response.status_severity} - {response.content(decode=False)}", file=sys.stderr)
                     is_gone_error = any("HiddenServiceNonExistent" in str(line) for line in response.content())
                     if not is_gone_error:
                          print(f"Warning: Failed to explicitly remove service {tor_service_id}. It might persist if Tor continues running.", file=sys.stderr)
            else:
                 print(f"Warning: Tor controller connection lost or unauthenticated before cleanup of {tor_service_id}.", file=sys.stderr)
        except ProtocolError as pe:
             print(f"Warning: Tor Protocol Error during cleanup: {pe}", file=sys.stderr)
        except Exception as e:
            print(f"Warning: Error during Tor service cleanup: {e}", file=sys.stderr)
        finally:
            if tor_controller:
                try:
                    tor_controller.close()
                    print("Tor controller connection closed.")
                except Exception as close_e:
                    print(f"Warning: Error closing Tor controller during cleanup: {close_e}", file=sys.stderr)
            tor_controller = None
            tor_service_id = None
    elif tor_service_id:
        print(f"\nWarning: Tor controller not available for cleanup of service {tor_service_id}. Service might persist if Tor continues running.", file=sys.stderr)

# --- HTML Templates ---

LOGIN_TEMPLATE = """
<!doctype html>
<html>
<head><title>Login</title></head>
<body>
  <h2>Login</h2>
  {% if error %}<p style="color:red;"><strong>Error:</strong> {{ error }}</p>{% endif %}
  <form method="post">
    Passphrase: <input type="password" name="passphrase" value=""><br>
    <input type="submit" value="Login">
  </form>
  <p><a href="{{ url_for('index') }}">Back to Feed</a></p>
</body>
</html>
"""

PROFILE_TEMPLATE = """
<!doctype html>
<html>
<head><title>Profile</title></head>
<body>
  <h2>Profile</h2>
  <a href="{{ url_for('logout') }}">Logout</a> | <a href="{{ url_for('index') }}">Home</a>
  <form method="post">
    Nickname: <input type="text" name="nickname" value="{{ profile.get('nickname', '') }}"><br>
    Location: <input type="text" name="location" value="{{ profile.get('location', '') }}"><br>
    Description:<br>
    <textarea name="description" rows="4" cols="50">{{ profile.get('description', '') }}</textarea><br>
    Email: <input type="text" name="email" value="{{ profile.get('email', '') }}"><br>
    Website: <input type="text" name="website" value="{{ profile.get('website', '') }}"><br>
    <input type="submit" value="Update Profile">
  </form>
</body>
</html>
"""

INDEX_TEMPLATE = """
<!doctype html>
<html>
<head>
    <title>Blitter Feed - {{ site_name }}</title>
    <style>
        body { font-family: sans-serif; margin: 0; background-color: #222; color: #eee; }
        .header, .footer { background-color: #333; padding: 10px; overflow: hidden; }
        .header .logo { float: left; font-weight: bold; display: flex; align-items: center; }
        .header .site-name { text-align: center; font-size: 1.1em; margin: 0 180px; line-height: 1.5em; }
        .header .controls { float: right; }
        .content { display: flex; flex-wrap: wrap; padding: 10px; }
        .feed-panel { flex: 1; min-width: 200px; margin-right: 10px; margin-bottom: 10px; }
        .subscriptions-panel { flex: 2; min-width: 400px; background-color: #333; padding: 10px; border-radius: 5px; max-height: 80vh; overflow-y: auto;}
        .subscriptions-header { font-size:24px; font-weight: bold; margin-bottom: 8px; }
        .post-box { border: 1px solid #444; padding: 10px; margin-bottom: 4px; background-color: #2a2a2a; border-radius: 5px;}
        .post-box.own-post-highlight { border: 1px solid #ffcc00; }
        .post-meta { font-size: 0.8em; color: #888; margin-bottom: 5px;}
        .post-meta a { color: #aaa; }
        .post-content { margin-top: 5px; white-space: pre-wrap; word-wrap: break-word; font-size: 0.9em; }
         textarea { width: 95%; background-color: #444; color: #eee; border: 1px solid #555; padding: 5px; font-family: inherit;}
         input[type=submit], button { padding: 5px 10px; background-color: #555; border: none; color: #eee; cursor: pointer; border-radius: 3px; margin-left: 5px; }
         button:disabled { background-color: #444; color: #888; cursor: not-allowed;}
         a { color: #7af; text-decoration: none; }
         a:hover { text-decoration: underline; }
         .error { color: red; font-weight: bold; }
         .site-info { margin-left: 10px; font-size: 0.9em; }
         .nickname { font-family: 'Courier New', Courier, monospace; color: #ff9900; }
         .location { color: #ccc; }
         .subscription-site-name { font-weight: bold; color: #aaa; }
         .remove-link { margin-left: 5px; color: #f88; font-size: 0.9em; cursor: pointer; }
         #status-message { margin-top: 10px; padding: 5px; background-color: #444; border-radius: 3px; display: none; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        {{ header_section|safe}}
    </div>

    {% if site_name == 'tor_setup_pending' and onion_address == None %}
    <div style="background-color: #500; color: white; padding: 10px; text-align: center;">
        <strong>Warning:</strong> Tor Onion Service setup failed or is pending. Site name may be incorrect. Check logs.
    </div>
    {% endif %}

    <div class="content">
        <div class="feed-panel">
            <h2><span class="nickname">{{ profile.nickname if profile else 'User' }}</span> Feed</h2>
            {% if profile and profile.location %}
                <span class="site-info">Location: <em>{{ profile.location }}</em></span>
                <br/>
            {% endif %}
            {% if profile and profile.description %}
                <span class="site-info">Bio: {{ bmd2html(profile.description) | safe }}</span>
                <br/>
            {% endif %}
            <hr/>
             <div id="status-message"></div>
            {% if logged_in %}
            <form method="post" action="{{ url_for('post') }}">
                <textarea id="content" name="content" rows="3" placeholder="What's happening? (Max {{ MAX_MSG_LENGTH }} bytes)" maxlength="{{ MAX_MSG_LENGTH * 2 }}" required></textarea><br>
                <input type="submit" value="Post" style="margin: 5px;">
                <span id="byte-count" style="font-size: 0.8em; margin-left: 10px;">0 / {{ MAX_MSG_LENGTH }} bytes</span>
                <span style="font-size: 0.8em; margin-left: 10px;"> Markdown: *italic*, **bold**, [link](url) </span>
            </form>
            <hr/>
            {% endif %}
            {% for post in user_feed %}
            <div class="post-box">
                <div class="post-meta">
                    Posted: {{ post.display_timestamp }}
                     | <a href="{{ url_for('view_message', timestamp=post.timestamp) }}" title="View raw message format">Raw</a>
                     | <a href="{{ url_for('view_thread', message_id=post.site + ':' + post.timestamp) }}" title="View thread">Thread</a>
                </div>
                <div class="post-content">{{ bmd2html(post.display_content) | safe }}</div>
            </div>
            {% else %}
            <p>No posts yet.</p>
            {% endfor %}
        </div>

        <div class="subscriptions-panel" id="subscriptions-panel">
            {{ subscriptions_panel|safe }}
        </div>
    </div>

    <div class="footer">
        {{ footer_section|safe }}
    </div>

    <div id="add-subscription-modal" style="display:none; position:fixed; top:20%; left:50%; transform:translate(-50%, 0); background-color:#333; padding:20px; border: 1px solid #555; border-radius:5px; z-index:1000; width:460px;">
      <form method="post" action="{{ url_for('add_subscription') }}">
        <label for="onion_address" style="color:#eee;">Enter .onion address:</label><br>
        <input type="text" name="onion_address" id="onion_address" required pattern="^(https?:\\/\\/)?[a-z2-7]{56}(?:\\.onion)?\\/?$" title="Enter a valid v3 Onion address (56 characters, optionally starting with http:// or https://, optionally ending with .onion, and optionally a trailing slash)" style="width: 440px;">
        <br><br>
        <input type="submit" value="Add Subscription">
        <button type="button" onclick="document.getElementById('add-subscription-modal').style.display='none';">Cancel</button>
      </form>
    </div>

    <script>
      function showStatus(message, isError = false) {
          const statusDiv = document.getElementById('status-message');
          if (statusDiv) {
              statusDiv.textContent = message;
              statusDiv.style.color = isError ? '#f88' : '#8f8';
              statusDiv.style.display = 'block';
          }
      }

      {% if logged_in %}
        document.getElementById("add-subscription-btn").addEventListener("click", function() {
          document.getElementById("add-subscription-modal").style.display = "block";
        });

        document.getElementById("fetch-subscriptions-btn").addEventListener("click", function() {
          const btn = this;
          btn.disabled = true;
          btn.textContent = "Fetching...";
          showStatus("Initiating subscription fetch...");

          fetch("{{ url_for('fetch_subscriptions') }}", { method: 'POST' })
            .then(response => response.json().then(data => ({ status: response.status, body: data })))
            .then(({ status, body }) => {
              if (status === 429) {
                  showStatus(body.message || "Fetch is already in progress.", true);
              } else if (status >= 200 && status < 300) {
                  showStatus(body.message || "Fetch process started in background.");
              } else {
                   showStatus(body.error || `Error starting fetch (Status: ${status})`, true);
              }
            })
            .catch(error => {
              console.error('Error starting subscription fetch:', error);
              showStatus("Client-side error during fetch request. Check console.", true);
            })
            .finally(() => {
               setTimeout(() => {
                   btn.disabled = false;
                   btn.textContent = "Fetch";
               }, 1500);
            });
        });
      {% endif %}

      function bindRemoveLinks() {
          var subList = document.getElementById("subscription-list");
          if (subList) {
              subList.addEventListener("click", function(event) {
                  if (event.target.classList.contains("remove-link")) {
                      event.preventDefault();
                      const siteDir = event.target.dataset.siteDir;
                      const siteOnion = siteDir + ".onion";
                      if (confirm(`Are you sure you want to remove the subscription for ${siteOnion}? This will delete the cached messages.`)) {
                          showStatus(`Removing subscription ${siteOnion}...`);
                          fetch(`/remove_subscription/${siteDir}`, {
                              method: 'POST',
                              headers: {
                                   'Content-Type': 'application/json'
                              }
                          })
                          .then(response => response.json().then(data => ({ ok: response.ok, body: data })))
                          .then(({ok, body}) => {
                              if (ok && body.success) {
                                  showStatus(`Subscription for ${siteOnion} removed. Reloading...`);
                                  window.location.reload();
                              } else {
                                  showStatus(`Error removing subscription: ${body.error || 'Unknown error'}`, true);
                              }
                          })
                          .catch(error => {
                              console.error('Error removing subscription:', error);
                              showStatus('Failed to remove subscription. Check console.', true);
                          });
                      }
                  }
              });
          }
      }

      function refreshSubscriptionsPanel() {
          fetch("{{ url_for('subscriptions_panel') }}")
              .then(response => response.text())
              .then(html => {
                  document.getElementById("subscriptions-panel").innerHTML = html;
                  bindRemoveLinks();
              })
              .catch(error => {
                  console.error("Error refreshing subscriptions panel:", error);
              });
      }

      setInterval(refreshSubscriptionsPanel, 60000); // Refresh every 60 seconds

      // Initial binding on page load
      document.addEventListener("DOMContentLoaded", function () {
          bindRemoveLinks();
      });

      const textarea = document.getElementById('content');
      if (textarea) {
          textarea.addEventListener('keydown', e => {
              if (e.key === 'Enter') e.preventDefault();
          });
          textarea.addEventListener('input', () => {
              textarea.value = textarea.value.replace(/[\\r\\n]+/g, ' ');
          });

          document.addEventListener("DOMContentLoaded", function () {
              const counter = document.getElementById("byte-count");
              const maxBytes = {{ MAX_MSG_LENGTH }};
              if (counter) {
                  const updateCounter = () => {
                      const text = textarea.value;
                      const byteLength = new TextEncoder().encode(text).length;
                      counter.textContent = `${byteLength} / ${maxBytes} bytes`;
                      if (byteLength > maxBytes) {
                          counter.style.color = "red";
                      } else {
                           counter.style.color = "#aaa";
                      }
                  };
                  textarea.addEventListener("input", updateCounter);
                  updateCounter();
              }
          });
      }
    </script>
</body>
</html>
"""

SUBSCRIPTIONS_TEMPLATE = """
<div class="subscriptions-header">
    Timeline 
    <span style="font-size: 0.6em; margin-left:20px;">{{ utc_time }}</span>
</div>
{% for post in combined_feed %}
<div class="post-box {% if post.site == site_name %}own-post-highlight{% endif %}">
    <div class="post-meta">
        {% if post.site == site_name %}
            <span class="nickname">{{ profile.nickname if profile else 'Local user' }}: </span>
            <span class="subscription-site-name">{{ post.site }}.onion</span> <br>
            {{ post.display_timestamp }}
            | <a href="{{ url_for('view_message', timestamp=post.timestamp) }}" title="View raw message format">Raw</a>
        {% else %}
            {% if post.nickname %}
                <span class="nickname">{{ post.nickname }}: </span>
            {% endif %}
            <span class="subscription-site-name">{{ post.site }}.onion</span> <br>
            {{ post.display_timestamp }}
            | <a href="http://{{ post.site }}.onion/{{ post.timestamp }}" target="_blank" title="View raw message on originating site">Raw</a>
        {% endif %}
        | <a href="{{ url_for('view_thread', message_id=post.site + ':' + post.timestamp) }}" title="View thread">Thread</a>
        {% if post.reply_id != null_reply_address %}
            <ul><li>
                <em>In reply to:</em>
                <a href="http://{{ post.reply_id.split(':')[0] }}.onion/thread/{{ post.reply_id }}">{{ post.reply_id }}</a>
            </li></ul>
        {% endif %}
    </div>
    <div class="post-content">{{ bmd2html(post.display_content) | safe }}</div>
</div>
{% else %}
<p>No messages found in timeline.</p>
{% if subscriptions %}
<p>
  {% if logged_in %} Click 'Fetch' to update subscriptions. {% else %} Login to fetch subscription updates. {% endif %}
</p>
{% endif %}
{% endfor %}
<hr style="border-color: #444; margin: 20px 0;">
<h4>Subscribed Sites:</h4>
<ul id="subscription-list">
    {% for sub in subscriptions %}
        <li>
           {% if sub.nickname %}
               <span class="nickname">{{ sub.nickname }}: </span>
           {% endif %}
           <a href="http://{{ sub.site }}.onion" target="_blank">{{ sub.site }}.onion</a>
           {% if logged_in %}
               <a href="#" class="remove-link" data-site-dir="{{ sub.site }}" title="Remove subscription for {{ sub.site }}.onion">[Remove]</a>
           {% endif %}
        </li>
    {% else %}
        <li>No subscriptions added yet.</li>
    {% endfor %}
</ul>
"""

HEADER_TEMPLATE = """
        <span class="logo">
            <img src="{{ url_for('static', filename='logo_128.png') }}" height="32" width="32" style="margin-right:10px;"/>
            Blitter
        </span>
        <span class="controls">
            {% if logged_in %}
                <a href="{{ url_for('profile') }}">Profile</a> |
                <button id="fetch-subscriptions-btn" title="Fetch subscriptions">Fetch</button> |
                <button id="add-subscription-btn" title="Add subscription">Add</button> |
                <a href="{{ url_for('logout') }}">Logout</a>
            {% else %}
                {% if profile.nickname %} <span class="nickname">{{ profile.nickname }}</span> {% endif %} <a href="{{ url_for('login') }}">login</a>
            {% endif %}
        </span>
        <div class="site-name">
            {% if onion_address %}
                    {{ ('<a href="http://' ~ onion_address ~ '">' ~ profile.nickname ~ '</a>') | safe if profile else 'User' }}:
            {% else %}
                <span class="nickname"> {{ profile.nickname if profile else 'User' }}:</span>
            {% endif %}

            <span id="site-name">{{ onion_address or site_name }}</span>
            <button title="Copy" onclick="navigator.clipboard.writeText(document.getElementById('site-name').innerText)" style="font-family: system-ui, sans-serif;">⧉</button>
        </div>
"""

FOOTER_TEMPLATE="""
       <p style="text-align: center; font-size: 0.8em;">Blitter Node v{{ app_version }} | Protocol v{{ protocol_version }}</p>
 """

VIEW_THREAD_TEMPLATE="""
<!doctype html>
<html>
<head>
    <title>Blitter Feed - {{ site_name }}</title>
    <style>
        body { font-family: sans-serif; margin: 0; background-color: #222; color: #eee; }
        .header, .footer { background-color: #333; padding: 10px; overflow: hidden; }
        .header .logo { float: left; font-weight: bold; display: flex; align-items: center; }
        .header .site-name { text-align: center; font-size: 1.1em; margin: 0 180px; line-height: 1.5em; }
        .header .controls { float: right; }
        .content { display: flex; flex-wrap: wrap; padding: 10px; }
        .feed-panel { flex: 1; min-width: 200px; margin-right: 10px; margin-bottom: 10px; }
        .subscriptions-panel { flex: 2; min-width: 400px; background-color: #333; padding: 10px; border-radius: 5px; max-height: 80vh; overflow-y: auto;}
        .subscriptions-header { font-size:24px; font-weight: bold; margin-bottom: 8px; }
        .post-box { border: 1px solid #444; padding: 10px; margin-bottom: 4px; background-color: #2a2a2a; border-radius: 5px;}
        .post-box.own-post-highlight { border: 1px solid #ffcc00; }
        .post-meta { font-size: 0.8em; color: #888; margin-bottom: 5px;}
        .post-meta a { color: #aaa; }
        .post-content { margin-top: 5px; white-space: pre-wrap; word-wrap: break-word; font-size: 0.9em; }
         textarea { width: 95%; background-color: #444; color: #eee; border: 1px solid #555; padding: 5px; font-family: inherit;}
         input[type=submit], button { padding: 5px 10px; background-color: #555; border: none; color: #eee; cursor: pointer; border-radius: 3px; margin-left: 5px; }
         button:disabled { background-color: #444; color: #888; cursor: not-allowed;}
         a { color: #7af; text-decoration: none; }
         a:hover { text-decoration: underline; }
         .error { color: red; font-weight: bold; }
         .site-info { margin-left: 10px; font-size: 0.9em; }
         .nickname { font-family: 'Courier New', Courier, monospace; color: #ff9900; }
         .location { color: #ccc; }
         .subscription-site-name { font-weight: bold; color: #aaa; }
         .remove-link { margin-left: 5px; color: #f88; font-size: 0.9em; cursor: pointer; }
         #status-message { margin-top: 10px; padding: 5px; background-color: #444; border-radius: 3px; display: none; font-size: 0.9em; }
         .children { margin-top: 10px; }
    </style>
</head>
<body>
    <div class="header">
        {{ header_section|safe }}
    </div>
    <div class="thread-view">
        {% if parent_post is string %}
            {{ parent_post|safe }}
        {% elif parent_post %}
            <div class="post-box {% if parent_post.site == site_name %}own-post-highlight{% endif %}">
                <div class="post-meta">
                    {% if parent_post.site == site_name %}
                        <span class="nickname">{{ profile.nickname if profile else 'Local user' }}: </span>
                    {% else %}
                        {% if parent_post.nickname %}
                            <span class="nickname">{{ parent_post.nickname }}: </span>
                        {% endif %}
                    {% endif %}
                    <span class="subscription-site-name">{{ parent_post.site }}.onion</span> <br>
                    {{ parent_post.display_timestamp }}
                    | <a href="{{ url_for('view_message', timestamp=parent_post.timestamp) }}" title="View raw message format">Raw</a>
                    | <a href="http://{{ parent_post.site }}.onion/thread/{{ parent_post.site }}:{{ parent_post.timestamp }}" target="_blank" title="View">Thread</a>
                    {% if parent_post.reply_id != null_reply_address %}
                        <ul><li>
                            <em>In reply to:</em>
                            <a href="http://{{ parent_post.reply_id.split(':')[0] }}.onion/thread/{{ parent_post.reply_id }}">{{ parent_post.reply_id }}</a>
                        </li></ul>
                    {% endif %}
                </div>
                <div class="post-content">{{ bmd2html(parent_post.display_content) | safe }}</div>
            </div>
        {% endif %}
        <hr/>
        <div class="post-box {% if selected_post.site == site_name %}own-post-highlight{% endif %}"{% if selected_post.reply_id != null_reply_address %} style="margin-left:50px;"{% endif %}>
            <div class="post-meta">
                {% if selected_post.site == site_name %}
                    <span class="nickname">{{ profile.nickname if profile else 'Local user' }}: </span>
                    <span class="subscription-site-name">{{ selected_post.site }}.onion</span> <br>
                    {{ selected_post.display_timestamp }}
                    | <a href="{{ url_for('view_message', timestamp=selected_post.timestamp) }}" title="View raw message format">Raw</a>
                {% else %}
                    {% if selected_post.nickname %}
                        <span class="nickname">{{ selected_post.nickname }}: </span>
                    {% endif %}
                    <span class="subscription-site-name">{{ selected_post.site }}.onion</span> <br>
                    {{ selected_post.display_timestamp }}
                    | <a href="http://{{ selected_post.site }}.onion/{{ selected_post.timestamp }}" target="_blank" title="View raw message on originating site">Raw</a>
                {% endif %}
                | <a href="{{ url_for('view_thread', message_id=selected_post.site + ':' + selected_post.timestamp) }}" title="View thread">Thread</a>
            </div>
            <div class="post-content">{{ bmd2html(selected_post.display_content) | safe }}</div>
        </div>
        <hr/>
        {{ thread_section|safe }}
        <hr/>
        {% if logged_in %}
        <form method="post" action="{{ url_for('post') }}">
            <textarea id="content" name="content" rows="3" placeholder="What's happening? (Max {{ MAX_MSG_LENGTH }} bytes)" maxlength="{{ MAX_MSG_LENGTH * 2 }}" required></textarea><br>
            <input type="text" name="reply_id" value="{{ selected_post.site }}:{{ selected_post.timestamp }}" readonly title="You are replying to the selected bleet." size="73">
            <input type="submit" value="Post" style="margin: 5px;">
            <span id="byte-count" style="font-size: 0.8em; margin-left: 10px;">0 / {{ MAX_MSG_LENGTH }} bytes</span>
            <span style="font-size: 0.8em; margin-left: 10px;"> Markdown: *italic*, **bold**, [link](url) </span>
        </form>
        <hr/>
        {% endif %}
    </div>
    <div class="footer">
        {{ footer_section|safe }}
    </div>
    <!-- JavaScript for toggling collapsible child threads -->
    <script>
    function toggleChildren(id) {
        var elem = document.getElementById(id);
        var toggleLink = document.getElementById(id.replace('-children','-toggle'));
        if (elem.style.display === 'none') {
             elem.style.display = 'block';
             if (toggleLink) toggleLink.textContent = '[-] Collapse replies';
        } else {
             elem.style.display = 'none';
             if (toggleLink) toggleLink.textContent = '[+] Expand replies';
        }
    }
    </script>
</body>
</html>
"""

# --- Flask Routes ---

@app.route('/thread/<string:message_id>')
def view_thread(message_id):

    profile_data = load_json(PROFILE_FILE) or {}

    if (':' not in message_id) or (len(message_id) != len(NULL_REPLY_ADDRESS)):
        abort(400, description="Invalid message id format.")
    message_site, message_timestamp = message_id.split(':')

    if not is_valid_onion_address(message_site):
        abort(400, description="Invalid blitter (onion) address.")

    if not (len(message_timestamp) == 16 and all(c in string.hexdigits for c in message_timestamp)):
        abort(400, description="Invalid timestamp format.")

    thread_section = ""

    local_message = False  # Whether this selected post is in the local feed
    # Assemble combined feed
    user_feed_data = load_json(FEED_FILE) or []
    user_processed_feed = []
    if isinstance(user_feed_data, list):
         for msg_str in user_feed_data:
            parsed_msg = parse_message_string(msg_str)
            if parsed_msg:
                if parsed_msg['site'] == SITE_NAME:
                    user_processed_feed.append(parsed_msg)
                else:
                    print(f"Notice: Skipping message with mismatched site name '{parsed_msg['site']}' (expected '{SITE_NAME}') in main feed '{FEED_FILE}'.", file=sys.stderr)

    _, subscription_raw_feed, nicknames_map = load_subscriptions()
    combined_feed = user_processed_feed + subscription_raw_feed
    try:
        combined_feed.sort(key=lambda x: x['timestamp'], reverse=True)
    except Exception as e:
        print(f"Error sorting combined feed: {e}", file=sys.stderr)
    for post in combined_feed:
        if post['site'] != SITE_NAME:
            post['nickname'] = nicknames_map.get(post['site'])
        else:
            post['nickname'] = profile_data.get('nickname', 'User')

    selected_post = None
    parent_post = None
    for post in combined_feed:
        if post['site'] == message_site and post['timestamp'] == message_timestamp:
            selected_post = post
            # Display parent if exists
            if post['reply_id'] != NULL_REPLY_ADDRESS:
                for parent in combined_feed:
                    if parent['site'] + ':' + parent['timestamp'] == post['reply_id']:
                        parent_post = parent
                        break
                if not parent_post:
                    parent_post = f"Parent post is not cached locally: http://{message_site}.onion/thread/{post['reply_id']}"
            else:
                parent_post = "This post is not a reply. It is an original bleet."
            break

    if not selected_post:
        abort(404, description="Message not stored or cached on this Blitter site.")

    # Define a recursive function to build a collapsible thread tree.
    def generate_children_html(parent, feed, level=1):
        parent_id = f"{parent['site']}_{parent['timestamp']}"
        # Find all posts that are direct replies to the parent
        children = [child for child in feed if child['reply_id'] == f"{parent['site']}:{parent['timestamp']}"]
        if not children:
            return ""
        html = f'<div class="children" style="margin-left:{level * 20}px; border-left:1px dashed #555; padding-left:10px;">'
        html += f'<a href="javascript:void(0);" onclick="toggleChildren(\'{parent_id}-children\');" id="{parent_id}-toggle">[-] Collapse replies</a>'
        html += f'<div id="{parent_id}-children">'
        for child in children:
            child_id = f"{child['site']}_{child['timestamp']}"
            html += '<div class="post-box" style="margin-top:10px;">'
            html += '<div class="post-meta">'
            if child['site'] == SITE_NAME:
                html += f'<span class="nickname">{profile_data.get("nickname", "Local user")}: </span>'
            else:
                if child.get("nickname"):
                    html += f'<span class="nickname">{child["nickname"]}: </span>'
            html += f'<span class="subscription-site-name">{child["site"]}.onion</span> <br>'
            html += f'{child["display_timestamp"]} '
            html += f'| <a href="{url_for("view_message", timestamp=child["timestamp"])}" title="View raw message format">Raw</a> '
            html += f'| <a href="http://{child["site"]}.onion/thread/{child["site"]}:{child["timestamp"]}" target="_blank" title="View thread">Thread</a>'
            if child["reply_id"] != NULL_REPLY_ADDRESS:
                html += f'<br><em>In reply to:</em> <a href="http://{child["reply_id"].split(":")[0]}.onion/thread/{child["reply_id"]}">{child["reply_id"]}</a>'
            html += '</div>'  # end post-meta
            html += f'<div class="post-content">{bmd2html(child["display_content"])}</div>'
            # Recursively add any replies to this child
            html += generate_children_html(child, feed, level+1)
            html += '</div>'  # end child post-box
        html += '</div></div>'
        return html

    # Build the tree of replies for the selected message.
    thread_section = generate_children_html(selected_post, combined_feed, 1)

    utc_now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    header_section = render_template_string(
        HEADER_TEMPLATE,
        logged_in=is_logged_in(),
        profile=profile_data,
        site_name=SITE_NAME,
        onion_address=onion_address,
    )

    footer_section = render_template_string(
        FOOTER_TEMPLATE,
        protocol_version=PROTOCOL_VERSION,
        app_version=APP_VERSION
    )

    view_thread_html = render_template_string(
        VIEW_THREAD_TEMPLATE,
        header_section=header_section,
        utc_now=utc_now,
        logged_in=is_logged_in(),
        parent_post=parent_post,
        selected_post=selected_post,
        thread_section=thread_section,
        footer_section=footer_section,
        site_name=SITE_NAME,
        profile=profile_data,
        MAX_MSG_LENGTH=MAX_MSG_LENGTH,
        bmd2html=bmd2html,
        null_reply_address=NULL_REPLY_ADDRESS
    )         

    return view_thread_html

@app.route('/')
def index():
    user_feed_data = load_json(FEED_FILE) or []
    user_processed_feed = []
    if isinstance(user_feed_data, list):
        for msg_str in user_feed_data:
            parsed_msg = parse_message_string(msg_str)
            if parsed_msg:
                if parsed_msg['site'] == SITE_NAME:
                    user_processed_feed.append(parsed_msg)
                else:
                    print(f"Notice: Skipping message with mismatched site name '{parsed_msg['site']}' (expected '{SITE_NAME}') in main feed '{FEED_FILE}'.", file=sys.stderr)

    utc_now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    profile_data = load_json(PROFILE_FILE) or {}
    user_feed_for_panel = sorted(user_processed_feed, key=lambda x: x['timestamp'], reverse=True)

    header_section = render_template_string(
        HEADER_TEMPLATE,
        logged_in=is_logged_in(),
        profile=profile_data,
        site_name=SITE_NAME,
        onion_address=onion_address,
    )

    footer_section = render_template_string(
        FOOTER_TEMPLATE,
        protocol_version=PROTOCOL_VERSION,
        app_version=APP_VERSION
    )

    return render_template_string(
        INDEX_TEMPLATE,
        header_section=header_section,
        footer_section=footer_section,
        user_feed=user_feed_for_panel,
        subscriptions_panel=subscriptions_panel(),
        logged_in=is_logged_in(),
        site_name=SITE_NAME,
        onion_address=onion_address,
        profile=profile_data,
        MAX_MSG_LENGTH=MAX_MSG_LENGTH,
        bmd2html=bmd2html
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('index'))
    error = None
    if request.method == 'POST':
        secret_word_data = load_json(os.path.join(KEYS_DIR, SECRET_WORD_FILE))
        if not secret_word_data or 'secret_word' not in secret_word_data:
             error = 'Secret word configuration is missing or invalid.'
             print("Login failed: Secret word file error.", file=sys.stderr)
             return render_template_string(LOGIN_TEMPLATE, error=error)
        secret_word = secret_word_data.get("secret_word")
        onion_dir = find_first_onion_service_dir(KEYS_DIR)
        if not onion_dir:
            error = 'Cannot locate Tor key directory to verify passphrase.'
            print("Login failed: Could not find Tor key directory.", file=sys.stderr)
            return render_template_string(LOGIN_TEMPLATE, error=error)
        try:
            correct_passphrase = " ".join(get_passphrase(onion_dir, secret_word))
        except FileNotFoundError:
             error = 'Tor key file not found. Cannot verify passphrase.'
             print("Login failed: Tor key file missing.", file=sys.stderr)
             return render_template_string(LOGIN_TEMPLATE, error=error)
        except Exception as e:
            error = f'Error generating expected passphrase: {e}'
            print(f"Login failed: Error during passphrase generation - {e}", file=sys.stderr)
            return render_template_string(LOGIN_TEMPLATE, error=error)
        if request.form.get('passphrase') == correct_passphrase:
            session['logged_in'] = True
            session.permanent = True
            app.permanent_session_lifetime = datetime.timedelta(days=7)
            print("User logged in.")
            return redirect(url_for('index'))
        else:
            print("Login failed: Invalid Credentials.")
            error = 'Invalid Credentials. Please try again.'
            time.sleep(1)
    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    print("User logged out.")
    return redirect(url_for('index'))

@app.route('/about')
def about():
    profile_data = load_json(PROFILE_FILE) or {}
    display_site_name = onion_address or SITE_NAME
    if display_site_name.startswith("tor_"):
         display_site_name = "Unknown Site (Tor Setup Issue)"
    about_profile = []
    if not display_site_name.startswith("Unknown"):
        about_profile.append(f'{display_site_name}')
    if profile_data.get("nickname"): about_profile.append(f'nickname: {profile_data["nickname"]}')
    if profile_data.get("location"): about_profile.append(f'Loc: {profile_data["location"]}')
    if profile_data.get("description"): about_profile.append(f'Desc: {profile_data["description"]}')
    if profile_data.get("email"): about_profile.append(f'Email: {profile_data["email"]}')
    if profile_data.get("website"): about_profile.append(f'Website: {profile_data["website"]}')
    if not about_profile:
         return "No profile information available.", 200, {'Content-Type': 'text/plain; charset=utf-8'}
    return "\n".join(about_profile), 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if not is_logged_in():
        return redirect(url_for('login'))
    profile_data = load_json(PROFILE_FILE) or {}
    if request.method == 'POST':
        profile_data['nickname'] = request.form.get('nickname', profile_data.get('nickname', '')).strip()
        profile_data['location'] = request.form.get('location', profile_data.get('location', '')).strip()
        profile_data['description'] = request.form.get('description', profile_data.get('description', '')).strip()
        profile_data['email'] = request.form.get('email', profile_data.get('email', '')).strip()
        profile_data['website'] = request.form.get('website', profile_data.get('website', '')).strip()
        save_json(PROFILE_FILE, profile_data)
        print(f"Profile updated.")
        return redirect(url_for('profile'))
    profile_data.setdefault('nickname', '')
    profile_data.setdefault('location', '')
    profile_data.setdefault('description', '')
    profile_data.setdefault('email', '')
    profile_data.setdefault('website', '')
    return render_template_string(PROFILE_TEMPLATE, profile=profile_data)

@app.route('/post', methods=['POST'])
def post():
    if not is_logged_in():
        print("Error: Unauthorized attempt to post.", file=sys.stderr)
        abort(403)
    content = request.form.get('content')
    if not content or not content.strip():
         print("Post rejected: Empty content.")
         return redirect(url_for('index'))
    new_message_str, timestamp = create_message_string(content, request.form.get('reply_id'))
    if not new_message_str:
        print("Error: Failed to create message string (check logs). Post rejected.", file=sys.stderr)
        return redirect(url_for('index'))
    try:
        feed_data = load_json(FEED_FILE) or []
        if not isinstance(feed_data, list):
            print(f"Warning: Feed file '{FEED_FILE}' contained invalid data. Resetting to empty list before appending.", file=sys.stderr)
            feed_data = []
        feed_data.append(new_message_str)
        save_json(FEED_FILE, feed_data)
        print(f"New post added with timestamp: {timestamp}")
    except Exception as e:
         print(f"Error saving post to feed file {FEED_FILE}: {e}", file=sys.stderr)
         return redirect(url_for('index'))
    return redirect(url_for('index'))

@app.route('/feed')
def feed():
    feed_data = load_json(FEED_FILE) or []
    if not isinstance(feed_data, list):
        return "", 200, {'Content-Type': 'text/plain; charset=utf-8'}
    if not SITE_NAME or SITE_NAME.startswith("tor_"):
         print("Warning: /feed requested but SITE_NAME is not valid. Returning empty feed.", file=sys.stderr)
         return "", 200, {'Content-Type': 'text/plain; charset=utf-8'}
    site_feed = []
    for msg_str in feed_data:
         parsed_msg = parse_message_string(msg_str)
         if parsed_msg and parsed_msg['site'] == SITE_NAME:
             site_feed.append(msg_str)
    return "\n".join(site_feed), 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/subs')
def subs():
    sub_dirs = []
    try:
        if os.path.isdir(SUBSCRIPTIONS_DIR):
             sub_dirs = [d for d in os.listdir(SUBSCRIPTIONS_DIR)
                         if os.path.isdir(os.path.join(SUBSCRIPTIONS_DIR, d))
                         and len(d) == 56
                         and all(c in string.ascii_lowercase + string.digits + '234567' for c in d)]
    except Exception as e:
        print(f"Error accessing subscriptions directory '{SUBSCRIPTIONS_DIR}': {e}", file=sys.stderr)
    return "\n".join(sorted(sub_dirs)), 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/<string:timestamp>')
def view_message(timestamp):
    if not (len(timestamp) == 16 and all(c in string.hexdigits for c in timestamp)):
        abort(404, description="Invalid timestamp format.")
    if SITE_NAME and not SITE_NAME.startswith("tor_"):
        feed_data = load_json(FEED_FILE) or []
        if not isinstance(feed_data, list):
             print(f"Warning: Feed file '{FEED_FILE}' is missing or invalid during message view.", file=sys.stderr)
        else:
            for msg_str in feed_data:
                if f"|{timestamp}|" in msg_str:
                     parsed_msg = parse_message_string(msg_str)
                     if parsed_msg and parsed_msg['site'] == SITE_NAME and parsed_msg['timestamp'] == timestamp:
                         try:
                             ascii_msg = msg_str.encode('ascii').decode('ascii')
                             return ascii_msg, 200, {'Content-Type': 'text/plain; charset=ascii'}
                         except UnicodeEncodeError:
                              print(f"Warning: Message {timestamp} contains non-ASCII characters, returning as UTF-8.", file=sys.stderr)
                              return msg_str, 200, {'Content-Type': 'text/plain; charset=utf-8'}
    abort(404, description="Message not found.")

@app.route('/add_subscription', methods=['POST'])
def add_subscription():
    if not is_logged_in():
        abort(403)
    onion_input = request.form.get('onion_address', '').strip().lower()
    onion_input = onion_input.replace("http://","").replace("https://","")
    if onion_input.endswith('/'):
         onion_input = onion_input[:-1]
    if not onion_input:
        return redirect(url_for('index'))
    if onion_input.endswith('.onion'):
         dir_name = onion_input[:-6]
    else:
         dir_name = onion_input
         onion_input += '.onion'
    if not (len(dir_name) == 56 and all(c in string.ascii_lowercase + string.digits + '234567' for c in dir_name)):
         print(f"Add subscription failed: Invalid address format for {onion_input}", file=sys.stderr)
         return redirect(url_for('index'))
    if dir_name == SITE_NAME:
         print(f"Add subscription failed: Cannot subscribe to own site {onion_input}", file=sys.stderr)
         return redirect(url_for('index'))
    subscription_dir = os.path.join(SUBSCRIPTIONS_DIR, dir_name)
    if os.path.isdir(subscription_dir):
        print(f"Subscription attempt for already subscribed site: {onion_input}")
        return redirect(url_for('index'))
    about_info = {}
    try:
        print(f"Attempting to fetch /about for new subscription: {onion_input}")
        proxies = {"http": SOCKS_PROXY, "https": SOCKS_PROXY}
        about_url = f"http://{onion_input}/about"
        r = requests.get(about_url, proxies=proxies, timeout=FETCH_TIMEOUT)
        r.raise_for_status()
        about_text = r.text.strip()
        if not about_text:
            print(f"Warning: /about for {onion_input} returned empty response.")
        else:
            lines = about_text.splitlines()
            temp_info = {}
            if lines and lines[0].strip().lower() != onion_input:
                 print(f"Warning: /about first line '{lines[0]}' does not match expected onion address '{onion_input}'")
            for line in lines[1:]:
                 if ":" in line:
                     try:
                         key, value = line.split(":", 1)
                         key = key.strip().lower()
                         value = value.strip()
                         if key in ['nickname', 'loc', 'desc', 'email', 'website']:
                              if key == 'loc': key = 'location'
                              if key == 'desc': key = 'description'
                              temp_info[key] = value
                     except ValueError:
                          print(f"Warning: Malformed line in /about from {onion_input}: {line}", file=sys.stderr)
            about_info = temp_info
            print(f"Successfully fetched /about info for {onion_input}: {about_info}")
    except requests.exceptions.Timeout:
        print(f"Error fetching /about from {onion_input}: Timeout after {FETCH_TIMEOUT}s", file=sys.stderr)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching /about from {onion_input}: {e}", file=sys.stderr)
    except Exception as e:
        print(f"Unexpected error fetching /about from {onion_input}: {e}", file=sys.stderr)
    try:
        os.makedirs(subscription_dir, exist_ok=True)
        notes_file = os.path.join(subscription_dir, "notes.json")
        notes_data = {
            "nickname": about_info.get('nickname', ''),
            "location": about_info.get('location', ''),
            "description": about_info.get('description', ''),
            "email": about_info.get('email', ''),
            "website": about_info.get('website', '')
        }
        save_json(notes_file, notes_data)
        print(f"Successfully added subscription: {onion_input} (Directory: {subscription_dir})")
        print(f"Submitting initial fetch task for new subscription {dir_name}")
        fetch_executor.submit(fetch_and_process_feed, dir_name)
    except Exception as e:
        print(f"Error creating subscription directory or notes file for {onion_input}: {e}", file=sys.stderr)
        if os.path.exists(subscription_dir):
             try:
                  if not os.listdir(subscription_dir):
                       os.rmdir(subscription_dir)
             except Exception as clean_e:
                  print(f"Error cleaning up directory {subscription_dir} after failed add: {clean_e}", file=sys.stderr)
        return redirect(url_for('index'))
    return redirect(url_for('index'))

def fetch_and_process_feed(site_dir):
    site_onion = f"{site_dir}.onion"
    feed_url = f"http://{site_onion}/feed"
    cache_file = os.path.join(SUBSCRIPTIONS_DIR, site_dir, 'feedcache.json')
    print(f"[Fetcher] Starting fetch for: {site_onion}")
    new_messages_added = 0
    try:
        existing_cache = load_json(cache_file) or []
        if not isinstance(existing_cache, list):
            print(f"[Fetcher] Warning: Invalid cache file {cache_file}. Starting fresh.", file=sys.stderr)
            existing_cache = []
        existing_timestamps = set()
        valid_existing_cache = []
        for msg_str in existing_cache:
             parsed = parse_message_string(msg_str)
             if parsed and parsed['site'] == site_dir:
                 existing_timestamps.add(parsed['timestamp'])
                 valid_existing_cache.append(msg_str)
             elif parsed:
                  print(f"[Fetcher] Warning: Found message from wrong site ({parsed['site']}) in cache {cache_file}. Discarding.", file=sys.stderr)
        proxies = {"http": SOCKS_PROXY, "https": SOCKS_PROXY}
        fetched_content = None
        try:
             with requests.get(feed_url, proxies=proxies, timeout=FETCH_TIMEOUT, stream=True) as response:
                 response.raise_for_status()
                 try:
                     fetched_content = response.content.decode('utf-8', errors='replace')
                 except UnicodeDecodeError as ude:
                     print(f"[Fetcher] Unicode decode error reading feed from {feed_url}: {ude}. Trying latin-1.", file=sys.stderr)
                     fetched_content = response.content.decode('latin-1', errors='replace')
        except requests.exceptions.Timeout:
             print(f"[Fetcher] Timeout fetching {feed_url}", file=sys.stderr)
             return 0
        except requests.exceptions.RequestException as e:
             print(f"[Fetcher] Error fetching {feed_url}: {e}", file=sys.stderr)
             return 0
        except Exception as e:
             print(f"[Fetcher] Unexpected error during fetch request for {feed_url}: {e}", file=sys.stderr)
             return 0
        if fetched_content is None:
             print(f"[Fetcher] Failed to retrieve content from {feed_url}", file=sys.stderr)
             if len(valid_existing_cache) != len(existing_cache):
                  print(f"[Fetcher] Saving cleaned cache for {site_onion} after fetch failure.", file=sys.stderr)
                  save_json(cache_file, valid_existing_cache)
             return 0
        if not fetched_content.strip():
            print(f"[Fetcher] Empty feed received from {site_onion}")
            if len(valid_existing_cache) != len(existing_cache):
                print(f"[Fetcher] Saving cleaned cache for {site_onion} after receiving empty feed.", file=sys.stderr)
                save_json(cache_file, valid_existing_cache)
            return 0
        processed_new_messages = []
        malformed_lines = 0
        mismatched_site_lines = 0
        duplicate_timestamps = 0
        for line in fetched_content.strip().splitlines():
            msg_str = line.strip()
            if not msg_str: continue
            parsed_msg = parse_message_string(msg_str)
            if not parsed_msg:
                if malformed_lines < 5:
                     print(f"[Fetcher] Invalid message format received from {site_onion}: {msg_str[:100]}...", file=sys.stderr)
                malformed_lines += 1
                continue
            if parsed_msg['site'] != site_dir:
                 if mismatched_site_lines < 5:
                      print(f"[Fetcher] SECURITY WARNING: Message received from {site_onion} claims to be from {parsed_msg['site']}. DISCARDING: {msg_str[:100]}...", file=sys.stderr)
                 mismatched_site_lines +=1
                 continue
            if parsed_msg['timestamp'] not in existing_timestamps:
                processed_new_messages.append(msg_str)
                existing_timestamps.add(parsed_msg['timestamp'])
                new_messages_added += 1
            else:
                 duplicate_timestamps += 1
        if malformed_lines > 5:
             print(f"[Fetcher] ...skipped {malformed_lines - 5} more malformed lines from {site_onion}.", file=sys.stderr)
        if mismatched_site_lines > 5:
             print(f"[Fetcher] ...skipped {mismatched_site_lines - 5} more mismatched site lines from {site_onion}.", file=sys.stderr)
        if duplicate_timestamps > 0:
             print(f"[Fetcher] Skipped {duplicate_timestamps} duplicate messages already present in cache for {site_onion}.")
        cache_updated = False
        if new_messages_added > 0:
            updated_cache = valid_existing_cache + processed_new_messages
            save_json(cache_file, updated_cache)
            print(f"[Fetcher] Added {new_messages_added} new messages for {site_onion}. Cache size: {len(updated_cache)}")
            cache_updated = True
        else:
            if len(valid_existing_cache) != len(existing_cache):
                 print(f"[Fetcher] No new messages, but saving cleaned cache for {site_onion}. Cache size: {len(valid_existing_cache)}")
                 save_json(cache_file, valid_existing_cache)
                 cache_updated = True
            else:
                 print(f"[Fetcher] No new messages found for {site_onion}")
        if not cache_updated:
            print(f"[Fetcher] Cache file {cache_file} remains unchanged.")
    except Exception as e:
        print(f"[Fetcher] Unexpected error processing feed for {site_onion}: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 0
    return new_messages_added

def run_fetch_cycle():
    global fetch_lock, fetch_executor, fetch_timer, FETCH_CYCLE
    print(f"[{datetime.datetime.now().isoformat()}] Attempting scheduled fetch cycle...")
    if fetch_lock.acquire(blocking=False):
        print("[Fetcher] Acquired lock for scheduled run.")
        total_new_messages = 0
        sites_fetched_count = 0
        try:
            start_time = time.time()
            subscription_dirs = []
            if os.path.isdir(SUBSCRIPTIONS_DIR):
                subscription_dirs = [d for d in os.listdir(SUBSCRIPTIONS_DIR)
                                     if os.path.isdir(os.path.join(SUBSCRIPTIONS_DIR, d))
                                     and len(d) == 56
                                     and all(c in string.ascii_lowercase + string.digits + '234567' for c in d)]
            if not subscription_dirs:
                print("[Fetcher] No valid subscription directories found.")
            else:
                print(f"[Fetcher] Submitting {len(subscription_dirs)} sites for background fetching...")
                futures = {fetch_executor.submit(fetch_and_process_feed, site_dir): site_dir for site_dir in subscription_dirs}
                results = concurrent.futures.wait(futures)
                sites_fetched_count = len(futures)
                for future in results.done:
                     site = futures[future]
                     try:
                         new_count = future.result()
                         if new_count is not None:
                              total_new_messages += new_count
                         else:
                              print(f'[Fetcher] Warning: Task for site {site} returned None.', file=sys.stderr)
                     except Exception as exc:
                          print(f'[Fetcher] Site {site} generated an exception during fetch: {exc}', file=sys.stderr)
                if results.not_done:
                     print(f"[Fetcher] Warning: {len(results.not_done)} fetch tasks did not complete.", file=sys.stderr)
                     for future in results.not_done:
                          site = futures[future]
                          print(f"[Fetcher] Task for site {site} did not complete.", file=sys.stderr)
            end_time = time.time()
            duration = end_time - start_time
            print(f"[Fetcher] Scheduled fetch cycle completed in {duration:.2f} seconds.")
            print(f"[Fetcher] Attempted fetch for {sites_fetched_count} sites, added {total_new_messages} total new messages across all feeds.")
        except Exception as e:
            print(f"[Fetcher] Error during scheduled fetch cycle coordination: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
        finally:
            fetch_lock.release()
            print("[Fetcher] Released lock for scheduled run.")
    else:
        print("[Fetcher] Skipping scheduled run: Fetch lock already held (likely by manual fetch).")
    app_is_exiting = getattr(sys, 'is_exiting', False)
    if not app_is_exiting:
        print(f"[Fetcher] Scheduling next fetch cycle in {FETCH_CYCLE} seconds.")
        fetch_timer = threading.Timer(FETCH_CYCLE, run_fetch_cycle)
        fetch_timer.daemon = True
        fetch_timer.start()
    else:
         print("[Fetcher] Application is exiting, not scheduling next fetch cycle.")

@app.route('/fetch_subscriptions', methods=['POST'])
def fetch_subscriptions():
    if not is_logged_in():
        return jsonify({"error": "Authentication required"}), 403
    global fetch_lock, fetch_executor
    print("[Fetcher] Received request to MANUALLY fetch subscriptions.")
    if fetch_lock.acquire(blocking=False):
        print("[Fetcher] Acquired lock for manual run.")
        submitted_tasks = 0
        try:
            subscription_dirs = []
            if os.path.isdir(SUBSCRIPTIONS_DIR):
                subscription_dirs = [d for d in os.listdir(SUBSCRIPTIONS_DIR)
                                     if os.path.isdir(os.path.join(SUBSCRIPTIONS_DIR, d))
                                     and len(d) == 56
                                     and all(c in string.ascii_lowercase + string.digits + '234567' for c in d)]
            if not subscription_dirs:
                print("[Fetcher] No subscriptions found to fetch.")
                fetch_lock.release()
                print("[Fetcher] Released lock for manual run (no sites).")
                return jsonify({"message": "No subscriptions to fetch."})
            print(f"[Fetcher] Submitting {len(subscription_dirs)} sites for background fetching (manual trigger)...")
            for site_dir in subscription_dirs:
                fetch_executor.submit(fetch_and_process_feed, site_dir)
                submitted_tasks += 1
            print(f"[Fetcher] Submitted {submitted_tasks} site(s) for background fetching.")
            return jsonify({"message": f"Started background fetch for {submitted_tasks} subscription(s). Refresh later to see results."})
        except Exception as e:
            print(f"[Fetcher] Error submitting manual fetch tasks: {e}", file=sys.stderr)
            return jsonify({"error": "Failed to start fetch process."}), 500
        finally:
             fetch_lock.release()
             print("[Fetcher] Released lock for manual run (submission phase).")
    else:
        print("[Fetcher] Manual fetch request denied: Fetch lock already held.")
        return jsonify({"message": "Fetch operation already in progress. Please wait."}), 429

@app.route('/remove_subscription/<string:site_dir>', methods=['POST'])
def remove_subscription(site_dir):
    if not is_logged_in():
        print(f"Unauthorized attempt to remove subscription: {site_dir}", file=sys.stderr)
        return jsonify({"error": "Authentication required"}), 403
    if not (len(site_dir) == 56 and all(c in string.ascii_lowercase + string.digits + '234567' for c in site_dir)):
        print(f"Invalid site directory format in removal request: {site_dir}", file=sys.stderr)
        return jsonify({"error": "Invalid subscription identifier format."}), 400
    base_dir = os.path.abspath(SUBSCRIPTIONS_DIR)
    target_path = os.path.abspath(os.path.join(base_dir, site_dir))
    if not target_path.startswith(base_dir + os.sep):
        print(f"SECURITY ALERT: Path traversal attempt detected in remove_subscription for: {site_dir} (Resolved: {target_path})", file=sys.stderr)
        return jsonify({"error": "Invalid subscription identifier."}), 400
    if os.path.isdir(target_path):
        try:
            shutil.rmtree(target_path)
            print(f"Removed subscription directory: {target_path}")
            return jsonify({"success": True, "message": f"Subscription {site_dir}.onion removed."})
        except FileNotFoundError:
            print(f"Subscription directory not found during removal attempt (race condition?): {target_path}", file=sys.stderr)
            return jsonify({"error": "Subscription not found."}), 404
        except PermissionError:
             print(f"Permission error removing subscription directory: {target_path}", file=sys.stderr)
             return jsonify({"error": "Permission denied while removing subscription."}), 500
        except Exception as e:
            print(f"Error removing subscription directory {target_path}: {e}", file=sys.stderr)
            return jsonify({"error": "An error occurred while removing the subscription."}), 500
    else:
        print(f"Subscription directory not found: {target_path}", file=sys.stderr)
        return jsonify({"error": "Subscription not found."}), 404

# Subscriptions panel content for AJAX refresh
@app.route('/subscriptions_panel')
def subscriptions_panel():
    user_feed_data = load_json(FEED_FILE) or []
    user_processed_feed = []
    if isinstance(user_feed_data, list):
         for msg_str in user_feed_data:
            parsed_msg = parse_message_string(msg_str)
            if parsed_msg:
                if parsed_msg['site'] == SITE_NAME:
                    user_processed_feed.append(parsed_msg)
                else:
                    print(f"Notice: Skipping message with mismatched site name '{parsed_msg['site']}' (expected '{SITE_NAME}') in main feed '{FEED_FILE}'.", file=sys.stderr)
    # Load subscriptions
    subscriptions_with_nicknames, subscription_raw_feed, nicknames_map = load_subscriptions()
    combined_feed = user_processed_feed + subscription_raw_feed
    try:
        combined_feed.sort(key=lambda x: x['timestamp'], reverse=True)
    except Exception as e:
        print(f"Error sorting combined feed: {e}", file=sys.stderr)
    for post in combined_feed:
        if post['site'] != SITE_NAME:
            post['nickname'] = nicknames_map.get(post['site'])
 
    profile_data = load_json(PROFILE_FILE) or {}
    utc_now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    return render_template_string(
        SUBSCRIPTIONS_TEMPLATE,
        utc_time=utc_now,
        combined_feed=combined_feed,
        subscriptions=subscriptions_with_nicknames,
        logged_in=is_logged_in(),
        profile=profile_data,
        bmd2html=bmd2html,
        null_reply_address=NULL_REPLY_ADDRESS,
        site_name=SITE_NAME
    )

def initialize_app():
    global SITE_NAME, onion_address
    print(f"Initializing Blitter Node v{APP_VERSION} (Protocol: {PROTOCOL_VERSION})...")
    os.makedirs(SUBSCRIPTIONS_DIR, exist_ok=True)
    os.makedirs(KEYS_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    static_dir = os.path.join(script_dir, 'static')
    os.makedirs(static_dir, exist_ok=True)
    logo_path = os.path.join(static_dir, 'logo_128.png')
    if not os.path.exists(logo_path):
         print(f"Warning: Logo file not found at {logo_path}. Ensure 'static/logo_128.png' exists.", file=sys.stderr)
    print(f"Directories checked/created: {SUBSCRIPTIONS_DIR}, {KEYS_DIR}, {LOG_DIR}, static")
    secret_file_path = os.path.join(KEYS_DIR, SECRET_WORD_FILE)
    if not os.path.exists(secret_file_path):
        try:
            save_json(secret_file_path, {"secret_word": "changeme"})
            print(f'Default secret word file created at {secret_file_path}.')
            print("***************************************************************************", file=sys.stderr)
            print("IMPORTANT: Default secret word 'changeme' set. Change this for security!", file=sys.stderr)
            print(f"Edit the file: {secret_file_path}", file=sys.stderr)
            print("***************************************************************************", file=sys.stderr)
        except Exception as e:
            print(f"FATAL ERROR: Could not create secret word file at {secret_file_path}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        try:
            secret_data = load_json(secret_file_path)
            if not secret_data or 'secret_word' not in secret_data:
                 print(f"Warning: Secret word file {secret_file_path} exists but is invalid or empty.", file=sys.stderr)
            elif secret_data['secret_word'] == 'changeme':
                 print("***************************************************************************", file=sys.stderr)
                 print("WARNING: Using default secret word 'changeme'. Change this for security!", file=sys.stderr)
                 print(f"Edit the file: {secret_file_path}", file=sys.stderr)
                 print("***************************************************************************", file=sys.stderr)
        except Exception as e:
             print(f"Warning: Could not read or parse secret word file {secret_file_path}: {e}", file=sys.stderr)
    if not os.path.exists(PROFILE_FILE):
        print(f"Profile file '{PROFILE_FILE}' not found, creating default.")
        save_json(PROFILE_FILE, {
          "nickname": "User",
          "location": "", "description": "My Blitter profile.",
          "email": "", "website": ""
        })
    else:
         print(f"Profile file found: {PROFILE_FILE}")
         profile_data = load_json(PROFILE_FILE)
         if not isinstance(profile_data, dict):
              print(f"Warning: Profile file '{PROFILE_FILE}' is empty or invalid. Resetting to default.", file=sys.stderr)
              save_json(PROFILE_FILE, {"nickname": "User", "location": "", "description": "My Blitter profile.", "email": "", "website": ""})
    if not os.path.exists(FEED_FILE):
        print(f"Feed file '{FEED_FILE}' not found, creating empty feed.")
        save_json(FEED_FILE, [])
    else:
        feed_data = load_json(FEED_FILE)
        if not isinstance(feed_data, list):
             print(f"Warning: Feed file '{FEED_FILE}' does not contain a valid JSON list. Resetting to empty.", file=sys.stderr)
             save_json(FEED_FILE, [])
        else:
             print(f"Feed file found: {FEED_FILE}")
    if not STEM_AVAILABLE:
        print("\n--- Tor Integration Disabled ---")
        print("Skipping Tor setup because 'stem' library is not installed.")
        print("Install it using: pip install stem")
        SITE_NAME = "tor_disabled"
        onion_address = None
        return
    print("\n--- Starting Tor Onion Service Setup ---")
    onion_dir = find_first_onion_service_dir(KEYS_DIR)
    if onion_dir:
        key_blob = get_key_blob(onion_dir)
        if key_blob:
            print(f"Using key from: {onion_dir}")
            if start_tor_hidden_service(key_blob):
                print(f"--- Tor Onion Service setup successful. Site Name: {SITE_NAME} ---")
            else:
                print("--- Tor Onion Service setup failed. ---", file=sys.stderr)
                SITE_NAME = "tor_failed"
                onion_address = None
        else:
            print(f"Failed to extract key blob from {onion_dir}.", file=sys.stderr)
            SITE_NAME = "tor_key_error"
            onion_address = None
    else:
        print("No suitable Tor key directory found. Onion service not started.", file=sys.stderr)
        SITE_NAME = "tor_no_key"
        onion_address = None
    if SITE_NAME.startswith("tor_"):
         print("\n*****************************************************", file=sys.stderr)
         print(f"WARNING: Tor setup did not complete successfully (Status: {SITE_NAME}).", file=sys.stderr)
         print("The application will run, but might not be accessible via Tor", file=sys.stderr)
         print("and the site name used for posts may be incorrect.", file=sys.stderr)
         print("Ensure Tor service is running, configured with ControlPort 9051", file=sys.stderr)
         print("and a valid v3 key exists in the 'keys' directory.", file=sys.stderr)
         print("Check Tor logs (usually /var/log/tor/log or similar) for details.", file=sys.stderr)
         print("*****************************************************\n", file=sys.stderr)
    if onion_dir and not SITE_NAME.startswith("tor_"):
        try:
            secret_word = None
            secret_word_data = load_json(os.path.join(KEYS_DIR, SECRET_WORD_FILE))
            if secret_word_data and 'secret_word' in secret_word_data:
                secret_word = secret_word_data.get("secret_word")
            if secret_word:
                 print(f'Using secret word from {secret_file_path} to derive passphrase.')
                 passphrase_words = get_passphrase(onion_dir, secret_word)
                 passphrase = " ".join(passphrase_words)
                 print("\n------------------------------------------------------")
                 print(f'--- Passphrase for local user login is: "{passphrase}" ---')
                 print("------------------------------------------------------\n")
            else:
                print("\n--- Cannot display passphrase: Could not read secret word from file. ---", file=sys.stderr)
        except FileNotFoundError:
             print(f"\n--- Cannot display passphrase: Necessary file not found (key or secret word). ---", file=sys.stderr)
        except Exception as e:
            print(f"\n--- Warning: Error generating or displaying passphrase: {e} ---", file=sys.stderr)
    elif onion_dir:
         print("\n--- Cannot display passphrase due to Tor setup issue. ---", file=sys.stderr)
    else:
        print("\n--- Cannot display passphrase as Tor key directory was not found. ---", file=sys.stderr)

if __name__ == '__main__':
    sys.is_exiting = False
    initialize_app()
    if not SITE_NAME.startswith("tor_"):
        print("\n--- Starting initial background fetch cycle ---")
        initial_fetch_thread = threading.Thread(target=run_fetch_cycle, daemon=True)
        initial_fetch_thread.start()
    else:
        print("\n--- Skipping initial background fetch due to Tor setup issue ---")
    print(f"\n--- Starting Flask server ---")
    if onion_address:
        print(f"Site Address: http://{onion_address}")
    else:
        print(f"Site Address: N/A (Tor Status: {SITE_NAME})")
    print(f"Local Access: http://{FLASK_HOST}:{FLASK_PORT}")
    print("Press Ctrl+C to stop.")
    try:
        app.run(debug=False, host=FLASK_HOST, port=FLASK_PORT, threaded=True, use_reloader=False)
    except KeyboardInterrupt:
         print("\nCtrl+C received, shutting down...")
    except SystemExit as e:
         print(f"\nSystem exit called ({e}). Shutting down...")
    except Exception as e:
         print(f"\nFlask server encountered an error: {e}", file=sys.stderr)
         import traceback
         traceback.print_exc()
    finally:
         print("\nInitiating shutdown sequence...")
         sys.is_exiting = True
         cleanup_tor_service()
         print("\nExiting Blitter Node.")
