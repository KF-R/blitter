#!/usr/bin/env python3
import os
import json
import time
import datetime
import sys  # Added for stderr
import base64  # Added for key encoding
import atexit  # Added for cleanup
import string
import requests # Added for fetching subscriptions
import concurrent.futures # Added for async fetching
import threading # Added for background task feedback and timer
import shutil # Added for directory removal
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session, abort
from markupsafe import escape
import re # Added for parsing markdown
import hashlib # For authentication

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
APP_VERSION = '0.1.9'
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
SOCKS_PROXY = "socks5h://127.0.0.1:9050" # SOCKS proxy for Tor requests
FETCH_TIMEOUT = 30 # Timeout in seconds for fetching subscription feeds
FETCH_CYCLE = 180 # Automatic fetch interval in seconds

# --- Global Variables ---
SITE_NAME = "tor_setup_pending"  # Placeholder until Tor setup
PROTOCOL_VERSION = "0001"
# --- Tor Globals ---
tor_controller = None
tor_service_id = None
onion_address = None
# --- Fetching Globals ---
fetch_executor = concurrent.futures.ThreadPoolExecutor(max_workers=5) # Executor for background fetches
active_fetches = {} # Track active fetch tasks (optional for status, might be less useful with lock)
fetch_lock = threading.Lock() # Lock to prevent concurrent manual/auto fetch cycles
fetch_timer = None # Timer object for rescheduling background fetches


# --- Helper Functions ---

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
        sys.exit(1) # Exit if wordlist is missing
    except Exception as e:
        print(f"FATAL ERROR: Failed to load BIP-0039 wordlist '{filepath}': {e}", file=sys.stderr)
        sys.exit(1)

def get_passphrase(service_dir, secret_word) -> list: # Return type hint added
    """
    Reads the last 64 bytes of the binary file,
    combines it with the secret_word and computes the SHA-256 hash,
    truncates it to 66 bits (6 x 11 bits), and maps each 11-bit segment
    to a word in the BIP-0039 word list.
    """
    # Load the word list
    bip39 = load_bip39_wordlist()

    # Read last 64 bytes (payload) of the file
    key_file_path = os.path.join(service_dir, "hs_ed25519_secret_key")

    try:
        with open(key_file_path, "rb") as f:
            f.seek(-64, os.SEEK_END)
            payload = f.read(64)
            if len(payload) != 64: # Ensure 64 bytes were actually read
                raise IOError(f"Could not read the last 64 bytes from {key_file_path}")
    except FileNotFoundError:
        print(f"Error: Key file not found at {key_file_path}", file=sys.stderr)
        raise # Re-raise the error to be handled by the caller
    except IOError as e:
        print(f"Error reading key file {key_file_path}: {e}", file=sys.stderr)
        raise # Re-raise the error

    # Compute SHA-256 hash and convert to an integer
    digest = hashlib.sha256(payload + secret_word.encode("utf-8")).digest()
    digest_int = int.from_bytes(digest, byteorder="big")

    # Truncate the digest to the top 66 bits
    truncated = digest_int >> (256 - 66)

    # Extract 6 segments of 11 bits each
    words = []
    for i in range(6):
        shift = (6 - i - 1) * 11
        index = (truncated >> shift) & 0x7FF  # 0x7FF = 2047 (11 bits)
        words.append(bip39[index])
    return words

def bmd2html(bmd_string):
    """Converts a Blitter Markdown string to valid html"""
    if not isinstance(bmd_string, str):
        return "" # Return empty string if input is not a string

    html_string = escape(bmd_string) # Escape HTML first

    # Convert [text](url) to <a href="url" target="_blank">text</a>
    # Make sure URLs are also escaped properly within the href attribute
    def replace_link(match):
        text = match.group(1)
        url = match.group(2)
        # Basic validation/sanitization for URL (allow http, https)
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url # Add default protocol if missing? Or reject? Let's add for now.
        # Escape the URL itself before putting it in href
        safe_url = escape(url)
        return f'<a href="{safe_url}" target="_blank">{escape(text)}</a>' # Escape text too

    html_string = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', replace_link, html_string)

    # Convert ***text*** to <strong><em>text</em></strong>
    html_string = re.sub(r'\*\*\*([^\*]+)\*\*\*', r'<strong><em>\1</em></strong>', html_string)

    # Convert **text** to <strong>text</strong>
    html_string = re.sub(r'\*\*([^\*]+)\*\*', r'<strong>\1</strong>', html_string)

    # Convert *text* to <em>text</em>
    html_string = re.sub(r'\*([^\*]+)\*', r'<em>\1</em>', html_string)

    return html_string

def load_json(filename):
    """Loads JSON data from a file."""
    try:
        with open(filename, 'r', encoding='utf-8') as f: # Specify encoding
            return json.load(f)
    # Allow FileNotFoundError for notes.json as well
    except FileNotFoundError:
        # Don't warn for expected missing files like caches or notes
        if 'feedcache.json' not in filename and 'notes.json' not in filename:
             print(f"Info: File not found {filename}, returning None.", file=sys.stderr)
        return None # Return None to indicate file not found
    except json.JSONDecodeError as e:
        print(f"Warning: Could not decode JSON from {filename}: {e}", file=sys.stderr)
        return None # Return None to indicate invalid JSON
    except Exception as e:
         print(f"Error loading JSON from {filename}: {e}", file=sys.stderr)
         return None # Return None on other errors

def save_json(filename, data):
    """Saves JSON data to a file."""
    try:
        # Ensure directory exists before saving
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w', encoding='utf-8') as f: # Specify encoding
            json.dump(data, f, indent=2, ensure_ascii=False) # Use ensure_ascii=False for broader char support
    except IOError as e:
        print(f"Error: Could not write JSON to {filename}: {e}", file=sys.stderr)
    except Exception as e:
        print(f"Unexpected error saving JSON to {filename}: {e}", file=sys.stderr)

def is_logged_in():
    """Checks if the user is logged in via session."""
    return 'logged_in' in session and session['logged_in']

def get_current_timestamp_hex():
    """Gets the current time as a 16-byte hex timestamp."""
    ms_timestamp = int(time.time() * 1000)
    return f'{ms_timestamp:016x}'

def format_timestamp_for_display(hex_timestamp):
    """Formats a hex timestamp for display."""
    try:
        ms_timestamp = int(hex_timestamp, 16)
        # Check for unreasonably large values which might indicate format errors
        # Let's assume timestamps beyond year 2100 are unlikely/invalid for this app
        if ms_timestamp > 4102444800000: # Milliseconds for Jan 1, 2100
            return "Invalid Timestamp (Future)"
        # Check for negative or zero timestamps
        if ms_timestamp <= 0:
             return "Invalid Timestamp (Past)"

        dt_object = datetime.datetime.fromtimestamp(ms_timestamp / 1000, tz=datetime.timezone.utc)
        day = dt_object.day
        if 11 <= day <= 13:
            suffix = 'th'
        else:
            suffixes = {1: 'st', 2: 'nd', 3: 'rd'}
            suffix = suffixes.get(day % 10, 'th')
        # Format to include milliseconds
        return dt_object.strftime(f'%d{suffix} %b \'%y %H:%M:%S.%f')[:-3] + ' (UTC)' # Use %d for day
    except (ValueError, TypeError, OverflowError):
        return "Invalid Timestamp"

def parse_message_string(msg_str):
    """Parses a message string into a dictionary, returns None if invalid."""
    if not isinstance(msg_str, str) or not msg_str.startswith('|') or not msg_str.endswith('|'):
        return None
    parts = msg_str.strip('|').split('|')
    if len(parts) != 8:
        return None
    # Basic validation of parts
    protocol, site, timestamp, reply_id, expiration, flag_int, length_field, content = parts
    if len(protocol) != 4 or not all(c in string.hexdigits for c in protocol): return None
    if len(site) != 56 or not all(c in string.ascii_lowercase + string.digits + '234567' for c in site): return None # Stricter check
    if len(timestamp) != 16 or not all(c in string.hexdigits for c in timestamp): return None
    # Stricter reply_id check: site:timestamp format
    reply_parts = reply_id.split(':')
    if len(reply_parts) != 2 or len(reply_parts[0]) != 57 or len(reply_parts[1]) != 16:
         # Allow the 'null' reply_id
         if reply_id != '0'*57 + ':' + '0'*16:
            return None
    if len(expiration) != 16 or not all(c in string.hexdigits for c in expiration): return None
    if len(flag_int) != 16 or not all(c in string.hexdigits for c in flag_int): return None
    if len(length_field) != 3 or not length_field.isdigit(): return None

    try:
        expected_len = int(length_field)
        # Use UTF-8 byte length for validation, as content might not be pure ASCII
        actual_len = len(content.encode('utf-8', errors='ignore')) # Use ignore for safety? Or surrogatepass?

        if actual_len != expected_len:
            # This is a deviation from spec, decide if strict or lenient
            # Let's be lenient for now but log a warning
             print(f"Warning: Message length field {expected_len} does not match UTF-8 byte length {actual_len}. Content: '{content[:50]}...'", file=sys.stderr)
             # Pass through, display might handle it
             pass

        # Basic check for non-printable characters (optional, might slow things down)
        # if not all(c in string.printable or c in '\n\r\t' for c in content):
        #     print(f"Warning: Message content contains non-printable characters. Content: '{content[:50]}...'", file=sys.stderr)

    except ValueError:
        return None # Should not happen if isdigit() passed

    return {
        'protocol': protocol,
        'site': site,
        'timestamp': timestamp,
        'display_timestamp': format_timestamp_for_display(timestamp),
        'reply_id': reply_id,
        'content': content, # Keep original content for cache
        'display_content': content, # Store raw content, apply escaping/markdown in template
        'expiration': expiration,
        'flags': flag_int,
        'len': length_field,
        'raw_message': msg_str # Keep the raw message string
        # 'nickname' will be added later in the index function
    }

def create_message_string(content, reply_id='0'*57 + ':' + '0'*16):
    """Creates a message string:
    |<protocol_version>|<sitename>|<timestamp>|<reply-id>|<expiration>|<flag_int>|<len>|<content>|
    """
    global SITE_NAME, PROTOCOL_VERSION # Use the globally set values
    if SITE_NAME.startswith("tor_"): # Don't create messages if Tor failed
         print("Error: Cannot create message, Tor setup incomplete/failed.", file=sys.stderr)
         return None, None

    timestamp = get_current_timestamp_hex()
    # Validate content type
    if not isinstance(content, str):
         print("Error: Message content must be a string.", file=sys.stderr)
         return None, None

    # Filter content? Let's trust the user for now, but enforce length limit based on UTF-8 bytes
    content_bytes = content.encode('utf-8', errors='ignore') # Use ignore for safety
    content_length = len(content_bytes)

    if content_length > MAX_MSG_LENGTH:
        # Truncate based on bytes, then decode back safely
        truncated_bytes = content_bytes[:MAX_MSG_LENGTH]
        content = truncated_bytes.decode('utf-8', errors='ignore') # Decode back to string
        content_length = len(content.encode('utf-8', errors='ignore')) # Recalculate length
        print(f"Warning: Message content truncated to {content_length} bytes (max {MAX_MSG_LENGTH}).", file=sys.stderr)


    expiration = 'f'*16  # Placeholder for expiration (max value)
    flag_int = '0'*16    # Placeholder for flags

    # Validate reply_id format (stricter check)
    if not isinstance(reply_id, str):
         reply_id = '0'*57 + ':' + '0'*16 # Default if not string
    else:
        reply_parts = reply_id.split(':')
        if not (len(reply_parts) == 2 and len(reply_parts[0]) == 57 and len(reply_parts[1]) == 16):
             # Allow the 'null' reply_id specifically
             if reply_id != '0'*57 + ':' + '0'*16:
                  print(f"Warning: Invalid reply_id format '{reply_id}'. Using default.", file=sys.stderr)
                  reply_id = '0'*57 + ':' + '0'*16  # Default if invalid format


    len_field = f"{content_length:03d}"
    message = f"|{PROTOCOL_VERSION}|{SITE_NAME}|{timestamp}|{reply_id}|{expiration}|{flag_int}|{len_field}|{content}|"
    return message, timestamp

# --- Tor Integration Functions ---

def find_first_onion_service_dir(keys_dir):
    """Scans the keys directory for the first valid v3 onion service key directory."""
    if not os.path.isdir(keys_dir):
        print(f"Error: Keys directory '{keys_dir}' not found.", file=sys.stderr)
        return None

    try:
        items = sorted(os.listdir(keys_dir)) # Sort for predictable behaviour
    except OSError as e:
        print(f"Error listing keys directory '{keys_dir}': {e}", file=sys.stderr)
        return None

    for item in items:
        service_dir = os.path.join(keys_dir, item)
        key_file = os.path.join(service_dir, "hs_ed25519_secret_key")
        if os.path.isdir(service_dir) and os.path.isfile(key_file):
            print(f"Found potential key directory: {service_dir}")
            return service_dir
    print(f"Info: No suitable key directories found in '{keys_dir}'.", file=sys.stderr)
    return None

def get_key_blob(service_dir):
    """Reads the secret key file and returns the base64 encoded 64-byte key material."""
    key_file_path = os.path.join(service_dir, "hs_ed25519_secret_key")
    try:
        with open(key_file_path, 'rb') as f:
            key_data = f.read()

        # Tor >= 0.4.7 uses different header
        # Check for both old and new formats
        is_new_format = key_data.startswith(b'== ed25519v1-secret: type0 ==\x00\x00\x00')
        is_old_format = key_data.startswith(b'== ed25519v1-secret: type0 ==') and len(key_data) == 96

        if not (is_new_format or is_old_format):
             raise ValueError(f"Key file format is incorrect. Header mismatch.")

        if is_new_format and len(key_data) < 64+32: # 32 header + 64 key
             raise ValueError(f"Key file size is incorrect for new format ({len(key_data)} bytes found)")
        elif is_old_format and len(key_data) != 96:
             raise ValueError(f"Key file size is incorrect for old format ({len(key_data)} bytes found)")

        # Key material is always the last 64 bytes
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
    """Connects to Tor, sends ADD_ONION command, and sets globals."""
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
            f"Flags=Detach " # Keep service running after controller disconnects
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
                # Basic validation for v3 onion address format (56 chars, specific charset)
                if len(parsed_service_id) == 56 and all(c in string.ascii_lowercase + string.digits + '234567' for c in parsed_service_id):
                     parsed_onion_address = f"{parsed_service_id}.onion"
                     break # Found valid ID, stop searching
                else:
                     print(f"Warning: Received unexpected ServiceID format: {parsed_service_id}", file=sys.stderr)
                     parsed_service_id = None # Invalidate if format is wrong


        if not parsed_service_id or not parsed_onion_address:
            raw_response_content = response.content(decode=False) # Get raw bytes if parsing fails
            raise ValueError(f"ADD_ONION command seemed to succeed, but failed to parse valid ServiceID/OnionAddress from response. Raw content: {raw_response_content}")

        print(f"Successfully created/attached service: {parsed_onion_address}")
        print(f"Service points to http://{FLASK_HOST}:{FLASK_PORT}")

        tor_controller = controller # Keep controller connection for cleanup
        tor_service_id = parsed_service_id
        onion_address = parsed_onion_address
        SITE_NAME = parsed_service_id # SITE_NAME is the onion address *without* .onion
        atexit.register(cleanup_tor_service) # Register cleanup
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
    """Sends DEL_ONION command to Tor if a service was created BY THIS INSTANCE and cleans up other resources."""
    global tor_controller, tor_service_id, fetch_timer, fetch_executor

    # --- Cancel the background fetch timer ---
    if fetch_timer:
        print("Cancelling background fetch timer...")
        fetch_timer.cancel()
        fetch_timer = None

    # --- Shutdown the thread pool executor ---
    print("Shutting down background fetch executor...")
    # Wait a short time for tasks to finish, but don't block indefinitely
    fetch_executor.shutdown(wait=True, cancel_futures=True)
    print("Fetch executor shut down.")

    # --- Remove Tor hidden service ---
    if tor_controller and tor_service_id:
        print(f"\nCleaning up Tor service: {tor_service_id}")
        try:
            # Check if controller connection is still valid
            if tor_controller.is_authenticated() and tor_controller.is_alive():
                 # Use DEL_ONION only if service wasn't persistent (no Detach flag was used?)
                 # If Detach *was* used (as it is now), DEL_ONION might fail or be unnecessary.
                 # Let's try anyway, but don't treat failure as critical.
                 print(f"Attempting DEL_ONION for {tor_service_id} (may fail if service is detached)...")
                 response = tor_controller.msg(f"DEL_ONION {tor_service_id}")
                 if response.is_ok():
                     print(f"Successfully removed service {tor_service_id}")
                 else:
                     # This is expected if Detach flag was used and Tor kept running
                     print(f"Info: DEL_ONION command response for {tor_service_id}: {response.status_type} {response.status_severity} - {response.content(decode=False)}", file=sys.stderr)
                     # Check if the error indicates it didn't exist (already gone or detached)
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
            # Always try to close the controller connection
            if tor_controller:
                try:
                    tor_controller.close()
                    print("Tor controller connection closed.")
                except Exception as close_e:
                    print(f"Warning: Error closing Tor controller during cleanup: {close_e}", file=sys.stderr)
            tor_controller = None
            tor_service_id = None # Clear ID even if cleanup failed
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
    Passphrase: <input type="password" name="passphrase"><br>
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
        .header .site-name { text-align: center; font-size: 1.1em; margin: 0 180px; line-height: 1.5em; } /* Increased margin */
        .header .controls { float: right; }
        .content { display: flex; flex-wrap: wrap; padding: 10px; }
        .feed-panel { flex: 1; min-width: 200px; margin-right: 10px; margin-bottom: 10px; }
        .subscriptions-panel { flex: 2; min-width: 400px; background-color: #333; padding: 10px; border-radius: 5px; max-height: 80vh; overflow-y: auto;}
        .post-box { border: 1px solid #444; padding: 10px; margin-bottom: 15px; background-color: #2a2a2a; border-radius: 5px;}
        .post-meta { font-size: 0.8em; color: #888; margin-bottom: 5px;}
        .post-meta a { color: #aaa; }
        .post-content { margin-top: 5px; white-space: pre-wrap; word-wrap: break-word; font-size: 0.9em; } /* Smaller font for content */
         textarea { width: 95%; background-color: #444; color: #eee; border: 1px solid #555; padding: 5px; font-family: inherit;}
         input[type=submit], button { padding: 5px 10px; background-color: #555; border: none; color: #eee; cursor: pointer; border-radius: 3px; margin-left: 5px; }
         button:disabled { background-color: #444; color: #888; cursor: not-allowed;}
         a { color: #7af; text-decoration: none; }
         a:hover { text-decoration: underline; }
         .error { color: red; font-weight: bold; }
         .site-info { margin-left: 10px; font-size: 0.9em; } /* Style for location/description */
         .nickname { font-family: 'Courier New', Courier, monospace; color: #ff9900; }
         .location { color: #ccc; }
         .subscription-site-name { font-weight: bold; color: #aaa; }
         .remove-link { margin-left: 5px; color: #f88; font-size: 0.9em; cursor: pointer; }
         #status-message { margin-top: 10px; padding: 5px; background-color: #444; border-radius: 3px; display: none; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
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
            <span class="nickname"> {{ profile.nickname if profile else 'User' }}:</span> {# Handle case where profile might not load #}
            <span id="site-name">{{ onion_address or site_name }}</span>
            <button title="Copy" onclick="navigator.clipboard.writeText(document.getElementById('site-name').innerText)" style="font-family: system-ui, sans-serif;">⧉</button>
            <br>
            <span style="font-size: 0.8em;">{{ utc_time }}</span>
        </div>
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
                <span class="site-info">Bio: {{ bmd2html(profile.description) | safe }}</span> {# Apply safe after markdown conversion #}
                <br/>
            {% endif %}
            <hr/>
             <div id="status-message"></div> {# Placeholder for status messages #}
            {% if logged_in %}
            <form method="post" action="{{ url_for('post') }}">
                <textarea id="content" name="content" rows="3" placeholder="What's happening? (Max {{ MAX_MSG_LENGTH }} bytes)" maxlength="{{ MAX_MSG_LENGTH * 2 }}" required></textarea><br> {# Adjust maxlength estimate #}
                <input type="submit" value="Post" style="margin: 5px;">
                <span id="byte-count" style="font-size: 0.8em; margin-left: 10px;">0 / {{ MAX_MSG_LENGTH }} bytes</span>
                <span style="font-size: 0.8em; margin-left: 10px;"> Markdown: *italic*, **bold**, [link](url) </span>
            </form>
            <hr/>
            {% endif %}

            {% for post in feed %}
            <div class="post-box">
                <div class="post-meta">
                    Posted: {{ post.display_timestamp }}
                    {% if post.reply_id and post.reply_id != '0'*57 + ':' + '0'*16 %}
                     | Replying to: <a href="#" title="Link to replied message (Not Implemented)">{{ post.reply_id }}</a>
                    {% endif %}
                     | <a href="{{ url_for('view_message', timestamp=post.timestamp) }}" title="View raw message format">Raw</a>
                </div>
                {# Apply markdown conversion here before | safe #}
                <div class="post-content">{{ bmd2html(post.display_content) | safe }}</div>
            </div>
            {% else %}
            <p>No posts yet.</p>
            {% endfor %}
        </div>

        {# --- SUBSCRIPTIONS PANEL --- #}
        <div class="subscriptions-panel">
            <h2>Subscriptions</h2>

             {% for sub_post in subscription_feed %}
             <div class="post-box">
                <div class="post-meta">
                    {# --- Display Nickname if available --- #}
                    {% if sub_post.nickname %}
                        <span class="nickname">{{ sub_post.nickname }}: </span>
                    {% endif %}
                    <span class="subscription-site-name">{{ sub_post.site }}.onion</span> <br>
                    {# --- End Nickname Display --- #}
                    {{ sub_post.display_timestamp }}
                    {% if sub_post.reply_id and sub_post.reply_id != '0'*57 + ':' + '0'*16 %}
                    | Replying to: <a href="#" title="Link to replied message (Not Implemented)">{{ sub_post.reply_id }}</a>
                    {% endif %}
                    | <a href="http://{{ sub_post.site }}.onion/{{ sub_post.timestamp }}" target="_blank" title="View raw message on originating site">Raw</a>
                </div>
                 {# Apply markdown conversion here before | safe #}
                <div class="post-content">{{ bmd2html(sub_post.display_content) | safe }}</div>
             </div>
             {% else %}
             <p>No messages found in subscription caches.</p>
             {% if subscriptions %}
             <p>
               {% if logged_in %} Click 'Fetch' to update. {% else %} Login to fetch updates. {% endif %}
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
                            {# --- Use sub.site for data attribute --- #}
                            <a href="#" class="remove-link" data-site-dir="{{ sub.site }}" title="Remove subscription for {{ sub.site }}.onion">[Remove]</a>
                        {% endif %}
                     </li>
                 {% else %}
                     <li>No subscriptions added yet.</li>
                 {% endfor %}
             </ul>
        </div> {# --- END SUBSCRIPTIONS PANEL --- #}

    </div> {# --- END CONTENT --- #}

    <div class="footer">
        <p style="text-align: center; font-size: 0.8em;">Blitter Node v{{ app_version }} | Protocol v{{ protocol_version }}</p>
    </div>

    {# --- MODALS --- #}
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
      // --- Status Message Helper ---
      function showStatus(message, isError = false) {
          const statusDiv = document.getElementById('status-message');
          if (statusDiv) {
              statusDiv.textContent = message;
              statusDiv.style.color = isError ? '#f88' : '#8f8';
              statusDiv.style.display = 'block';
              // Optionally hide after a few seconds
              // setTimeout(() => { statusDiv.style.display = 'none'; }, 5000);
          }
      }

      // --- SCRIPT LOGIC FOR LOGGED IN USERS ONLY ---
      {% if logged_in %}
        // Add Subscription Modal Button
        document.getElementById("add-subscription-btn").addEventListener("click", function() {
          document.getElementById("add-subscription-modal").style.display = "block";
        });

        // Fetch Subscriptions Button
        document.getElementById("fetch-subscriptions-btn").addEventListener("click", function() {
          const btn = this;
          btn.disabled = true;
          btn.textContent = "Fetching...";
          showStatus("Initiating subscription fetch..."); // Show status

          fetch("{{ url_for('fetch_subscriptions') }}", { method: 'POST' })
            .then(response => response.json().then(data => ({ status: response.status, body: data }))) // Process JSON regardless of status
            .then(({ status, body }) => {
              if (status === 429) { // 429 Too Many Requests (our custom busy signal)
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
               // Re-enable button after a short delay to prevent spamming
               setTimeout(() => {
                   btn.disabled = false;
                   btn.textContent = "Fetch";
               }, 1500); // Give some visual feedback
            });
        });

        // Remove Subscription Links
        document.getElementById("subscription-list").addEventListener("click", function(event) {
            if (event.target.classList.contains("remove-link")) {
                event.preventDefault(); // Prevent default link behavior
                const siteDir = event.target.dataset.siteDir;
                const siteOnion = siteDir + ".onion";
                if (confirm(`Are you sure you want to remove the subscription for ${siteOnion}? This will delete the cached messages.`)) {
                    showStatus(`Removing subscription ${siteOnion}...`);
                    fetch(`/remove_subscription/${siteDir}`, {
                        method: 'POST',
                        headers: {
                             'Content-Type': 'application/json'
                             // Add CSRF token header if implemented
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

      {% endif %} // --- END LOGGED IN SCRIPT LOGIC ---
    </script>
    <script>
        // --- Byte Counter for Post Textarea ---
        document.addEventListener("DOMContentLoaded", function () {
            const textarea = document.getElementById("content");
            const counter = document.getElementById("byte-count");
            const maxBytes = {{ MAX_MSG_LENGTH }};

            if (textarea && counter) {
                const updateCounter = () => {
                    // Calculate UTF-8 byte length
                    const text = textarea.value;
                    const byteLength = new TextEncoder().encode(text).length;

                    counter.textContent = `${byteLength} / ${maxBytes} bytes`;
                    if (byteLength > maxBytes) {
                        counter.style.color = "red";
                        // Optionally disable submit button if over limit?
                    } else {
                         counter.style.color = "#aaa";
                    }
                };

                textarea.addEventListener("input", updateCounter);
                updateCounter(); // initialize on load
            }
        });
    </script>

</body>
</html>
"""

# --- Flask Routes ---

@app.route('/')
def index():
    feed_data = load_json(FEED_FILE) or [] # Ensure feed_data is a list
    processed_feed = []
    if isinstance(feed_data, list):
         # Iterate through a copy for safe removal if needed, newest first
         for msg_str in reversed(feed_data[:]):
            parsed_msg = parse_message_string(msg_str)
            if parsed_msg and parsed_msg['site'] == SITE_NAME:
                 processed_feed.append(parsed_msg)
            elif parsed_msg:
                 # Log messages not belonging to the site found in the main feed
                 print(f"Notice: Skipping message with mismatched site name '{parsed_msg['site']}' (expected '{SITE_NAME}') in main feed '{FEED_FILE}'.", file=sys.stderr)
            else:
                 # Log invalid message strings found in the main feed
                 print(f"Warning: Removing invalid message string from main feed '{FEED_FILE}': {msg_str[:100]}...", file=sys.stderr)
                 # Optionally remove invalid message from feed_data and resave? Be careful with concurrent access.
                 # For simplicity, we just skip displaying it.

    utc_now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    # --- Load subscription directories and their nicknames ---
    subscriptions_with_nicknames = [] # List to hold {'site': site_dir, 'nickname': nickname}
    subscription_feed = []            # List to hold parsed messages from caches
    nicknames_map = {}                # Quick lookup map {site_dir: nickname}

    try:
        if os.path.isdir(SUBSCRIPTIONS_DIR):
             # Get sorted directory names first
             subscription_dirs_list = sorted([d for d in os.listdir(SUBSCRIPTIONS_DIR) if os.path.isdir(os.path.join(SUBSCRIPTIONS_DIR, d))])

             for site_dir in subscription_dirs_list:
                 # Load nickname from notes.json
                 nickname = None # Default nickname
                 notes_file = os.path.join(SUBSCRIPTIONS_DIR, site_dir, 'notes.json')
                 notes_data = load_json(notes_file) # load_json handles FileNotFoundError and JSON errors
                 if notes_data and isinstance(notes_data, dict) and notes_data.get('nickname'):
                     nickname = notes_data['nickname']
                 # Add to list for the static site list display
                 subscriptions_with_nicknames.append({'site': site_dir, 'nickname': nickname})
                 # Add to map for quick lookup when processing feed posts
                 nicknames_map[site_dir] = nickname

                 # Load feed cache for this site_dir
                 cache_file = os.path.join(SUBSCRIPTIONS_DIR, site_dir, 'feedcache.json')
                 cached_data = load_json(cache_file) or []
                 if isinstance(cached_data, list):
                     # Iterate through a copy for safe removal if needed
                     for msg_str in cached_data[:]:
                         parsed_msg = parse_message_string(msg_str)
                         # Important: Ensure message belongs to the site indicated by the directory
                         if parsed_msg and parsed_msg['site'] == site_dir:
                             subscription_feed.append(parsed_msg) # Add parsed message dict
                         elif parsed_msg:
                              print(f"Warning: Message site '{parsed_msg['site']}' in cache file '{cache_file}' does not match directory '{site_dir}'. Skipping display.", file=sys.stderr)
                         else:
                              print(f"Warning: Invalid message string found in cache file '{cache_file}'. Skipping display: {msg_str[:100]}...", file=sys.stderr)
                              # Optionally clean up cache file? More complex.
                 elif cached_data is not None: # File existed but wasn't a list
                      print(f"Warning: Cache file '{cache_file}' is not a valid JSON list. Skipping.", file=sys.stderr)


    except FileNotFoundError: # Should not be needed if load_json handles it, but keep for safety
        print(f"Warning: Subscriptions directory '{SUBSCRIPTIONS_DIR}' not found during index load.", file=sys.stderr)
        # Reset lists just in case
        subscriptions_with_nicknames = []
        subscription_feed = []
        nicknames_map = {}
    except Exception as e:
         print(f"Error loading subscription data or notes: {e}", file=sys.stderr)
         # Reset lists on error
         subscriptions_with_nicknames = []
         subscription_feed = []
         nicknames_map = {}

    # Sort combined subscription feed by timestamp (newest first)
    try:
        subscription_feed.sort(key=lambda x: x['timestamp'], reverse=True)
    except Exception as e:
        print(f"Error sorting subscription feed: {e}", file=sys.stderr) # Handle potential errors if parsing failed somehow

    # Iterate through the sorted feed and add the nickname using the map
    for post in subscription_feed:
        post['nickname'] = nicknames_map.get(post['site']) # Use .get() for safety

    # Load profile data
    profile_data = load_json(PROFILE_FILE) or {} # Ensure profile_data is a dict

    return render_template_string(
        INDEX_TEMPLATE,
        feed=processed_feed,
        subscription_feed=subscription_feed, # Pass the augmented and sorted subscription feed
        logged_in=is_logged_in(),
        site_name=SITE_NAME,
        onion_address=onion_address,
        utc_time=utc_now,
        protocol_version=PROTOCOL_VERSION,
        app_version=APP_VERSION,
        subscriptions=subscriptions_with_nicknames, # Pass list of dicts for static list
        profile=profile_data,
        MAX_MSG_LENGTH=MAX_MSG_LENGTH, # Pass max length to template
        bmd2html=bmd2html # Pass markdown function
    )


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login route"""
    if is_logged_in():
        return redirect(url_for('index'))

    error = None
    if request.method == 'POST':

        # Don't need onion_address here, just the key directory and secret word
        secret_word_data = load_json(os.path.join(KEYS_DIR, SECRET_WORD_FILE))
        if not secret_word_data or 'secret_word' not in secret_word_data:
             error = 'Secret word configuration is missing or invalid.'
             print("Login failed: Secret word file error.", file=sys.stderr)
             return render_template_string(LOGIN_TEMPLATE, error=error)
        secret_word = secret_word_data.get("secret_word")

        # Check if secret word is still the default
        # if secret_word == "changeme":
        #      error = 'Default secret word "changeme" is set. Please edit the secret_word file in the keys directory before logging in.'
        #      print("Login blocked: Default secret word 'changeme' detected.", file=sys.stderr)
        #      return render_template_string(LOGIN_TEMPLATE, error=error)

        onion_dir = find_first_onion_service_dir(KEYS_DIR)
        if not onion_dir:
            error = 'Cannot locate Tor key directory to verify passphrase.'
            print("Login failed: Could not find Tor key directory.", file=sys.stderr)
            return render_template_string(LOGIN_TEMPLATE, error=error)

        try:
            correct_passphrase = " ".join(get_passphrase(onion_dir, secret_word))
        except FileNotFoundError: # Handle specific error from get_passphrase
             error = 'Tor key file not found. Cannot verify passphrase.'
             print("Login failed: Tor key file missing.", file=sys.stderr)
             return render_template_string(LOGIN_TEMPLATE, error=error)
        except Exception as e:
            error = f'Error generating expected passphrase: {e}'
            print(f"Login failed: Error during passphrase generation - {e}", file=sys.stderr)
            return render_template_string(LOGIN_TEMPLATE, error=error)

        try:
            correct_passphrase = " ".join(get_passphrase(onion_dir, secret_word))
        except Exception as e:
            error = f'Error generating expected passphrase: {e}'
            print(f"Login failed: Error during passphrase generation - {e}", file=sys.stderr)
            return render_template_string(LOGIN_TEMPLATE, error=error)

        if request.form.get('passphrase') == correct_passphrase:
            session['logged_in'] = True
            session.permanent = True # Make session persistent
            app.permanent_session_lifetime = datetime.timedelta(days=7) # Example: 1 week session
            print("User logged in.")
            return redirect(url_for('index'))
        else:
            print("Login failed: Invalid Credentials.")
            error = 'Invalid Credentials. Please try again.'
            time.sleep(1) # delay for failed attempts

    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route('/logout')
def logout():
    """Logout route."""
    session.pop('logged_in', None)
    print("User logged out.")
    return redirect(url_for('index'))

@app.route('/about')
def about():
    """About route (public profile page)"""
    profile_data = load_json(PROFILE_FILE) or {}
    # Ensure SITE_NAME reflects the actual onion service name if available
    display_site_name = onion_address or SITE_NAME
    if display_site_name.startswith("tor_"): # Don't show error names
         display_site_name = "Unknown Site (Tor Setup Issue)"

    about_profile = []
    # Only include site name if it's reasonably set
    if not display_site_name.startswith("Unknown"):
        about_profile.append(f'{display_site_name}')

    # Only include fields if they have values
    if profile_data.get("nickname"): about_profile.append(f'nickname: {profile_data["nickname"]}')
    if profile_data.get("location"): about_profile.append(f'Loc: {profile_data["location"]}')
    if profile_data.get("description"): about_profile.append(f'Desc: {profile_data["description"]}')
    if profile_data.get("email"): about_profile.append(f'Email: {profile_data["email"]}')
    if profile_data.get("website"): about_profile.append(f'Website: {profile_data["website"]}')

    if not about_profile: # Handle case where profile is empty and site name is unknown
         return "No profile information available.", 200, {'Content-Type': 'text/plain; charset=utf-8'}

    return "\n".join(about_profile), 200, {'Content-Type': 'text/plain; charset=utf-8'}


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    """Profile viewing and editing route."""
    if not is_logged_in():
        return redirect(url_for('login'))

    profile_data = load_json(PROFILE_FILE) or {} # Ensure it's a dict

    if request.method == 'POST':
        # Update only fields present in the form, sanitizing input slightly
        profile_data['nickname'] = request.form.get('nickname', profile_data.get('nickname', '')).strip()
        profile_data['location'] = request.form.get('location', profile_data.get('location', '')).strip()
        profile_data['description'] = request.form.get('description', profile_data.get('description', '')).strip()
        profile_data['email'] = request.form.get('email', profile_data.get('email', '')).strip()
        profile_data['website'] = request.form.get('website', profile_data.get('website', '')).strip()
        # Add other editable fields here

        save_json(PROFILE_FILE, profile_data)
        print(f"Profile updated.") # Avoid logging sensitive data
        # Add a success message?
        return redirect(url_for('profile')) # Redirect to GET to show updated profile

    # Make sure all expected keys exist for the template, even if None/empty
    profile_data.setdefault('nickname', '')
    profile_data.setdefault('location', '')
    profile_data.setdefault('description', '')
    profile_data.setdefault('email', '')
    profile_data.setdefault('website', '')

    return render_template_string(PROFILE_TEMPLATE, profile=profile_data)

@app.route('/post', methods=['POST'])
def post():
    """Handles new post submissions."""
    if not is_logged_in():
        print("Error: Unauthorized attempt to post.", file=sys.stderr)
        abort(403) # Forbidden

    content = request.form.get('content')
    if not content or not content.strip():
         print("Post rejected: Empty content.")
         # Add user feedback here? e.g., flash message
         return redirect(url_for('index')) # Redirect without posting

    # Use create_message_string which handles filtering and length limits
    new_message_str, timestamp = create_message_string(content)

    if not new_message_str:
        # Error occurred during message creation (e.g., Tor not ready, content invalid)
        print("Error: Failed to create message string (check logs). Post rejected.", file=sys.stderr)
        # Add user feedback here? e.g., flash message
        return redirect(url_for('index'))

    # --- Append to Feed File (with potential locking for safety) ---
    # Basic file locking might be needed if multiple processes/threads could write
    # For simple cases, hoping Flask's single-threaded-per-request is enough,
    # but a file lock would be safer in complex setups.
    try:
        # Load just before saving to minimize race conditions
        feed_data = load_json(FEED_FILE) or [] # Ensure it's a list
        if not isinstance(feed_data, list):
            print(f"Warning: Feed file '{FEED_FILE}' contained invalid data. Resetting to empty list before appending.", file=sys.stderr)
            feed_data = []

        feed_data.append(new_message_str)
        save_json(FEED_FILE, feed_data)
        print(f"New post added with timestamp: {timestamp}")
    except Exception as e:
         print(f"Error saving post to feed file {FEED_FILE}: {e}", file=sys.stderr)
         # Add user feedback about failure?
         return redirect(url_for('index')) # Redirect even on save error?

    return redirect(url_for('index'))

@app.route('/feed')
def feed():
    """Returns the newline-separated feed containing only messages matching the current SITE_NAME."""
    feed_data = load_json(FEED_FILE) or []
    if not isinstance(feed_data, list):
        return "", 200, {'Content-Type': 'text/plain; charset=utf-8'} # Return empty if invalid

    # Ensure SITE_NAME is valid before filtering
    if not SITE_NAME or SITE_NAME.startswith("tor_"):
         print("Warning: /feed requested but SITE_NAME is not valid. Returning empty feed.", file=sys.stderr)
         return "", 200, {'Content-Type': 'text/plain; charset=utf-8'}

    site_feed = []
    for msg_str in feed_data:
         # Quick check before full parsing for performance
         # Note: This check might be unreliable if SITE_NAME appears elsewhere
         # if f"|{SITE_NAME}|" in msg_str:
         # Safer to parse first, then check
         parsed_msg = parse_message_string(msg_str)
         if parsed_msg and parsed_msg['site'] == SITE_NAME:
             site_feed.append(msg_str)

    return "\n".join(site_feed), 200, {'Content-Type': 'text/plain; charset=utf-8'}


@app.route('/subs')
def subs():
    """Returns the list of subscribed sites (directory names)."""
    sub_dirs = []
    try:
        if os.path.isdir(SUBSCRIPTIONS_DIR):
             # Filter ensure only valid site dir names (56 chars, correct alphabet) are listed
             sub_dirs = [d for d in os.listdir(SUBSCRIPTIONS_DIR)
                         if os.path.isdir(os.path.join(SUBSCRIPTIONS_DIR, d))
                         and len(d) == 56
                         and all(c in string.ascii_lowercase + string.digits + '234567' for c in d)]
    except Exception as e:
        print(f"Error accessing subscriptions directory '{SUBSCRIPTIONS_DIR}': {e}", file=sys.stderr)
        # Optionally return an error status code, but spec asks for plain text list
    return "\n".join(sorted(sub_dirs)), 200, {'Content-Type': 'text/plain; charset=utf-8'} # Sort for consistency

@app.route('/<string:timestamp>')
def view_message(timestamp):
    """Returns a specific message by its timestamp ID if it matches the current site OR a subscribed site."""
    # Validate timestamp format (16 hex characters)
    if not (len(timestamp) == 16 and all(c in string.hexdigits for c in timestamp)):
        abort(404, description="Invalid timestamp format.")

    # Check own feed first (only if SITE_NAME is valid)
    if SITE_NAME and not SITE_NAME.startswith("tor_"):
        feed_data = load_json(FEED_FILE) or []
        if not isinstance(feed_data, list):
             print(f"Warning: Feed file '{FEED_FILE}' is missing or invalid during message view.", file=sys.stderr)
             # Don't abort, just means we can't check own feed
        else:
            for msg_str in feed_data:
                # Optimisation: check timestamp before full parse
                if f"|{timestamp}|" in msg_str:
                     parsed_msg = parse_message_string(msg_str)
                     # Check site *and* timestamp match
                     if parsed_msg and parsed_msg['site'] == SITE_NAME and parsed_msg['timestamp'] == timestamp:
                         # Return raw ASCII message string as per spec
                         # Ensure it's ASCII compatible before sending with that content type
                         try:
                             ascii_msg = msg_str.encode('ascii').decode('ascii')
                             return ascii_msg, 200, {'Content-Type': 'text/plain; charset=ascii'}
                         except UnicodeEncodeError:
                              print(f"Warning: Message {timestamp} contains non-ASCII characters, returning as UTF-8.", file=sys.stderr)
                              return msg_str, 200, {'Content-Type': 'text/plain; charset=utf-8'}


    # If not in own feed, check subscription caches
    try:
        if os.path.isdir(SUBSCRIPTIONS_DIR):
             subscription_dirs = [d for d in os.listdir(SUBSCRIPTIONS_DIR) if os.path.isdir(os.path.join(SUBSCRIPTIONS_DIR, d))]
             for site_dir in subscription_dirs:
                 cache_file = os.path.join(SUBSCRIPTIONS_DIR, site_dir, 'feedcache.json')
                 cached_data = load_json(cache_file) or []
                 if isinstance(cached_data, list):
                     for msg_str in cached_data:
                          if f"|{timestamp}|" in msg_str:
                             parsed_msg = parse_message_string(msg_str)
                             # Check both timestamp and site match the cache dir
                             if parsed_msg and parsed_msg['site'] == site_dir and parsed_msg['timestamp'] == timestamp:
                                 try:
                                     ascii_msg = msg_str.encode('ascii').decode('ascii')
                                     return ascii_msg, 200, {'Content-Type': 'text/plain; charset=ascii'}
                                 except UnicodeEncodeError:
                                     print(f"Warning: Subscribed message {timestamp} contains non-ASCII characters, returning as UTF-8.", file=sys.stderr)
                                     return msg_str, 200, {'Content-Type': 'text/plain; charset=utf-8'}

    except Exception as e:
         print(f"Error searching subscription caches for message {timestamp}: {e}", file=sys.stderr)
         # Don't abort here, just means we didn't find it in caches

    # If not found anywhere
    abort(404, description="Message not found.")

# --- Route for Adding a Subscription ---

@app.route('/add_subscription', methods=['POST'])
def add_subscription():
    if not is_logged_in():
        abort(403)

    onion_input = request.form.get('onion_address', '').strip().lower()
    # Basic cleanup and validation
    onion_input = onion_input.replace("http://","").replace("https://","")
    # Remove trailing slash if present
    if onion_input.endswith('/'):
         onion_input = onion_input[:-1]

    if not onion_input:
        # Add user feedback (e.g., flash message)
        return redirect(url_for('index')) # Redirect back

    # Basic format check (v3 onion is 56 chars + .onion)
    if onion_input.endswith('.onion'):
         dir_name = onion_input[:-6]
    else:
         dir_name = onion_input
         onion_input += '.onion' # Use full .onion address for fetching

    # Validate directory name format (56 chars, specific alphabet)
    if not (len(dir_name) == 56 and all(c in string.ascii_lowercase + string.digits + '234567' for c in dir_name)):
         print(f"Add subscription failed: Invalid address format for {onion_input}", file=sys.stderr)
         # Add user feedback
         return redirect(url_for('index'))

    # Prevent subscribing to self (only if SITE_NAME is validly set)
    if SITE_NAME and not SITE_NAME.startswith("tor_") and dir_name == SITE_NAME:
         print(f"Add subscription failed: Attempt to subscribe to self ({onion_input})", file=sys.stderr)
         # Add user feedback
         return redirect(url_for('index'))

    # Check if already subscribed
    subscription_dir = os.path.join(SUBSCRIPTIONS_DIR, dir_name)
    if os.path.isdir(subscription_dir):
        print(f"Subscription attempt for already subscribed site: {onion_input}")
        # Add user feedback
        return redirect(url_for('index'))


    # --- Attempt to fetch /about to get initial info ---
    about_info = {}
    try:
        print(f"Attempting to fetch /about for new subscription: {onion_input}")
        proxies = {"http": SOCKS_PROXY, "https": SOCKS_PROXY}
        # Always use http for onion addresses
        about_url = f"http://{onion_input}/about"
        # Use stream=True and read in chunks to avoid memory issues with large responses?
        # For /about, probably not necessary.
        r = requests.get(about_url, proxies=proxies, timeout=FETCH_TIMEOUT)
        r.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        about_text = r.text.strip()
        if not about_text:
            print(f"Warning: /about for {onion_input} returned empty response.")
            # Proceed without notes
        else:
            # Parse key-value pairs (handle potential missing keys gracefully)
            lines = about_text.splitlines()
            temp_info = {}
            # First line should be the site name itself, verify?
            if lines and lines[0].strip().lower() != onion_input:
                 print(f"Warning: /about first line '{lines[0]}' does not match expected onion address '{onion_input}'")

            for line in lines[1:]: # Skip first line (address)
                 if ":" in line:
                     try:
                         key, value = line.split(":", 1)
                         key = key.strip().lower()
                         value = value.strip()
                         # Store only recognized keys
                         if key in ['nickname', 'loc', 'desc', 'email', 'website']:
                              # Map 'loc', 'desc' to full names
                              if key == 'loc': key = 'location'
                              if key == 'desc': key = 'description'
                              temp_info[key] = value
                     except ValueError:
                          print(f"Warning: Malformed line in /about from {onion_input}: {line}", file=sys.stderr)
            about_info = temp_info # Assign parsed info

    except requests.exceptions.Timeout:
        print(f"Error fetching /about from {onion_input}: Timeout after {FETCH_TIMEOUT}s", file=sys.stderr)
        # Add user feedback
        return redirect(url_for('index'))
    except requests.exceptions.RequestException as e:
        print(f"Error fetching /about from {onion_input}: {e}", file=sys.stderr)
        # Add user feedback
        return redirect(url_for('index'))
    except Exception as e:
        print(f"Unexpected error fetching /about from {onion_input}: {e}", file=sys.stderr)
        # Add user feedback
        return redirect(url_for('index'))

    # --- Create Directory and Save notes.json ---
    try:
        os.makedirs(subscription_dir, exist_ok=True)
        notes_file = os.path.join(subscription_dir, "notes.json")
        # Ensure default keys exist even if not fetched
        notes_data = {
            "nickname": about_info.get('nickname', ''),
            "location": about_info.get('location', ''),
            "description": about_info.get('description', ''),
            "email": about_info.get('email', ''),
            "website": about_info.get('website', '')
        }
        save_json(notes_file, notes_data)
        print(f"Successfully added subscription: {onion_input}")
        # Optionally trigger an initial fetch here?
        # Submit a single fetch task immediately for the new sub?
        print(f"Submitting initial fetch task for new subscription {dir_name}")
        fetch_executor.submit(fetch_and_process_feed, dir_name)

    except Exception as e:
        print(f"Error creating subscription directory or notes file for {onion_input}: {e}", file=sys.stderr)
        # Cleanup potentially created directory?
        if os.path.exists(subscription_dir):
             try:
                  # Ensure it's safe before removing - check if it's empty?
                  if not os.listdir(subscription_dir):
                       os.rmdir(subscription_dir)
             except Exception as clean_e:
                  print(f"Error cleaning up directory {subscription_dir} after failed add: {clean_e}", file=sys.stderr)
        # Add user feedback
        return redirect(url_for('index'))

    # Add success feedback
    return redirect(url_for('index'))

# --- Subscription Fetching Logic ---

def fetch_and_process_feed(site_dir):
    """Fetches feed for a single site, processes, and saves to cache. Returns number of new messages added."""
    site_onion = f"{site_dir}.onion"
    feed_url = f"http://{site_onion}/feed" # Always use http for onion
    cache_file = os.path.join(SUBSCRIPTIONS_DIR, site_dir, 'feedcache.json')
    print(f"[Fetcher] Starting fetch for: {site_onion}")
    new_messages_added = 0

    try:
        # 1. Load existing cache and timestamps
        existing_cache = load_json(cache_file) or []
        if not isinstance(existing_cache, list):
            print(f"[Fetcher] Warning: Invalid cache file {cache_file}. Starting fresh.", file=sys.stderr)
            existing_cache = []

        existing_timestamps = set()
        valid_existing_cache = []
        for msg_str in existing_cache:
             parsed = parse_message_string(msg_str)
             if parsed and parsed['site'] == site_dir: # Ensure message belongs to this site
                 existing_timestamps.add(parsed['timestamp'])
                 valid_existing_cache.append(msg_str) # Keep only valid messages for this site
             elif parsed:
                  print(f"[Fetcher] Warning: Found message from wrong site ({parsed['site']}) in cache {cache_file}. Discarding.", file=sys.stderr)
             # else: Invalid message string, discard implicitly by not adding to valid_existing_cache

        # 2. Fetch new feed
        proxies = {"http": SOCKS_PROXY, "https": SOCKS_PROXY}
        fetched_content = None
        try:
             # Use stream=True and iter_content for potentially large feeds
             with requests.get(feed_url, proxies=proxies, timeout=FETCH_TIMEOUT, stream=True) as response:
                 response.raise_for_status() # Check for HTTP errors
                 # Read content line by line? Or read chunks? Assume newline delimited.
                 # Let's read the whole thing for simplicity unless proven problematic.
                 # Limit the total size read? requests doesn't make this easy directly.
                 # Check Content-Length header? Onion services might not provide it.
                 fetched_content = response.text # Reads entire response

        except requests.exceptions.Timeout:
             print(f"[Fetcher] Timeout fetching {feed_url}", file=sys.stderr)
             return 0 # Don't update cache on timeout
        except requests.exceptions.RequestException as e:
             print(f"[Fetcher] Error fetching {feed_url}: {e}", file=sys.stderr)
             return 0 # Don't update cache on connection error
        except Exception as e:
             print(f"[Fetcher] Unexpected error during fetch request for {feed_url}: {e}", file=sys.stderr)
             return 0

        if fetched_content is None:
             print(f"[Fetcher] Failed to retrieve content from {feed_url}")
             # Save potentially cleaned cache
             if len(valid_existing_cache) != len(existing_cache):
                  save_json(cache_file, valid_existing_cache)
             return 0

        if not fetched_content.strip():
            print(f"[Fetcher] Empty feed received from {site_onion}")
            # Keep existing cache as is, save if it was cleaned
            if len(valid_existing_cache) != len(existing_cache):
                save_json(cache_file, valid_existing_cache)
            return 0

        # 3. Process fetched feed and add new messages
        processed_new_messages = []
        malformed_lines = 0
        mismatched_site_lines = 0
        for line in fetched_content.strip().splitlines():
            msg_str = line.strip()
            if not msg_str: continue # Skip empty lines

            parsed_msg = parse_message_string(msg_str)
            if not parsed_msg:
                # Only log malformed lines once per fetch to avoid spam
                if malformed_lines == 0:
                     print(f"[Fetcher] Invalid message format received from {site_onion}: {msg_str[:100]}...", file=sys.stderr)
                malformed_lines += 1
                continue # Skip invalid messages

            # *** Crucial Check: Ensure the message actually originates from the site we fetched it from ***
            if parsed_msg['site'] != site_dir:
                 if mismatched_site_lines == 0:
                      print(f"[Fetcher] SECURITY WARNING: Message received from {site_onion} claims to be from {parsed_msg['site']}. DISCARDING.", file=sys.stderr)
                 mismatched_site_lines +=1
                 continue # Discard message with mismatched origin

            # Check if timestamp is new
            if parsed_msg['timestamp'] not in existing_timestamps:
                processed_new_messages.append(msg_str)
                existing_timestamps.add(parsed_msg['timestamp']) # Add to set immediately
                new_messages_added += 1

        if malformed_lines > 1:
             print(f"[Fetcher] ...skipped {malformed_lines - 1} more malformed lines from {site_onion}.", file=sys.stderr)
        if mismatched_site_lines > 1:
             print(f"[Fetcher] ...skipped {mismatched_site_lines - 1} more mismatched site lines from {site_onion}.", file=sys.stderr)


        # 4. Combine and save
        cache_updated = False
        if new_messages_added > 0:
            updated_cache = valid_existing_cache + processed_new_messages
            # Optional: Sort cache by timestamp? Might improve locality for future reads.
            # updated_cache.sort(key=lambda m: parse_message_string(m)['timestamp'] if parse_message_string(m) else '0')
            save_json(cache_file, updated_cache)
            print(f"[Fetcher] Added {new_messages_added} new messages for {site_onion}")
            cache_updated = True
        else:
            print(f"[Fetcher] No new messages found for {site_onion}")
            # Save potentially cleaned cache even if no new messages were added
            if len(valid_existing_cache) != len(existing_cache):
                 save_json(cache_file, valid_existing_cache)
                 cache_updated = True

        if not cache_updated:
            print(f"[Fetcher] Cache file {cache_file} remains unchanged.")


    except Exception as e:
        print(f"[Fetcher] Unexpected error processing feed for {site_onion}: {e}", file=sys.stderr)
        # Decide whether to wipe cache or leave it? Leave it for now.
        return 0 # Return 0 on error

    return new_messages_added


# --- NEW: Function to run the fetch cycle for all subs ---
def run_fetch_cycle():
    """Gets all subscriptions, fetches them using the executor, controlled by a lock."""
    global fetch_lock, fetch_executor, fetch_timer, FETCH_CYCLE

    print(f"[{datetime.datetime.now().isoformat()}] Attempting scheduled fetch cycle...")

    # Try to acquire the lock without blocking
    if fetch_lock.acquire(blocking=False):
        print("[Fetcher] Acquired lock for scheduled run.")
        total_new_messages = 0
        sites_fetched = 0
        try:
            start_time = time.time()
            subscription_dirs = []
            if os.path.isdir(SUBSCRIPTIONS_DIR):
                subscription_dirs = [d for d in os.listdir(SUBSCRIPTIONS_DIR)
                                     if os.path.isdir(os.path.join(SUBSCRIPTIONS_DIR, d))
                                     and len(d) == 56 # Basic validation
                                     and all(c in string.ascii_lowercase + string.digits + '234567' for c in d)]

            if not subscription_dirs:
                print("[Fetcher] No valid subscription directories found.")
            else:
                print(f"[Fetcher] Submitting {len(subscription_dirs)} sites for background fetching...")
                futures = {fetch_executor.submit(fetch_and_process_feed, site_dir): site_dir for site_dir in subscription_dirs}

                # Wait for all futures to complete
                results = concurrent.futures.wait(futures)

                sites_fetched = len(futures)
                for future in results.done:
                     try:
                         new_count = future.result() # Get the return value from fetch_and_process_feed
                         total_new_messages += new_count
                     except Exception as exc:
                          site = futures[future]
                          print(f'[Fetcher] Site {site} generated an exception during fetch: {exc}', file=sys.stderr)

                # Handle futures that didn't complete (cancelled, etc.) - results.not_done
                if results.not_done:
                     print(f"[Fetcher] Warning: {len(results.not_done)} fetch tasks did not complete.", file=sys.stderr)


            end_time = time.time()
            duration = end_time - start_time
            print(f"[Fetcher] Scheduled fetch cycle completed in {duration:.2f} seconds.")
            print(f"[Fetcher] Fetched {sites_fetched} sites, added {total_new_messages} total new messages.")

        except Exception as e:
            print(f"[Fetcher] Error during scheduled fetch cycle: {e}", file=sys.stderr)
        finally:
            # ALWAYS release the lock
            fetch_lock.release()
            print("[Fetcher] Released lock for scheduled run.")
    else:
        # If lock is held, it means another fetch (manual or previous auto) is running. Skip this cycle.
        print("[Fetcher] Skipping scheduled run: Fetch lock already held.")

    # --- Reschedule the next run ---
    # Check if the timer object still exists (i.e., cleanup hasn't run)
    # This check prevents rescheduling if the app is shutting down.
    if fetch_timer is not None or not hasattr(sys, 'is_exiting'): # Add a simple exit flag check
        print(f"[Fetcher] Scheduling next fetch cycle in {FETCH_CYCLE} seconds.")
        fetch_timer = threading.Timer(FETCH_CYCLE, run_fetch_cycle)
        fetch_timer.daemon = True # Allow program to exit even if timer is waiting
        fetch_timer.start()


@app.route('/fetch_subscriptions', methods=['POST'])
def fetch_subscriptions():
    """API endpoint to trigger background fetching of all subscriptions."""
    if not is_logged_in():
        return jsonify({"error": "Authentication required"}), 403

    global fetch_lock, fetch_executor

    print("[Fetcher] Received request to MANUALLY fetch subscriptions.")

    # Try to acquire the lock *without* blocking
    if fetch_lock.acquire(blocking=False):
        print("[Fetcher] Acquired lock for manual run.")
        try:
            subscription_dirs = []
            if os.path.isdir(SUBSCRIPTIONS_DIR):
                subscription_dirs = [d for d in os.listdir(SUBSCRIPTIONS_DIR)
                                     if os.path.isdir(os.path.join(SUBSCRIPTIONS_DIR, d))
                                     and len(d) == 56 # Basic validation
                                     and all(c in string.ascii_lowercase + string.digits + '234567' for c in d)]


            if not subscription_dirs:
                print("[Fetcher] No subscriptions found to fetch.")
                return jsonify({"message": "No subscriptions to fetch."})

            submitted_tasks = 0
            # Submit tasks to the executor
            print(f"[Fetcher] Submitting {len(subscription_dirs)} sites for background fetching (manual trigger)...")
            futures = {}
            for site_dir in subscription_dirs:
                # No need to track active_fetches specifically if we rely on the lock
                future = fetch_executor.submit(fetch_and_process_feed, site_dir)
                futures[future] = site_dir # Keep track for potential error logging if needed
                submitted_tasks += 1

            # --- IMPORTANT ---
            # We *don't* wait for completion here in the manual trigger.
            # We release the lock immediately after submitting.
            # The background tasks will run, but the UI gets an immediate response.
            # The lock prevents the *next* cycle (manual or auto) from starting
            # until this batch is somewhat processed (or errors out).
            # A more robust solution might involve a callback to release the lock
            # *after* all futures complete, but this is simpler.

            print(f"[Fetcher] Submitted {submitted_tasks} site(s) for background fetching.")
            return jsonify({"message": f"Started background fetch for {submitted_tasks} subscription(s). Refresh later."})

        except Exception as e:
            print(f"[Fetcher] Error submitting manual fetch tasks: {e}", file=sys.stderr)
            # Release lock in case of error during submission
            fetch_lock.release()
            print("[Fetcher] Released lock after error during manual submission.")
            return jsonify({"error": "Failed to start fetch process."}), 500
        finally:
             # Ensure lock is released if no exception occurred during submission
             # Check if lock is still held by this thread before releasing
             if fetch_lock.locked() and threading.get_ident() == fetch_lock._owner: # Check ownership (might be fragile)
                  fetch_lock.release()
                  print("[Fetcher] Released lock for manual run after submission.")

    else:
        # Lock was already held
        print("[Fetcher] Manual fetch request denied: Fetch lock already held.")
        # Return a specific status code (e.g., 429 Too Many Requests) to indicate busy
        return jsonify({"message": "Fetch operation already in progress. Please wait."}), 429


# --- Route for Removing a Subscription ---

@app.route('/remove_subscription/<string:site_dir>', methods=['POST'])
def remove_subscription(site_dir):
    """Removes a subscription directory."""
    if not is_logged_in():
        print(f"Unauthorized attempt to remove subscription: {site_dir}", file=sys.stderr)
        return jsonify({"error": "Authentication required"}), 403

    # --- Security Validation ---
    # Ensure site_dir is just the directory name (alphanumeric v3 onion)
    if not (len(site_dir) == 56 and all(c in string.ascii_lowercase + string.digits + '234567' for c in site_dir)):
        print(f"Invalid site directory format in removal request: {site_dir}", file=sys.stderr)
        return jsonify({"error": "Invalid subscription identifier format."}), 400

    # Construct path carefully
    # Use os.path.abspath and check it starts with the intended parent directory
    base_dir = os.path.abspath(SUBSCRIPTIONS_DIR)
    target_path = os.path.abspath(os.path.join(base_dir, site_dir))

    # Prevent path traversal rigorously
    if not target_path.startswith(base_dir + os.sep): # Ensure it's strictly within SUBSCRIPTIONS_DIR
        print(f"SECURITY ALERT: Path traversal attempt detected in remove_subscription for: {site_dir} (Resolved: {target_path})", file=sys.stderr)
        return jsonify({"error": "Invalid subscription identifier."}), 400


    if os.path.isdir(target_path):
        try:
            shutil.rmtree(target_path)
            print(f"Removed subscription directory: {target_path}")
            return jsonify({"success": True, "message": f"Subscription {site_dir}.onion removed."})
        except FileNotFoundError: # Should not happen if isdir() passed, but handle anyway
            print(f"Subscription directory not found during removal attempt: {target_path}", file=sys.stderr)
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


# --- Initialization and Tor Setup ---
def initialize_app():
    """Create necessary directories, load config, and start Tor service."""
    global SITE_NAME, onion_address # Ensure globals are modified

    print("Initializing Blitter Node...")
    # Ensure directories exist
    os.makedirs(SUBSCRIPTIONS_DIR, exist_ok=True)
    os.makedirs(KEYS_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    # Ensure static dir exists relative to script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    static_dir = os.path.join(script_dir, 'static')
    os.makedirs(static_dir, exist_ok=True)

    # Check for logo, provide basic one if missing?
    logo_path = os.path.join(static_dir, 'logo_128.png')
    if not os.path.exists(logo_path):
         print(f"Warning: Logo file not found at {logo_path}. Consider adding one.", file=sys.stderr)
         # Create a placeholder? Maybe not.

    print(f"Directories checked/created: {SUBSCRIPTIONS_DIR}, {KEYS_DIR}, {LOG_DIR}, static")

    # Create/check secret word file
    secret_file_path = os.path.join(KEYS_DIR, SECRET_WORD_FILE)
    if not os.path.exists(secret_file_path):
        try:
            save_json(secret_file_path, {"secret_word": "changeme"})
            print(f'Default secret word file created at {secret_file_path}.')
            print("***************************************************************************", file=sys.stderr)
            print("IMPORTANT: Default secret word 'changeme' set.", file=sys.stderr)
            # print(f"Please edit the file '{secret_file_path}'", file=sys.stderr)
            # print("and change the secret word BEFORE your first login attempt.", file=sys.stderr)
            print("***************************************************************************", file=sys.stderr)
        except Exception as e:
            print(f"FATAL ERROR: Could not create secret word file at {secret_file_path}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Check if secret word is still default 'changeme'
        try:
            secret_data = load_json(secret_file_path)
            # if secret_data and secret_data.get("secret_word") == "changeme":
            #     print("***************************************************************************", file=sys.stderr)
            #     print("WARNING: Secret word is still set to the default 'changeme'.", file=sys.stderr)
            #     print(f"Please edit '{secret_file_path}' and change it for security.", file=sys.stderr)
            #     print("Login will be blocked until the secret word is changed.", file=sys.stderr)
            #     print("***************************************************************************", file=sys.stderr)
        except Exception as e:
             print(f"Warning: Could not read or parse secret word file {secret_file_path}: {e}", file=sys.stderr)


    # Create/check profile file
    if not os.path.exists(PROFILE_FILE):
        print(f"Profile file '{PROFILE_FILE}' not found, creating default.")
        save_json(PROFILE_FILE, {
          "nickname": "User",
          "location": "", "description": "My Blitter profile.",
          "email": "", "website": "" # Use empty strings instead of None
        })
    else:
         print(f"Profile file found: {PROFILE_FILE}")
         profile_data = load_json(PROFILE_FILE)
         if not isinstance(profile_data, dict): # Handle case where file exists but is empty/invalid
              print(f"Warning: Profile file '{PROFILE_FILE}' is empty or invalid. Resetting to default.", file=sys.stderr)
              # Optionally back up the invalid file before overwriting
              save_json(PROFILE_FILE, {"nickname": "User", "location": "", "description": "My Blitter profile.", "email": "", "website": ""})

    # Create/check feed file
    if not os.path.exists(FEED_FILE):
        print(f"Feed file '{FEED_FILE}' not found, creating empty feed.")
        save_json(FEED_FILE, [])
    else:
        # Validate feed file is a list
        feed_data = load_json(FEED_FILE)
        if not isinstance(feed_data, list):
             print(f"Warning: Feed file '{FEED_FILE}' does not contain a valid JSON list. Resetting to empty.", file=sys.stderr)
             # Optionally backup invalid file
             save_json(FEED_FILE, [])
        else:
             print(f"Feed file found: {FEED_FILE}")

    # --- Tor Setup ---
    if not STEM_AVAILABLE:
        print("Skipping Tor setup because 'stem' library is not installed.")
        SITE_NAME = "tor_disabled"
        onion_address = None
        return # Skip Tor steps if library missing

    print("\n--- Starting Tor Onion Service Setup ---")
    onion_dir = find_first_onion_service_dir(KEYS_DIR)
    if onion_dir:
        key_blob = get_key_blob(onion_dir)
        if key_blob:
            print(f"Using key from: {onion_dir}")
            if start_tor_hidden_service(key_blob):
                print(f"--- Tor Onion Service setup successful. Site Name: {SITE_NAME} ---")
                # SITE_NAME and onion_address are set by start_tor_hidden_service
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
         print("and CookieAuthentication, and a valid key exists in the 'keys' directory.", file=sys.stderr)
         print("*****************************************************\n", file=sys.stderr)

    # Display passphrase for this site only if setup looks okay
    # Add checks for missing files/keys before trying to generate passphrase
    if onion_dir and not SITE_NAME.startswith("tor_"):
        try:
            secret_word = None
            secret_word_data = load_json(os.path.join(KEYS_DIR, SECRET_WORD_FILE))
            if secret_word_data and 'secret_word' in secret_word_data:
                secret_word = secret_word_data.get("secret_word")

            if secret_word: # and secret_word != "changeme":
                 print(f'Secret word is: {secret_word}' ) 
                 passphrase_words = get_passphrase(onion_dir, secret_word)
                 passphrase = " ".join(passphrase_words)
                 print(f'--- Passphrase for local user is: "{passphrase}" ---')
            # elif secret_word == "changeme":
            #      print("--- Cannot display passphrase: Secret word is still the default 'changeme'. ---", file=sys.stderr)
            else:
                print("--- Cannot display passphrase: Could not read secret word from file. ---", file=sys.stderr)
        except FileNotFoundError:
             print(f"--- Cannot display passphrase: Necessary file not found (key or secret word). ---", file=sys.stderr)
        except Exception as e:
            print(f"--- Warning: Error generating or displaying passphrase: {e} ---", file=sys.stderr)
    elif onion_dir: # Tor setup failed but dir exists
         print("--- Cannot display passphrase due to Tor setup issue. ---", file=sys.stderr)
    else: # No key dir found
        print("--- Cannot display passphrase as Tor key directory was not found. ---", file=sys.stderr)

# --- Main Execution ---
if __name__ == '__main__':
    initialize_app()

    # --- Start the background fetch timer AFTER initialization ---
    print("\n--- Starting initial background fetch cycle ---")
    # Run the first cycle immediately in the background, then schedule repeats
    # Use the executor to run the first cycle off the main thread
    # Initial run should also respect the lock
    initial_fetch_thread = threading.Thread(target=run_fetch_cycle, daemon=True)
    initial_fetch_thread.start()
    # The run_fetch_cycle function itself will schedule the *next* timer

    print(f"\n--- Starting Flask server ---\nSite: '{onion_address or SITE_NAME}'") # Show .onion if available
    print(f"Listening on http://{FLASK_HOST}:{FLASK_PORT}")
    if onion_address:
        print(f"Access via Tor at: http://{onion_address}")
    else:
         print("Access via Tor at: N/A (Setup incomplete/failed/disabled)")
    print("Press Ctrl+C to stop.")

    # Note: Flask's built-in server is not recommended for production.
    # Consider using a production-ready WSGI server like Gunicorn or uWSGI.
    try:
        # Disable debug mode for security and performance
        # Use threaded=True to handle multiple requests concurrently if needed,
        # but background tasks are handled by the executor/timer thread.
        app.run(debug=False, host=FLASK_HOST, port=FLASK_PORT, threaded=True, use_reloader=False) # Disable reloader explicitly
    except KeyboardInterrupt:
         print("\nCtrl+C received, shutting down...")
    except SystemExit as e: # Catch sys.exit() calls
         print(f"\nSystem exit called ({e}). Shutting down...")
    except Exception as e:
         print(f"\nFlask server encountered an error: {e}", file=sys.stderr)
         import traceback
         traceback.print_exc() # Print traceback for debugging
    finally:
         # Set a flag to signal cleanup that we are exiting
         sys.is_exiting = True
         # Cleanup is registered with atexit, will run automatically on normal exit/interrupt
         print("\nExiting Blitter Node.")

