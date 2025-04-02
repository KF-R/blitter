#!/usr/bin/env python3
import os
import json
import time
import datetime
import sys # Added for stderr
import base64 # Added for key encoding
import atexit # Added for cleanup
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session, abort
from markupsafe import escape
import string
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
ONION_PORT = 80  # Virtual port the onion service will listen on
FLASK_HOST = "127.0.0.1" # Host Flask should listen on for Tor
FLASK_PORT = 5000 # Port Flask should listen on for Tor
MAX_MSG_LENGTH = 512

# --- Global Variables ---
# SITE_NAME will be updated by Tor setup if successful
SITE_NAME = "tor_setup_pending" # Placeholder until Tor setup
PROTOCOL_VERSION = "0001"
# --- Tor Globals ---
tor_controller = None
tor_service_id = None
onion_address = None


# --- Helper Functions ---

def load_json(filename):
    """Loads JSON data from a file."""
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"Warning: Could not load or decode JSON from {filename}", file=sys.stderr)
        return {} # Return empty dict or appropriate default

def save_json(filename, data):
    """Saves JSON data to a file."""
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
    except IOError as e:
        print(f"Error: Could not write JSON to {filename}: {e}", file=sys.stderr)


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
        dt_object = datetime.datetime.fromtimestamp(ms_timestamp / 1000, tz=datetime.timezone.utc)
        day = dt_object.day
        if 11 <= day <= 13:
            suffix = 'th'
        else:
            suffixes = {1: 'st', 2: 'nd', 3: 'rd'}
            suffix = suffixes.get(day % 10, 'th')
        return dt_object.strftime(f'{day}{suffix} %b \'%y %H:%M:%S.%f')[:-3] + ' (UTC)'
    except (ValueError, TypeError):
        return "Invalid Timestamp"

def create_message_string(content, reply_id='0'*57 + ':' + '0'*16):
    """Creates a message string in the new variable-width ASCII format:
    |<protocol_version>|<sitename>|<timestamp>|<reply-id>|<expiration>|<flag_int>|<len>|<content>|
    """
    global SITE_NAME # Use the globally set SITE_NAME (hopefully from Tor)
    timestamp = get_current_timestamp_hex()
    # Filter content to include only printable ASCII (no padding needed)
    printable_content = ''.join(filter(lambda x: x in string.printable, content))
    expiration = 'f'*16 # Placeholder for expiration (max value)
    flag_int = '0'*16   # Placeholder for flags

    # Validate reply_id format (basic check)
    if not (isinstance(reply_id, str) and len(reply_id) == 74 and reply_id.count(':') == 1):
         reply_id = '0'*57 + ':' + '0'*16 # Default if invalid

    # Calculate the length of the content in bytes (as ASCII)
    content_length = len(printable_content.encode('ascii'))
    if content_length > MAX_MSG_LENGTH:
         # If content is too long, truncate it to MAX_MSG_LENGTH bytes
         printable_content = printable_content[:MAX_MSG_LENGTH]
         content_length = len(printable_content.encode('ascii'))
    len_field = f"{content_length:03d}"
    message = f"|{PROTOCOL_VERSION}|{SITE_NAME}|{timestamp}|{reply_id}|{expiration}|{flag_int}|{len_field}|{printable_content}|"
    return message, timestamp


# --- Tor Integration Functions ---

def find_first_onion_service_dir(keys_dir):
    """Scans the keys directory for the first valid v3 onion service key directory."""
    if not os.path.isdir(keys_dir):
        print(f"Error: Keys directory '{keys_dir}' not found.", file=sys.stderr)
        return None

    for item in sorted(os.listdir(keys_dir)): # Sort for predictable behaviour
        service_dir = os.path.join(keys_dir, item)
        key_file = os.path.join(service_dir, "hs_ed25519_secret_key")
        if os.path.isdir(service_dir) and os.path.isfile(key_file):
            print(f"Found potential key directory: {service_dir}")
            return service_dir
    print(f"Error: No suitable key directories found in '{keys_dir}'.", file=sys.stderr)
    return None

def get_key_blob(service_dir):
    """Reads the secret key file and returns the base64 encoded 64-byte key material."""
    key_file_path = os.path.join(service_dir, "hs_ed25519_secret_key")
    try:
        with open(key_file_path, 'rb') as f:
            key_data = f.read()

        if not key_data.startswith(b'== ed25519v1-secret: type0 ==') or len(key_data) != 96:
             raise ValueError(f"Key file format is incorrect or size is not 96 bytes! ({len(key_data)} bytes found)")

        key_material_64 = key_data[32:]
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
            if isinstance(line, (tuple, list)) and len(line) >= 3 and isinstance(line[2], str):
                line_text = line[2]
                if line_text.startswith("ServiceID="):
                    parsed_service_id = line_text.split("=", 1)[1]
                    parsed_onion_address = f"{parsed_service_id}.onion"
                    break
            elif isinstance(line, str) and line.startswith("ServiceID="):
                 parsed_service_id = line.split("=", 1)[1]
                 parsed_onion_address = f"{parsed_service_id}.onion"
                 break

        if not parsed_service_id or not parsed_onion_address:
            raw_response_content = response.content(decode=False)
            raise ValueError(f"ADD_ONION command seemed to succeed, but failed to parse ServiceID/OnionAddress from response. Raw content: {raw_response_content}")

        print(f"Successfully created service: {parsed_onion_address}")
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
    """Sends DEL_ONION command to Tor if a service was created."""
    global tor_controller, tor_service_id
    if tor_controller and tor_service_id:
        print(f"\nCleaning up Tor service: {tor_service_id}")
        try:
            if tor_controller.is_alive():
                 response = tor_controller.msg(f"DEL_ONION {tor_service_id}")
                 if response.is_ok():
                     print(f"Successfully removed service {tor_service_id}")
                 else:
                     print(f"Warning: Failed to remove service {tor_service_id}:\n{response}", file=sys.stderr)
            else:
                 print(f"Warning: Tor controller connection lost before cleanup of {tor_service_id}.", file=sys.stderr)

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
        print(f"\nWarning: Tor controller not available for cleanup of service {tor_service_id}. Service might persist.", file=sys.stderr)


# --- HTML Templates (simplified) ---

LOGIN_TEMPLATE = """
<!doctype html>
<html>
<head><title>Login</title></head>
<body>
  <h2>Login</h2>
  {% if error %}<p style="color:red;"><strong>Error:</strong> {{ error }}</p>{% endif %}
  <form method="post">
    Password: <input type="password" name="password"><br>
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
        .header .logo { float: left; font-weight: bold; }
        .header .site-name { text-align: center; font-size: 1.1em; margin: 0 150px; line-height: 1.5em; }
        .header .controls { float: right; }
        .content { display: flex; flex-wrap: wrap; padding: 10px; }
        .feed-panel { flex: 2; min-width: 300px; margin-right: 10px; margin-bottom: 10px; }
        .subscriptions-panel { flex: 1; min-width: 250px; background-color: #333; padding: 10px; border-radius: 5px;}
        .post-box { border: 1px solid #444; padding: 10px; margin-bottom: 15px; background-color: #2a2a2a; border-radius: 5px;}
        .post-meta { font-size: 0.8em; color: #888; margin-bottom: 5px;}
        .post-meta a { color: #aaa; }
        .post-content { margin-top: 5px; white-space: pre-wrap; word-wrap: break-word; }
         textarea { width: 95%; background-color: #444; color: #eee; border: 1px solid #555; padding: 5px; font-family: inherit;}
         input[type=submit], button { padding: 5px 10px; background-color: #555; border: none; color: #eee; cursor: pointer; border-radius: 3px; }
         button:disabled { background-color: #444; color: #888; cursor: not-allowed;}
         a { color: #7af; text-decoration: none; }
         a:hover { text-decoration: underline; }
         .error { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
         <span class="logo">Blitter</span>
        <span class="controls">
            {% if logged_in %}
                <a href="{{ url_for('profile') }}">Profile</a> |
                <button disabled title="Refresh subscriptions (Not Implemented)">Refresh</button> |
                <button disabled title="Add subscription (Not Implemented)">Add</button> |
                <a href="{{ url_for('logout') }}">Logout</a>
            {% else %}
                <a href="{{ url_for('login') }}">Login</a>
            {% endif %}
        </span>
        <div class="site-name">
             {{ onion_address or site_name }}<br>
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
            <h2>Your Feed</h2>
            {% if logged_in %}
            <form method="post" action="{{ url_for('post') }}">
                 <textarea name="content" rows="4" placeholder="What's happening? (Markdown supported)" required></textarea><br>
                 <input type="submit" value="Post">
                 <span style="font-size: 0.8em; margin-left: 10px;">Max 500 chars. Markdown: *italic*, **bold**, [link](url)</span>
            </form>
            {% else %}
            <p><i>You must <a href="{{ url_for('login')}}">login</a> to post.</i></p>
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
                <div class="post-content">{{ escape(post.content) }}</div>
            </div>
            {% else %}
            <p>No posts yet.</p>
            {% endfor %}
        </div>

        <div class="subscriptions-panel">
            <h2>Subscriptions</h2>
            <p><i>Subscription fetching not implemented yet.</i></p>
            <div class="post-box">
                 <div class="post-meta">testsztreh...y7qdefyd.onion <br> 31st Mar '25 16:04:33.160 (UTC)</div>
                 <div class="post-content">News is depressing. I like cats!</div>
             </div>
             <h4>Subscribed Sites:</h4>
             <ul>
                 {% for sub in subscriptions %}
                     <li>{{ sub }}</li>
                 {% else %}
                     <li>No subscriptions added yet.</li>
                 {% endfor %}
             </ul>
        </div>
    </div>

    <div class="footer">
        <p style="text-align: center; font-size: 0.8em;">Blitter Node | Protocol v{{ protocol_version }}</p>
    </div>

</body>
</html>
"""

# --- Flask Routes ---

@app.route('/')
def index():
    """Main page route."""
    feed_data = load_json(FEED_FILE)
    processed_feed = []
    if isinstance(feed_data, list):
         # Process feed data for display (parse messages, format timestamps)
         for msg_str in reversed(feed_data): # Newest first
            parts = msg_str.strip('|').split('|')
            if len(parts) == 8:
                 site = parts[1]
                 timestamp = parts[2]
                 reply_id = parts[3]
                 expiration = parts[4]
                 flag_int = parts[5]
                 length_field = parts[6]
                 content = parts[7]
                 if site == SITE_NAME:
                    processed_feed.append({
                         'protocol': parts[0],
                         'site': site,
                         'timestamp': timestamp,
                         'display_timestamp': format_timestamp_for_display(timestamp),
                         'reply_id': reply_id,
                         'content': content,
                         'expiration': expiration,
                         'flags': flag_int,
                         'len': length_field
                    })
                 else:
                      print(f"Notice: Skipping message with mismatched site name '{site}' (expected '{SITE_NAME}')", file=sys.stderr)

    utc_now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    try:
        sub_dirs = [d for d in os.listdir(SUBSCRIPTIONS_DIR) if os.path.isdir(os.path.join(SUBSCRIPTIONS_DIR, d))]
    except FileNotFoundError:
        sub_dirs = []

    return render_template_string(
        INDEX_TEMPLATE,
        feed=processed_feed,
        logged_in=is_logged_in(),
        site_name=SITE_NAME,
        onion_address=onion_address,
        utc_time=utc_now,
        protocol_version=PROTOCOL_VERSION,
        subscriptions=sub_dirs,
        escape=escape
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login route - basic password stub."""
    if is_logged_in():
        return redirect(url_for('index'))

    error = None
    if request.method == 'POST':
        profile_data = load_json(PROFILE_FILE)
        correct_password = profile_data.get('passphrase')
        if not correct_password:
             error = 'Login disabled: No passphrase set in profile.json.'
        elif request.form.get('password') == correct_password:
            session['logged_in'] = True
            session.permanent = True
            app.permanent_session_lifetime = datetime.timedelta(days=7)
            return redirect(url_for('index'))
        else:
            error = 'Invalid Credentials. Please try again.'
            time.sleep(0.5)

    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route('/logout')
def logout():
    """Logout route."""
    session.pop('logged_in', None)
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    """Profile viewing and editing route."""
    if not is_logged_in():
        return redirect(url_for('login'))

    profile_data = load_json(PROFILE_FILE)

    if request.method == 'POST':
        profile_data['nickname'] = request.form.get('nickname', profile_data.get('nickname'))
        profile_data['location'] = request.form.get('location', profile_data.get('location'))
        profile_data['description'] = request.form.get('description', profile_data.get('description'))
        save_json(PROFILE_FILE, profile_data)
        return redirect(url_for('profile'))

    return render_template_string(PROFILE_TEMPLATE, profile=profile_data)

@app.route('/post', methods=['POST'])
def post():
    """Handles new post submissions."""
    if not is_logged_in():
        abort(403)

    content = request.form.get('content')
    if not content or not content.strip():
         return redirect(url_for('index'))

    content = content.strip()[:500]

    feed_data = load_json(FEED_FILE)
    if not isinstance(feed_data, list):
        feed_data = []

    new_message_str, _ = create_message_string(content)
    feed_data.append(new_message_str)
    save_json(FEED_FILE, feed_data)

    return redirect(url_for('index'))

@app.route('/feed')
def feed():
    """Returns the newline-separated feed matching the current SITE_NAME."""
    feed_data = load_json(FEED_FILE)
    if not isinstance(feed_data, list):
        feed_data = []

    site_feed = []
    for msg_str in feed_data:
         parts = msg_str.strip('|').split('|')
         if len(parts) == 8 and parts[1] == SITE_NAME:
             site_feed.append(msg_str)

    return "\n".join(site_feed), 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/subs')
def subs():
    """Returns the list of subscribed sites (directory names)."""
    try:
        sub_dirs = [d for d in os.listdir(SUBSCRIPTIONS_DIR) if os.path.isdir(os.path.join(SUBSCRIPTIONS_DIR, d))]
    except FileNotFoundError:
        print(f"Warning: Subscriptions directory '{SUBSCRIPTIONS_DIR}' not found.", file=sys.stderr)
        sub_dirs = []
    return "\n".join(sub_dirs), 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/<string:timestamp>')
def view_message(timestamp):
    """Returns a specific message by its timestamp ID if it matches the current site."""
    if not all(c in string.hexdigits for c in timestamp) or len(timestamp) != 16:
        abort(404, description="Invalid timestamp format.")

    feed_data = load_json(FEED_FILE)
    if not isinstance(feed_data, list):
         abort(500, description="Feed data is missing or invalid.")

    for msg_str in feed_data:
        parts = msg_str.strip('|').split('|')
        if len(parts) == 8 and parts[1] == SITE_NAME and parts[2] == timestamp:
             return msg_str, 200, {'Content-Type': 'text/plain; charset=ascii'}

    abort(404, description="Message not found for this site.")

# --- Initialization and Tor Setup ---
def initialize_app():
    """Create necessary directories, load config, and start Tor service."""
    global SITE_NAME

    print("Initializing Blitter Node...")
    os.makedirs(SUBSCRIPTIONS_DIR, exist_ok=True)
    os.makedirs(KEYS_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    print(f"Directories checked/created: {SUBSCRIPTIONS_DIR}, {KEYS_DIR}, {LOG_DIR}")

    if not os.path.exists(PROFILE_FILE):
        print(f"Profile file '{PROFILE_FILE}' not found, creating default.")
        save_json(PROFILE_FILE, {
          "nickname": "User",
          "passphrase": "change_this_password",
          "location": "", "description": "My Blitter profile.",
          "profile_picture": None, "custom_background_image": None, "email": None
        })
    else:
         print(f"Profile file found: {PROFILE_FILE}")
         profile_data = load_json(PROFILE_FILE)
         if not profile_data.get('passphrase'):
              print(f"WARNING: 'passphrase' not set in {PROFILE_FILE}. Login will be disabled.", file=sys.stderr)

    if not os.path.exists(FEED_FILE):
        print(f"Feed file '{FEED_FILE}' not found, creating empty feed.")
        save_json(FEED_FILE, [])
    else:
        print(f"Feed file found: {FEED_FILE}")

    if not STEM_AVAILABLE:
        print("Skipping Tor setup because 'stem' library is not installed.")
        SITE_NAME = "tor_disabled"
        return

    print("--- Starting Tor Onion Service Setup ---")
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
        else:
            print(f"Failed to extract key blob from {onion_dir}.", file=sys.stderr)
            SITE_NAME = "tor_key_error"
    else:
        print("No suitable Tor key directory found. Onion service not started.", file=sys.stderr)
        SITE_NAME = "tor_no_key"

    if SITE_NAME.startswith("tor_"):
         print("\n*****************************************************", file=sys.stderr)
         print(f"WARNING: Tor setup did not complete successfully (Status: {SITE_NAME}).", file=sys.stderr)
         print("The application will run, but might not be accessible via Tor", file=sys.stderr)
         print("and the site name used for posts may be incorrect.", file=sys.stderr)
         print("Ensure Tor service is running, configured with ControlPort 9051", file=sys.stderr)
         print("and CookieAuthentication, and a valid key exists in the 'keys' directory.", file=sys.stderr)
         print("*****************************************************\n", file=sys.stderr)

# --- Main Execution ---
if __name__ == '__main__':
    initialize_app()
    print(f"\nStarting Flask server for site '{SITE_NAME}' ({onion_address or 'Tor Disabled/Failed'})")
    print(f"Listening on http://{FLASK_HOST}:{FLASK_PORT}")
    print("Access via Tor at:", onion_address if onion_address else "N/A")
    print("Press Ctrl+C to stop.")

    try:
        app.run(debug=False, host=FLASK_HOST, port=FLASK_PORT)
    except Exception as e:
         print(f"\nFlask server encountered an error: {e}", file=sys.stderr)
    finally:
         print("\nExiting Blitter Node.")
