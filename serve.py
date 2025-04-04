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
import threading # Added for background task feedback (optional)
import shutil # Added for directory removal
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session, abort
from markupsafe import escape
import re # Added for parsing markdown

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
APP_VERSION = '0.1.4'
PROFILE_FILE = 'profile.json'
FEED_FILE = 'feed.json'
SUBSCRIPTIONS_DIR = 'subscriptions'
KEYS_DIR = 'keys'
LOG_DIR = 'log'
ONION_PORT = 80  # Virtual port the onion service will listen on
FLASK_HOST = "127.0.0.1"  # Host Flask should listen on for Tor
FLASK_PORT = 5000  # Port Flask should listen on for Tor
MAX_MSG_LENGTH = 512
SOCKS_PROXY = "socks5h://127.0.0.1:9050" # SOCKS proxy for Tor requests
FETCH_TIMEOUT = 30 # Timeout in seconds for fetching subscription feeds

# --- Global Variables ---
SITE_NAME = "tor_setup_pending"  # Placeholder until Tor setup
PROTOCOL_VERSION = "0001"
# --- Tor Globals ---
tor_controller = None
tor_service_id = None
onion_address = None
# --- Fetching Globals ---
fetch_executor = concurrent.futures.ThreadPoolExecutor(max_workers=5) # Executor for background fetches
active_fetches = {} # Track active fetch tasks (optional for status)

# --- Helper Functions ---

def bmd2html(bmd_string):
    """Converts a Blitter Markdown string to valid html"""

    html_string = bmd_string

    # Convert [text](url) to <a href="url" target="_blank">text</a>
    html_string = re.sub(
        r'\[([^\]]+)\]\(([^)]+)\)',
        r'<a href="\2" target="_blank">\1</a>',
        html_string
    )

    # Convert ***text*** to <strong><em>text</em></strong>
    html_string = re.sub(
        r'\*\*\*([^\*]+)\*\*\*',
        r'<strong><em>\1</em></strong>',
        html_string
    )

    # Convert **text** to <strong>text</strong>
    html_string = re.sub(
        r'\*\*([^\*]+)\*\*',
        r'<strong>\1</strong>',
        html_string
    )

    # Convert *text* to <em>text</em>
    html_string = re.sub(
        r'\*([^\*]+)\*',
        r'<em>\1</em>',
        html_string
    )

    return html_string

def load_json(filename):
    """Loads JSON data from a file."""
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # Don't print warning for missing feedcache, it's expected
        if 'feedcache.json' not in filename:
             print(f"Warning: Could not load or decode JSON from {filename}", file=sys.stderr)
        return None # Return None to distinguish from empty file

def save_json(filename, data):
    """Saves JSON data to a file."""
    try:
        # Ensure directory exists before saving
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
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
        dt_object = datetime.datetime.fromtimestamp(ms_timestamp / 1000, tz=datetime.timezone.utc)
        day = dt_object.day
        if 11 <= day <= 13:
            suffix = 'th'
        else:
            suffixes = {1: 'st', 2: 'nd', 3: 'rd'}
            suffix = suffixes.get(day % 10, 'th')
        # Format to include milliseconds
        return dt_object.strftime(f'{day}{suffix} %b \'%y %H:%M:%S.%f')[:-3] + ' (UTC)'
    except (ValueError, TypeError, OverflowError):
        return "Invalid Timestamp"

def parse_message_string(msg_str):
    """Parses a message string into a dictionary, returns None if invalid."""
    if not msg_str or not msg_str.startswith('|') or not msg_str.endswith('|'):
        return None
    parts = msg_str.strip('|').split('|')
    if len(parts) != 8:
        return None
    # Basic validation of parts
    protocol, site, timestamp, reply_id, expiration, flag_int, length_field, content = parts
    if len(protocol) != 4 or not all(c in string.hexdigits for c in protocol): return None
    if len(site) != 56: return None # v3 onion address without .onion
    if len(timestamp) != 16 or not all(c in string.hexdigits for c in timestamp): return None
    if not (len(reply_id) == 74 and reply_id.count(':') == 1): return None # Basic format check
    if len(expiration) != 16 or not all(c in string.hexdigits for c in expiration): return None
    if len(flag_int) != 16 or not all(c in string.hexdigits for c in flag_int): return None
    if len(length_field) != 3 or not length_field.isdigit(): return None

    try:
        expected_len = int(length_field)
        actual_len = len(content.encode('ascii', errors='ignore')) # Use ignore for safety? Or check string.printable?
        # Tolerate slight variations? Maybe not strict ASCII length? Let's be strict for now.
        # Re-calculate length based on printable ASCII only for stricter validation if needed
        printable_content = ''.join(filter(lambda x: x in string.printable, content))
        if len(printable_content.encode('ascii')) != expected_len:
             # print(f"Warning: Message length mismatch. Expected {expected_len}, got {len(printable_content.encode('ascii'))} printable bytes. Raw content len {len(content)}.", file=sys.stderr)
             # Allow it for now, maybe log? Content might handle it.
             pass # Let it pass for now, display might handle it.

    except ValueError:
        return None # Should not happen if isdigit() passed

    return {
        'protocol': protocol,
        'site': site,
        'timestamp': timestamp,
        'display_timestamp': format_timestamp_for_display(timestamp),
        'reply_id': reply_id,
        'content': content, # Keep original content for cache
        'display_content': escape(''.join(filter(lambda x: x in string.printable, content))), # Pre-escape printable
        'expiration': expiration,
        'flags': flag_int,
        'len': length_field,
        'raw_message': msg_str # Keep the raw message string
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
    # Filter content to include only printable ASCII
    printable_content = ''.join(filter(lambda x: x in string.printable, content))
    expiration = 'f'*16  # Placeholder for expiration (max value)
    flag_int = '0'*16    # Placeholder for flags

    # Validate reply_id format (basic check)
    if not (isinstance(reply_id, str) and len(reply_id) == 74 and reply_id.count(':') == 1):
         reply_id = '0'*57 + ':' + '0'*16  # Default if invalid

    # Calculate the length of the *printable* content in bytes (as ASCII)
    content_length = len(printable_content.encode('ascii'))
    if content_length > MAX_MSG_LENGTH:
         # If content is too long, truncate it to MAX_MSG_LENGTH bytes
         printable_content = printable_content.encode('ascii')[:MAX_MSG_LENGTH].decode('ascii', 'ignore')
         content_length = len(printable_content.encode('ascii')) # Recalculate length after truncation

    len_field = f"{content_length:03d}"
    message = f"|{PROTOCOL_VERSION}|{SITE_NAME}|{timestamp}|{reply_id}|{expiration}|{flag_int}|{len_field}|{printable_content}|"
    return message, timestamp

# --- Tor Integration Functions ---

def find_first_onion_service_dir(keys_dir):
    """Scans the keys directory for the first valid v3 onion service key directory."""
    if not os.path.isdir(keys_dir):
        print(f"Error: Keys directory '{keys_dir}' not found.", file=sys.stderr)
        return None

    for item in sorted(os.listdir(keys_dir)):  # Sort for predictable behaviour
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
                    # Basic validation for v3 onion address format (56 chars)
                    if len(parsed_service_id) == 56:
                         parsed_onion_address = f"{parsed_service_id}.onion"
                         break
                    else:
                         print(f"Warning: Received unexpected ServiceID format: {parsed_service_id}", file=sys.stderr)
            elif isinstance(line, str) and line.startswith("ServiceID="):
                 parsed_service_id = line.split("=", 1)[1]
                 if len(parsed_service_id) == 56:
                     parsed_onion_address = f"{parsed_service_id}.onion"
                     break
                 else:
                      print(f"Warning: Received unexpected ServiceID format: {parsed_service_id}", file=sys.stderr)


        if not parsed_service_id or not parsed_onion_address:
            raw_response_content = response.content(decode=False)
            raise ValueError(f"ADD_ONION command seemed to succeed, but failed to parse ServiceID/OnionAddress from response. Raw content: {raw_response_content}")

        print(f"Successfully created service: {parsed_onion_address}")
        print(f"Service points to http://{FLASK_HOST}:{FLASK_PORT}")

        tor_controller = controller
        tor_service_id = parsed_service_id
        onion_address = parsed_onion_address
        SITE_NAME = parsed_service_id # SITE_NAME is the onion address *without* .onion
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

    # --- Also shutdown the thread pool executor ---
    print("Shutting down background fetch executor...")
    fetch_executor.shutdown(wait=True)
    print("Fetch executor shut down.")


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
        .header .site-name { text-align: center; font-size: 1.1em; margin: 0 150px; line-height: 1.5em; }
        .header .controls { float: right; }
        .content { display: flex; flex-wrap: wrap; padding: 10px; }
        .feed-panel { flex: 1; min-width: 200px; margin-right: 10px; margin-bottom: 10px; }
        .subscriptions-panel { flex: 2; min-width: 400px; background-color: #333; padding: 10px; border-radius: 5px; max-height: 80vh; overflow-y: auto;}
        .post-box { border: 1px solid #444; padding: 10px; margin-bottom: 15px; background-color: #2a2a2a; border-radius: 5px;}
        .post-meta { font-size: 0.8em; color: #888; margin-bottom: 5px;}
        .post-meta a { color: #aaa; }
        .post-content { margin-top: 5px; white-space: pre-wrap; word-wrap: break-word; font-size: 0.9em; } /* Smaller font for content */
         textarea { width: 95%; background-color: #444; color: #eee; border: 1px solid #555; padding: 5px; font-family: inherit;}
         input[type=submit], button { padding: 5px 10px; background-color: #555; border: none; color: #eee; cursor: pointer; border-radius: 3px; }
         button:disabled { background-color: #444; color: #888; cursor: not-allowed;}
         a { color: #7af; text-decoration: none; }
         a:hover { text-decoration: underline; }
         .error { color: red; font-weight: bold; }
         .site-info { margin-left: 10px; font-size: 0.9em; } /* Style for nickname/location */
         .nickname { font-family: 'Courier New', Courier, monospace; color: #ff9900; }
         .location { color: #ccc; }
         .subscription-site-name { font-weight: bold; color: #aaa; }
         .remove-link { margin-left: 5px; color: #f88; font-size: 0.9em; cursor: pointer; }
    </style>
</head>
<body>
    <div class="header">
        <span class="logo">
            <img src="{{ url_for('static', filename='logo_128.png') }}" height="32" width="32" style="margin-right:10px;"/>
            Blitter
            <span class="site-info">
                <span class="nickname">
                    {{ profile.nickname }}
                </span>
                {% if profile.location %}
                    <span class="location">({{ profile.location }})</span>
                {% endif %}
            </span>
        </span>
        <span class="controls">
            {% if logged_in %}
                <a href="{{ url_for('profile') }}">Profile</a> |
                <button id="fetch-subscriptions-btn" title="Fetch subscriptions">Fetch</button> |
                <button id="add-subscription-btn" title="Add subscription">Add</button> |
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
            <h2><span class="nickname">{{ profile.nickname }}</span> Feed</h2>
            {% if logged_in %}
            <form method="post" action="{{ url_for('post') }}">
                 <textarea name="content" rows="3" placeholder="What's happening? ({{ MAX_MSG_LENGTH }} chars max)" maxlength="{{ MAX_MSG_LENGTH }}" required></textarea><br>
                 <input type="submit" value="Post" style="margin: 5px;">
                 <span style="font-size: 0.8em; margin-left: 10px;"> Max 500 chars. Markdown: *italic*, **bold**, [link](url) </span>
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
                <div class="post-content">{{ bmd2html(post.display_content) | safe }}</div> {# Render markdown as HTML #}            </div>
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
                    <span class="subscription-site-name">{{ sub_post.site }}.onion</span> <br>
                    {{ sub_post.display_timestamp }}
                    {% if sub_post.reply_id and sub_post.reply_id != '0'*57 + ':' + '0'*16 %}
                    | Replying to: <a href="#" title="Link to replied message (Not Implemented)">{{ sub_post.reply_id }}</a>
                    {% endif %}
                    | <a href="http://{{ sub_post.site }}.onion/{{ sub_post.timestamp }}" target="_blank" title="View raw message on originating site">Raw</a>
                </div>
                <div class="post-content">{{ bmd2html(sub_post.display_content) | safe }}</div> {# Render markdown as HTML #}             </div>
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
                        <a href="http://{{ sub }}.onion" target="_blank">{{ sub }}.onion</a>
                        {% if logged_in %}
                            <a href="#" class="remove-link" data-site-dir="{{ sub }}" title="Remove subscription for {{ sub }}.onion">[Remove]</a>
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
          fetch("{{ url_for('fetch_subscriptions') }}", { method: 'POST' })
            .then(response => response.json())
            .then(data => {
              alert(data.message || "Fetch process started in background. Refresh page later to see updates.");
            })
            .catch(error => {
              console.error('Error starting subscription fetch:', error);
              alert("Error starting fetch. Check console.");
            })
            .finally(() => {
               // Re-enable button after a short delay, or rely on page refresh
               setTimeout(() => {
                   btn.disabled = false;
                   btn.textContent = "Fetch";
               }, 2000); // Give some visual feedback
            });
        });

        // Remove Subscription Links
        document.getElementById("subscription-list").addEventListener("click", function(event) {
            if (event.target.classList.contains("remove-link")) {
                event.preventDefault(); // Prevent default link behavior
                const siteDir = event.target.dataset.siteDir;
                const siteOnion = siteDir + ".onion";
                if (confirm(`Are you sure you want to remove the subscription for ${siteOnion}? This will delete the cached messages.`)) {
                    // Send request to backend to remove the subscription
                    fetch(`/remove_subscription/${siteDir}`, {
                        method: 'POST',
                        headers: {
                             // Add CSRF token header if needed in a production app
                             'Content-Type': 'application/json'
                        }
                        // No body needed, siteDir is in URL
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            // alert(`Subscription for ${siteOnion} removed.`);
                            // Refresh page to reflect removal
                            window.location.reload();
                        } else {
                            alert(`Error removing subscription: ${data.error || 'Unknown error'}`);
                        }
                    })
                    .catch(error => {
                        console.error('Error removing subscription:', error);
                        alert('Failed to remove subscription. Check console.');
                    });
                }
            }
        });

      {% endif %} // --- END LOGGED IN SCRIPT LOGIC ---
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
         for msg_str in reversed(feed_data):  # Newest first
            parsed_msg = parse_message_string(msg_str)
            if parsed_msg and parsed_msg['site'] == SITE_NAME:
                 processed_feed.append(parsed_msg)
            elif parsed_msg:
                 print(f"Notice: Skipping message with mismatched site name '{parsed_msg['site']}' (expected '{SITE_NAME}') in main feed.", file=sys.stderr)
            # else: message parsing failed (already handled in parse_message_string)

    utc_now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    subscription_dirs = []
    subscription_feed = []
    try:
        if os.path.isdir(SUBSCRIPTIONS_DIR):
             # Sort directory names for consistent display order
             subscription_dirs = sorted([d for d in os.listdir(SUBSCRIPTIONS_DIR) if os.path.isdir(os.path.join(SUBSCRIPTIONS_DIR, d))])
             for site_dir in subscription_dirs:
                 cache_file = os.path.join(SUBSCRIPTIONS_DIR, site_dir, 'feedcache.json')
                 cached_data = load_json(cache_file) or []
                 if isinstance(cached_data, list):
                     for msg_str in cached_data:
                         parsed_msg = parse_message_string(msg_str)
                         # Important: Ensure message belongs to the site indicated by the directory
                         if parsed_msg and parsed_msg['site'] == site_dir:
                             subscription_feed.append(parsed_msg)
                         elif parsed_msg:
                              print(f"Warning: Message site '{parsed_msg['site']}' in cache file '{cache_file}' does not match directory '{site_dir}'. Skipping.", file=sys.stderr)

    except FileNotFoundError:
        print(f"Warning: Subscriptions directory '{SUBSCRIPTIONS_DIR}' not found during index load.", file=sys.stderr)
        subscription_dirs = []
        subscription_feed = []
    except Exception as e:
         print(f"Error loading subscription data: {e}", file=sys.stderr)
         subscription_dirs = []
         subscription_feed = []


    # Sort combined subscription feed by timestamp (newest first)
    subscription_feed.sort(key=lambda x: x['timestamp'], reverse=True)

    # Load profile data
    profile_data = load_json(PROFILE_FILE) or {} # Ensure profile_data is a dict

    return render_template_string(
        INDEX_TEMPLATE,
        feed=processed_feed,
        subscription_feed=subscription_feed, # Pass the sorted subscription feed
        logged_in=is_logged_in(),
        site_name=SITE_NAME,
        onion_address=onion_address,
        utc_time=utc_now,
        protocol_version=PROTOCOL_VERSION,
        app_version=APP_VERSION,
        subscriptions=subscription_dirs, # Pass directory names
        profile=profile_data,
        MAX_MSG_LENGTH=MAX_MSG_LENGTH, # Pass max length to template
        bmd2html=bmd2html
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login route - basic password stub."""
    if is_logged_in():
        return redirect(url_for('index'))

    error = None
    if request.method == 'POST':
        profile_data = load_json(PROFILE_FILE) or {}
        correct_password = profile_data.get('passphrase')
        if not correct_password:
             error = 'Login disabled: No passphrase set in profile.json.'
        elif request.form.get('password') == correct_password:
            session['logged_in'] = True
            session.permanent = True
            app.permanent_session_lifetime = datetime.timedelta(days=7) # Example: 1 week session
            print("User logged in.")
            return redirect(url_for('index'))
        else:
            print("Login failed: Invalid credentials.")
            error = 'Invalid Credentials. Please try again.'
            time.sleep(0.5) # Basic rate limiting

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
    about_profile.append(f'{display_site_name}')
    about_profile.append(f'nickname: {profile_data.get("nickname", "N/A")}')
    about_profile.append(f'Loc: {profile_data.get("location", "N/A")}')
    about_profile.append(f'Desc: {profile_data.get("description", "N/A")}')
    about_profile.append(f'Email: {profile_data.get("email", "N/A")}')
    about_profile.append(f'Website: {profile_data.get("website", "N/A")}')
    return "\n".join(about_profile), 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    """Profile viewing and editing route."""
    if not is_logged_in():
        return redirect(url_for('login'))

    profile_data = load_json(PROFILE_FILE) or {} # Ensure it's a dict

    if request.method == 'POST':
        # Update only fields present in the form
        profile_data['nickname'] = request.form.get('nickname', profile_data.get('nickname'))
        profile_data['location'] = request.form.get('location', profile_data.get('location'))
        profile_data['description'] = request.form.get('description', profile_data.get('description'))
        profile_data['email'] = request.form.get('email', profile_data.get('email'))
        profile_data['website'] = request.form.get('website', profile_data.get('website'))
        # Add other editable fields here

        save_json(PROFILE_FILE, profile_data)
        print(f"Profile updated for user.") # Avoid logging sensitive data
        return redirect(url_for('profile')) # Redirect to GET to show updated profile

    # Make sure all expected keys exist for the template, even if None
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
         return redirect(url_for('index')) # Redirect without posting

    # Use create_message_string which handles filtering and length limits
    new_message_str, timestamp = create_message_string(content)

    if not new_message_str:
        # Error occurred during message creation (e.g., Tor not ready)
        # Redirect with an error message? For now, just redirect to index.
        print("Error: Failed to create message string (check logs).", file=sys.stderr)
        return redirect(url_for('index'))


    feed_data = load_json(FEED_FILE) or [] # Ensure it's a list
    if not isinstance(feed_data, list):
        print(f"Warning: Feed file '{FEED_FILE}' contained invalid data. Resetting to empty list.", file=sys.stderr)
        feed_data = []

    feed_data.append(new_message_str)
    save_json(FEED_FILE, feed_data)
    print(f"New post added with timestamp: {timestamp}")

    return redirect(url_for('index'))

@app.route('/feed')
def feed():
    """Returns the newline-separated feed containing only messages matching the current SITE_NAME."""
    feed_data = load_json(FEED_FILE) or []
    if not isinstance(feed_data, list):
        return "", 200, {'Content-Type': 'text/plain; charset=utf-8'} # Return empty if invalid

    site_feed = []
    for msg_str in feed_data:
         # Quick check before full parsing for performance
         if f"|{SITE_NAME}|" in msg_str:
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
             sub_dirs = [d for d in os.listdir(SUBSCRIPTIONS_DIR) if os.path.isdir(os.path.join(SUBSCRIPTIONS_DIR, d))]
    except Exception as e:
        print(f"Error accessing subscriptions directory '{SUBSCRIPTIONS_DIR}': {e}", file=sys.stderr)
        # Optionally return an error status code, but spec asks for plain text list
    return "\n".join(sorted(sub_dirs)), 200, {'Content-Type': 'text/plain; charset=utf-8'} # Sort for consistency

@app.route('/<string:timestamp>')
def view_message(timestamp):
    """Returns a specific message by its timestamp ID if it matches the current site."""
    # Validate timestamp format (16 hex characters)
    if not (len(timestamp) == 16 and all(c in string.hexdigits for c in timestamp)):
        abort(404, description="Invalid timestamp format.")

    feed_data = load_json(FEED_FILE) or []
    if not isinstance(feed_data, list):
         print(f"Error: Feed file '{FEED_FILE}' is missing or invalid.", file=sys.stderr)
         abort(500, description="Feed data is missing or invalid.") # Internal Server Error

    # Check own feed first
    for msg_str in feed_data:
        # Optimisation: check timestamp before full parse
        if f"|{timestamp}|" in msg_str:
             parsed_msg = parse_message_string(msg_str)
             if parsed_msg and parsed_msg['site'] == SITE_NAME and parsed_msg['timestamp'] == timestamp:
                 # Return raw ASCII message string as per spec
                 return msg_str, 200, {'Content-Type': 'text/plain; charset=ascii'}

    # If not in own feed, check subscription caches (though spec didn't strictly require this route for sub messages)
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
                                  return msg_str, 200, {'Content-Type': 'text/plain; charset=ascii'}
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
    onion_input = onion_input.replace("/","")

    if not onion_input:
        return "Error: No .onion address provided.", 400
    # Basic format check (v3 onion is 56 chars + .onion)
    if onion_input.endswith('.onion'):
         dir_name = onion_input[:-6]
    else:
         dir_name = onion_input
         onion_input += '.onion'

    if len(dir_name) != 56 or not all(c in string.ascii_lowercase + string.digits + '234567' for c in dir_name):
         return f"Error: Invalid v3 onion address format: {escape(onion_input)}", 400

    # Prevent subscribing to self
    # if dir_name == SITE_NAME:
    #      return "Error: Cannot subscribe to your own site.", 400

    # Check if already subscribed
    subscription_dir = os.path.join(SUBSCRIPTIONS_DIR, dir_name)
    if os.path.isdir(subscription_dir):
        print(f"Subscription attempt for already subscribed site: {onion_input}")
        # Optionally redirect or show a message, redirecting is simpler
        return redirect(url_for('index'))


    # --- Attempt to fetch /about to get initial info ---
    about_info = {}
    try:
        print(f"Attempting to fetch /about for new subscription: {onion_input}")
        proxies = {"http": SOCKS_PROXY, "https": SOCKS_PROXY}
        about_url = f"http://{onion_input}/about"
        r = requests.get(about_url, proxies=proxies, timeout=FETCH_TIMEOUT)
        r.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        about_text = r.text.strip()
        if not about_text:
            print(f"Warning: /about for {onion_input} returned empty response.")
            # Proceed without notes, or return error? Let's proceed.
        else:
            # Parse key-value pairs (handle potential missing keys gracefully)
            lines = about_text.splitlines()
            temp_info = {}
            # First line should be the site name itself, verify?
            if lines and lines[0].strip() != onion_input:
                 print(f"Warning: /about first line '{lines[0]}' does not match expected onion address '{onion_input}'")

            for line in lines[1:]: # Skip first line (address)
                 if ":" in line:
                     key, value = line.split(":", 1)
                     key = key.strip().lower()
                     value = value.strip()
                     if key == 'nickname': temp_info['nickname'] = value
                     elif key == 'loc': temp_info['location'] = value
                     elif key == 'desc': temp_info['description'] = value
                     elif key == 'email': temp_info['email'] = value
                     elif key == 'website': temp_info['website'] = value
            about_info = temp_info # Assign parsed info

    except requests.exceptions.Timeout:
        print(f"Error fetching /about from {onion_input}: Timeout after {FETCH_TIMEOUT}s", file=sys.stderr)
        return f"Error: Timeout connecting to {escape(onion_input)}. Site may be offline or unreachable.", 400
    except requests.exceptions.RequestException as e:
        print(f"Error fetching /about from {onion_input}: {e}", file=sys.stderr)
        return f"Error: Could not connect to {escape(onion_input)}. Details: {escape(str(e))}", 400
    except Exception as e:
        print(f"Unexpected error fetching /about from {onion_input}: {e}", file=sys.stderr)
        return f"Error processing response from {escape(onion_input)}.", 500

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
        # Optionally trigger an initial fetch here? Or let user click Fetch.
    except Exception as e:
        print(f"Error creating subscription directory or notes file for {onion_input}: {e}", file=sys.stderr)
        # Cleanup potentially created directory?
        if os.path.exists(subscription_dir):
             try: os.rmdir(subscription_dir) # Only removes if empty
             except: pass
        return "Error: Could not save subscription data locally.", 500

    return redirect(url_for('index'))

# --- Subscription Fetching Logic ---

def fetch_and_process_feed(site_dir):
    """Fetches feed for a single site, processes, and saves to cache."""
    site_onion = f"{site_dir}.onion"
    feed_url = f"http://{site_onion}/feed"
    cache_file = os.path.join(SUBSCRIPTIONS_DIR, site_dir, 'feedcache.json')
    print(f"[Fetcher] Starting fetch for: {site_onion}")

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
                 valid_existing_cache.append(msg_str) # Keep only valid messages
             elif parsed:
                  print(f"[Fetcher] Warning: Found message from wrong site ({parsed['site']}) in cache {cache_file}. Discarding.", file=sys.stderr)

        # 2. Fetch new feed
        proxies = {"http": SOCKS_PROXY, "https": SOCKS_PROXY}
        try:
             response = requests.get(feed_url, proxies=proxies, timeout=FETCH_TIMEOUT)
             response.raise_for_status() # Check for HTTP errors
        except requests.exceptions.Timeout:
             print(f"[Fetcher] Timeout fetching {feed_url}", file=sys.stderr)
             return # Don't update cache on timeout
        except requests.exceptions.RequestException as e:
             print(f"[Fetcher] Error fetching {feed_url}: {e}", file=sys.stderr)
             return # Don't update cache on connection error

        fetched_content = response.text
        if not fetched_content:
            print(f"[Fetcher] Empty feed received from {site_onion}")
            # Keep existing cache as is
            save_json(cache_file, valid_existing_cache) # Save potentially cleaned cache
            return

        # 3. Process fetched feed and add new messages
        new_messages_added = 0
        processed_new_messages = []
        for line in fetched_content.strip().splitlines():
            msg_str = line.strip()
            if not msg_str: continue # Skip empty lines

            parsed_msg = parse_message_string(msg_str)
            if not parsed_msg:
                print(f"[Fetcher] Invalid message format received from {site_onion}: {msg_str[:100]}...", file=sys.stderr)
                continue # Skip invalid messages

            # *** Crucial Check: Ensure the message actually originates from the site we fetched it from ***
            if parsed_msg['site'] != site_dir:
                 print(f"[Fetcher] SECURITY WARNING: Message received from {site_onion} claims to be from {parsed_msg['site']}. DISCARDING.", file=sys.stderr)
                 continue # Discard message with mismatched origin

            # Check if timestamp is new
            if parsed_msg['timestamp'] not in existing_timestamps:
                processed_new_messages.append(msg_str)
                existing_timestamps.add(parsed_msg['timestamp']) # Add to set immediately
                new_messages_added += 1

        # 4. Combine and save
        if new_messages_added > 0:
            updated_cache = valid_existing_cache + processed_new_messages
            # Optional: Sort cache by timestamp? Maybe not necessary if we sort on display.
            # updated_cache.sort(key=lambda m: parse_message_string(m)['timestamp'] if parse_message_string(m) else '0')
            save_json(cache_file, updated_cache)
            print(f"[Fetcher] Added {new_messages_added} new messages for {site_onion}")
        else:
            print(f"[Fetcher] No new messages found for {site_onion}")
            # Save potentially cleaned cache even if no new messages
            if len(valid_existing_cache) != len(existing_cache):
                 save_json(cache_file, valid_existing_cache)


    except Exception as e:
        print(f"[Fetcher] Unexpected error processing feed for {site_onion}: {e}", file=sys.stderr)
        # Decide whether to wipe cache or leave it? Leave it for now.

@app.route('/fetch_subscriptions', methods=['POST'])
def fetch_subscriptions():
    """API endpoint to trigger background fetching of all subscriptions."""
    if not is_logged_in():
        return jsonify({"error": "Authentication required"}), 403

    global active_fetches # Use the global tracker

    print("[Fetcher] Received request to fetch subscriptions.")
    try:
        subscription_dirs = []
        if os.path.isdir(SUBSCRIPTIONS_DIR):
            subscription_dirs = [d for d in os.listdir(SUBSCRIPTIONS_DIR) if os.path.isdir(os.path.join(SUBSCRIPTIONS_DIR, d))]

        if not subscription_dirs:
            print("[Fetcher] No subscriptions found to fetch.")
            return jsonify({"message": "No subscriptions to fetch."})

        submitted_tasks = 0
        # Submit tasks to the executor
        for site_dir in subscription_dirs:
            # Optional: Check if a fetch for this site is already running
            if site_dir in active_fetches and not active_fetches[site_dir].done():
                 print(f"[Fetcher] Fetch already in progress for {site_dir}. Skipping.")
                 continue

            future = fetch_executor.submit(fetch_and_process_feed, site_dir)
            active_fetches[site_dir] = future # Store future to track status (optional)
            submitted_tasks += 1
            # Optional: Add callback to remove from active_fetches when done
            # future.add_done_callback(lambda f: active_fetches.pop(site_dir, None))


        print(f"[Fetcher] Submitted {submitted_tasks} site(s) for background fetching.")
        return jsonify({"message": f"Started background fetch for {submitted_tasks} subscription(s)."})

    except Exception as e:
        print(f"[Fetcher] Error submitting fetch tasks: {e}", file=sys.stderr)
        return jsonify({"error": "Failed to start fetch process."}), 500

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

    # Construct path and prevent path traversal
    subscription_path = os.path.join(SUBSCRIPTIONS_DIR, site_dir)
    # Double-check that the resolved path is still within SUBSCRIPTIONS_DIR
    if os.path.abspath(subscription_path).startswith(os.path.abspath(SUBSCRIPTIONS_DIR)):
        if os.path.isdir(subscription_path):
            try:
                shutil.rmtree(subscription_path)
                print(f"Removed subscription directory: {subscription_path}")
                return jsonify({"success": True, "message": f"Subscription {site_dir}.onion removed."})
            except FileNotFoundError: # Should not happen if isdir() passed, but handle anyway
                print(f"Subscription directory not found during removal attempt: {subscription_path}", file=sys.stderr)
                return jsonify({"error": "Subscription not found."}), 404
            except PermissionError:
                 print(f"Permission error removing subscription directory: {subscription_path}", file=sys.stderr)
                 return jsonify({"error": "Permission denied while removing subscription."}), 500
            except Exception as e:
                print(f"Error removing subscription directory {subscription_path}: {e}", file=sys.stderr)
                return jsonify({"error": "An error occurred while removing the subscription."}), 500
        else:
            print(f"Subscription directory not found: {subscription_path}", file=sys.stderr)
            return jsonify({"error": "Subscription not found."}), 404
    else:
        # This case should ideally never be reached with the format validation, but belt-and-suspenders
        print(f"SECURITY ALERT: Path traversal attempt detected in remove_subscription for: {site_dir}", file=sys.stderr)
        return jsonify({"error": "Invalid subscription identifier."}), 400


# --- Initialization and Tor Setup ---
def initialize_app():
    """Create necessary directories, load config, and start Tor service."""
    global SITE_NAME

    print("Initializing Blitter Node...")
    os.makedirs(SUBSCRIPTIONS_DIR, exist_ok=True)
    os.makedirs(KEYS_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    # Ensure static dir exists for logo
    static_dir = os.path.join(os.path.dirname(__file__), 'static')
    os.makedirs(static_dir, exist_ok=True)
    # TODO: Check if logo file exists, maybe provide a default?
    logo_path = os.path.join(static_dir, 'logo_128.png')
    if not os.path.exists(logo_path):
         print(f"Warning: Logo file not found at {logo_path}", file=sys.stderr)

    print(f"Directories checked/created: {SUBSCRIPTIONS_DIR}, {KEYS_DIR}, {LOG_DIR}, static")


    if not os.path.exists(PROFILE_FILE):
        print(f"Profile file '{PROFILE_FILE}' not found, creating default.")
        save_json(PROFILE_FILE, {
          "nickname": "User",
          "passphrase": "change_this_password", # Instruct user to change this!
          "location": "", "description": "My Blitter profile.",
          "email": None, "website": None
          # Removed picture/background fields for simplicity now
        })
        print("IMPORTANT: Default password 'change_this_password' set. Please login and change your profile passphrase.", file=sys.stderr)
    else:
         print(f"Profile file found: {PROFILE_FILE}")
         profile_data = load_json(PROFILE_FILE)
         if not profile_data: # Handle case where file exists but is empty/invalid
              print(f"Warning: Profile file '{PROFILE_FILE}' is empty or invalid. Resetting to default.", file=sys.stderr)
              # Optionally back up the invalid file before overwriting
              save_json(PROFILE_FILE, {"nickname": "User", "passphrase": "change_this_password", "location": "", "description": "My Blitter profile.", "email": None, "website": None})
              print("IMPORTANT: Default password 'change_this_password' set. Please login and change your profile passphrase.", file=sys.stderr)

         elif not profile_data.get('passphrase'):
              print(f"WARNING: 'passphrase' not set in {PROFILE_FILE}. Login will be disabled until set via manual edit.", file=sys.stderr)
         elif profile_data.get('passphrase') == 'change_this_password':
              print("WARNING: Default passphrase 'change_this_password' is still set. Please change it for security.", file=sys.stderr)


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
    if onion_address:
        print(f"Access via Tor at: http://{onion_address}")
    else:
         print("Access via Tor at: N/A")
    print("Press Ctrl+C to stop.")

    # Note: Flask's built-in server is not recommended for production.
    # Consider using a production-ready WSGI server like Gunicorn or uWSGI.
    try:
        # Disable debug mode for security and performance
        # Use threaded=True if needed for background tasks, but ThreadPoolExecutor handles fetches
        app.run(debug=False, host=FLASK_HOST, port=FLASK_PORT, threaded=True)
    except KeyboardInterrupt:
         print("\nCtrl+C received, shutting down...")
    except Exception as e:
         print(f"\nFlask server encountered an error: {e}", file=sys.stderr)
    finally:
         # Cleanup is registered with atexit, will run automatically on normal exit
         print("\nExiting Blitter Node.")

