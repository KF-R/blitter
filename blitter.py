#!/usr/bin/env python3
APP_VERSION = '0.3.5'
PROTOCOL_VERSION = "0002"  # Version constants defined before imports for visibility
REQUIREMENTS_INSTALL_STRING = "pip install stem Flask requests[socks]"
import os
import json
import time
import datetime
import sys
import base64
import atexit
import string
import requests
import concurrent.futures
import threading
import shutil
import sqlite3
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session, abort, send_from_directory
import html
import re
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes, serialization
import logging
import argparse


# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# Suppress non-error stem warnings
try:
    import stem.util.log
    stem.util.log.get_logger().setLevel(logging.ERROR)
except ImportError:
    pass

# --- Tor Integration Imports ---
try:
    from stem.control import Controller
    from stem import Signal, ProtocolError
except ImportError:
    logger.error("--- 'stem' library not found. ---")
    logger.error(f"Check tor is installed and then install Python requirements with:\n{REQUIREMENTS_INSTALL_STRING}\n")
    logger.error("Exiting...")
    exit()

app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- Constants and Configuration ---
DB_FILE = 'blitter.db'
KEYS_DIR = 'keys'
SECRET_WORD_FILE = 'secret_word'
ONION_PORT = 80
FLASK_HOST = "127.0.0.1"
FLASK_PORT = 5000
MAX_MSG_LENGTH = 512
SOCKS_PROXY = "socks5h://127.0.0.1:9050"
FETCH_TIMEOUT = 30
FETCH_CYCLE = 300
NULL_REPLY_ADDRESS = '0'*56 + ':' + '0'*16

# --- Global Variables ---
SITE_NAME = "tor_setup_pending"  # Placeholder until Tor setup
tor_controller = None
tor_service_id = None
onion_address = None
fetch_executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)
fetch_lock = threading.Lock()
fetch_timer = None

# --- Database Functions ---

def init_db():
    """Initializes (or upgrades) the SQLite database with two tables: profiles and posts."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            site TEXT PRIMARY KEY,
            nickname TEXT,
            location TEXT,
            description TEXT,
            email TEXT,
            website TEXT,
            pubkey TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            site TEXT,
            timestamp TEXT,
            protocol TEXT,
            reply_id TEXT,
            expiration TEXT,
            flags TEXT,
            length_field TEXT,
            content TEXT,
            PRIMARY KEY (site, timestamp)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS blats (
            recipient TEXT,
            sender TEXT,
            timestamp TEXT,
            subject TEXT,
            content TEXT,
            flags TEXT,
            PRIMARY KEY (sender, timestamp)
        )
    ''')
    conn.commit()
    conn.close()

def get_db_connection():
    return sqlite3.connect(DB_FILE)

def get_local_profile():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM profiles WHERE site = ?", (SITE_NAME,))
    row = c.fetchone()
    conn.close()
    if row:
        return dict(zip(["site", "nickname", "location", "description", "email", "website"], row))
    return {}

def update_local_profile(profile_data):
    conn = get_db_connection()
    c = conn.cursor()
    local_pubkey = get_public_key_x25519()
    c.execute("""
         INSERT INTO profiles (site, nickname, location, description, email, website, pubkey)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(site) DO UPDATE SET 
            nickname=excluded.nickname,
            location=excluded.location,
            description=excluded.description,
            email=excluded.email,
            website=excluded.website,
            pubkey=excluded.pubkey
    """, (SITE_NAME,
          profile_data.get("nickname", ""),
          profile_data.get("location", ""),
          profile_data.get("description", ""),
          profile_data.get("email", ""),
          profile_data.get("website", ""),
          local_pubkey))
    conn.commit()
    conn.close()

def get_profile(site):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM profiles WHERE site = ?", (site,))
    row = c.fetchone()
    conn.close()
    if row:
        keys = ["site", "nickname", "location", "description", "email", "website", "pubkey"]
        return dict(zip(keys, row))
    return {}

def upsert_subscription_profile(site, info):
    """
    Store remote subscription profile including pubkey
    """
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
         INSERT INTO profiles (site, nickname, location, description, email, website, pubkey)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(site) DO UPDATE SET
            nickname=excluded.nickname,
            location=excluded.location,
            description=excluded.description,
            email=excluded.email,
            website=excluded.website,
            pubkey=excluded.pubkey
    """, (site,
          info.get('nickname', ''),
          info.get('location', ''),
          info.get('description', ''),
          info.get('email', ''),
          info.get('website', ''),
          info.get('pubkey', '')))
    conn.commit()
    conn.close()

def insert_blat(recipient, sender, timestamp, subject, content, flags):
    # TODO: Validate fields
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("""
            INSERT OR IGNORE INTO blats (recipient, sender, timestamp, subject, content, flags)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (recipient, sender, timestamp, subject, content, flags))
        conn.commit()
    except Exception as e:
        logger.error("DB insert error: %s", e)
        return False
    finally:
        conn.close()
    return True

def insert_bleet_from_string(msg_str):
    parts = parse_bleet_string(msg_str)
    if not parts:
        return False
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("""
            INSERT OR IGNORE INTO posts (site, timestamp, protocol, reply_id, expiration, flags, length_field, content)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (parts['site'], parts['timestamp'], parts['protocol'], parts['reply_id'],
              parts['expiration'], parts['flags'], parts['len'], parts['content']))
        conn.commit()
    except Exception as e:
        logger.error("DB insert error: %s", e)
        return False
    finally:
        conn.close()
    return True

def get_local_feed():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM posts WHERE site = ? ORDER BY timestamp DESC", (SITE_NAME,))
    rows = c.fetchall()
    conn.close()
    feed = []
    for row in rows:
        post = dict(zip(["site", "timestamp", "protocol", "reply_id", "expiration", "flags", "length_field", "content"], row))
        post['len'] = post.pop("length_field")
        post['display_timestamp'] = format_timestamp_for_display(post['timestamp'])
        post['display_content'] = post['content']
        feed.append(post)
    return feed

def get_all_posts():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM posts ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()
    all_posts = []
    for row in rows:
        post = dict(zip(["site", "timestamp", "protocol", "reply_id", "expiration", "flags", "length_field", "content"], row))
        post['len'] = post.pop("length_field")
        post['display_timestamp'] = format_timestamp_for_display(post['timestamp'])
        post['display_content'] = post['content']
        all_posts.append(post)
    return all_posts

def get_post(site, timestamp):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM posts WHERE site = ? AND timestamp = ?", (site, timestamp))
    row = c.fetchone()
    conn.close()
    if row:
        post = dict(zip(["site", "timestamp", "protocol", "reply_id", "expiration", "flags", "length_field", "content"], row))
        post['len'] = post.pop("length_field")
        post['display_timestamp'] = format_timestamp_for_display(post['timestamp'])
        post['display_content'] = post['content']
        return post
    return None

def get_all_subscriptions():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM profiles WHERE site <> ?", (SITE_NAME,))
    rows = c.fetchall()
    conn.close()
    subs = []
    for row in rows:
        sub = dict(zip(["site", "nickname", "location", "description", "email", "website"], row))
        subs.append(sub)
    return subs

def get_combined_feed():
    posts = get_all_posts()
    for post in posts:
        if post['site'] != SITE_NAME:
            prof = get_profile(post['site'])
            post['nickname'] = prof.get('nickname', '')
        else:
            local_profile = get_local_profile()
            post['nickname'] = local_profile.get('nickname', 'User')
    return posts

# --- Helper Functions ---

def escape(s):
    """ Replacement for the escape function in the MarkupSafe module. html is built-in """
    return html.escape(s, quote=True)

def is_valid_onion_address(addr):
    return bool(re.fullmatch(r'[a-z2-7]{56}(?:\.onion)?', addr))

def load_bip39_wordlist(filename='bip39_english.txt'):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    filepath = os.path.join(script_dir, filename)
    if not os.path.exists(filepath):
        filepath = filename
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            words = [line.strip() for line in f if line.strip()]
        if len(words) != 2048:
            raise ValueError(f"BIP-0039 word list must contain exactly 2048 words (found {len(words)} in {filepath})")
        return words
    except FileNotFoundError:
        logger.critical("FATAL ERROR: BIP-0039 wordlist '%s' not found in %s or current directory.", filename, script_dir)
        sys.exit(1)
    except Exception as e:
        logger.critical("FATAL ERROR: Failed to load BIP-0039 wordlist '%s': %s", filepath, e)
        sys.exit(1)

def get_passphrase(service_dir, secret_word) -> list:
    bip39 = load_bip39_wordlist()
    key_file_path = os.path.join(service_dir, "hs_ed25519_secret_key")
    try:
        with open(key_file_path, "rb") as f:
            f.seek(-64, os.SEEK_END)
            payload = f.read(64)
            if len(payload) != 64:
                raise IOError(f"Could not read the last 64 bytes from {key_file_path}")
    except FileNotFoundError:
        logger.error("Key file not found at %s", key_file_path)
        raise
    except IOError as e:
        logger.error("Error reading key file %s: %s", key_file_path, e)
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

def get_current_timestamp_hex():
    ns_timestamp = time.time_ns()
    return f'{ns_timestamp:016x}'

def format_timestamp_for_display(hex_timestamp):
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
    except Exception:
        return "Invalid Timestamp"

def parse_bleet_string(msg_str):
    if not isinstance(msg_str, str) or not msg_str.startswith('|') or not msg_str.endswith('|'):
        return None
    parts = msg_str.strip('|').split('|')
    if len(parts) != 8:
        return None
    protocol, site, timestamp, reply_id, expiration, flag_int, length_field, content = parts
    if len(protocol) != 4 or not all(c in string.hexdigits for c in protocol): return None
    if len(site) != 56 or not all(c in string.ascii_lowercase + string.digits + '234567' for c in site): return None
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
            logger.warning("Bleet length field %d does not match UTF-8 byte length %d. Content: '%s...'", expected_len, actual_len, content[:50])
    except ValueError:
        return None
    return {
        'protocol': protocol,
        'site': site,
        'timestamp': timestamp,
        'reply_id': reply_id,
        'expiration': expiration,
        'flags': flag_int,
        'len': length_field,
        'content': content,
        'raw_bleet': msg_str
    }

def create_bleet_string(content, reply_id=NULL_REPLY_ADDRESS):
    global SITE_NAME, PROTOCOL_VERSION

    timestamp = get_current_timestamp_hex()
    if not isinstance(content, str):
         logger.error("Bleet content must be a string.")
         return None, None

    content_bytes = content.encode('utf-8', errors='ignore')
    content_length = len(content_bytes)

    if content_length > MAX_MSG_LENGTH:
        truncated_bytes = content_bytes[:MAX_MSG_LENGTH]
        content = truncated_bytes.decode('utf-8', errors='ignore')
        content_length = len(content.encode('utf-8', errors='ignore'))
        logger.warning("Bleet content truncated to %d bytes (max %d).", content_length, MAX_MSG_LENGTH)

    expiration = 'f'*16
    flag_int = '0'*16
    len_field = f"{content_length:03d}"
    if not reply_id:
        reply_id = NULL_REPLY_ADDRESS

    bleet = f"|{PROTOCOL_VERSION}|{SITE_NAME}|{timestamp}|{reply_id}|{expiration}|{flag_int}|{len_field}|{content}|"
    return bleet, timestamp

def bmd2html(bmd_string):
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

def normalize_onion_address(onion_input):
    onion_input = onion_input.strip().lower().replace("http://", "").replace("https://", "")
    if onion_input.endswith('/'):
        onion_input = onion_input[:-1]
    if onion_input.endswith('.onion'):
        dir_name = onion_input[:-6]
    else:
        dir_name = onion_input
        onion_input += '.onion'
    return onion_input, dir_name

# --- Encryption utility functions ---

def encrypt(shared_secret, plaintext):
    aesgcm = AESGCM(shared_secret)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ciphertext).decode()

def decrypt(shared_secret, encrypted_message):
    data = base64.b64decode(encrypted_message)
    nonce, ciphertext = data[:12], data[12:]
    aesgcm = AESGCM(shared_secret)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

def get_blitsec(service_dir):
    key_file_path = os.path.join(service_dir, "hs_ed25519_secret_key")
    try:
        with open(key_file_path, 'rb') as f:
            key_data = f.read()
        if len(key_data) != 96:
             rifueError(f"Key file size is incorrect for old format ({len(key_data)} bytes found)")
        return key_data[32:64]
    except FileNotFoundError:
        logger.error("Secret key file not found: %s", key_file_path)
        return None
    except ValueError as ve:
        logger.error("Error reading key file %s: %s", key_file_path, ve)
        return None
    except Exception as e:
        logger.error("Error processing key file %s: %s", key_file_path, e)
        return None
  
def ed25519_seed_to_x25519(ed_seed: bytes) -> bytes:
    """
    Convert a 32-byte Ed25519 seed to an X25519 private key bytes.
    h = SHA512(ed_seed)
    a = h[:32] clamped with:
        a[0] &= 248; a[31] &= 127; a[31] |= 64
    """
    h = hashlib.sha512(ed_seed).digest()
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return bytes(a)

def get_x25519_private_key_from_seed() -> X25519PrivateKey:
    """Obtain the X25519 private key from our stored Ed25519 seed."""
    onion_dir = find_first_onion_service_dir(KEYS_DIR)
    ed_seed = get_blitsec(onion_dir)  # 32-byte Ed25519 seed
    xpriv_bytes = ed25519_seed_to_x25519(ed_seed)
    return X25519PrivateKey.from_private_bytes(xpriv_bytes)

def get_public_key_x25519() -> str:
    """
    Compute our X25519 public key (base64-encoded) so that remote sites
    can use it for the Diffie-Hellman exchange.
    """
    xpriv = get_x25519_private_key_from_seed()
    xpub = xpriv.public_key()
    pub_bytes = xpub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(pub_bytes).decode('ascii')

def compute_shared_secret_x25519(my_seed: bytes, peer_pubkey_b64: str) -> bytes:
    """
    Given our Ed25519 seed and the peer’s public key (base64 encoded),
    compute the shared secret using X25519.
    The derived secret is post-processed via SHA256.
    """
    my_private = get_x25519_private_key_from_seed()  # from our seed
    peer_pub_bytes = base64.b64decode(peer_pubkey_b64)
    peer_public = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared = my_private.exchange(peer_public)
    return hashlib.sha256(shared).digest()  # final 32-byte symmetric key

# --- Tor Integration Functions ---

def find_first_onion_service_dir(keys_dir):
    if not os.path.isdir(keys_dir):
        logger.error("Keys directory '%s' not found.", keys_dir)
        return None
    try:
        items = sorted(os.listdir(keys_dir))
    except OSError as e:
        logger.error("Error listing keys directory '%s': %s", keys_dir, e)
        return None
    for item in items:
        service_dir = os.path.join(keys_dir, item)
        key_file = os.path.join(service_dir, "hs_ed25519_secret_key")
        if os.path.isdir(service_dir) and os.path.isfile(key_file):
            logger.info("Found key directory: %s", service_dir)
            return service_dir
    logger.info("No suitable key directories found in '%s'.", keys_dir)
    return None

def get_key_blob(service_dir):
    key_file_path = os.path.join(service_dir, "hs_ed25519_secret_key")
    try:
        with open(key_file_path, 'rb') as f:
            key_data = f.read()
        is_new_format = key_data.startswith(b'== ed25519v1-secret: type0 ==\x00\x00\x00')
        is_old_format = key_data.startswith(b'== ed25519v1-secret: type0 ==') and len(key_data) == 96
        if not (is_new_format or is_old_format):
             raise ValueError("Key file format is incorrect. Header mismatch.")
        if is_new_format and len(key_data) < 64+32:
             raise ValueError(f"Key file size is incorrect for new format ({len(key_data)} bytes found)")
        elif is_old_format and len(key_data) != 96:
             raise ValueError(f"Key file size is incorrect for old format ({len(key_data)} bytes found)")
        key_material_64 = key_data[-64:]
        key_blob = base64.b64encode(key_material_64).decode('ascii')
        return f"ED25519-V3:{key_blob}"
    except FileNotFoundError:
        logger.error("Secret key file not found: %s", key_file_path)
        return None
    except ValueError as ve:
        logger.error("Error reading key file %s: %s", key_file_path, ve)
        return None
    except Exception as e:
        logger.error("Error processing key file %s: %s", key_file_path, e)
        return None

def start_tor_hidden_service(key_blob_with_type):
    global tor_controller, tor_service_id, onion_address, SITE_NAME
    try:
        logger.info("Connecting to Tor controller...")
        controller = Controller.from_port()
        controller.authenticate()
        logger.info("Authenticated with Tor controller.")
        command = (
            f"ADD_ONION {key_blob_with_type} "
            f"Flags=Detach "
            f"Port={ONION_PORT},{FLASK_HOST}:{FLASK_PORT}"
        )
        logger.info("Sending ADD_ONION command to Tor...")
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
                     logger.warning("Received unexpected ServiceID format: %s", parsed_service_id)
                     parsed_service_id = None
        if not parsed_service_id or not parsed_onion_address:
            raw_response_content = response.content(decode=False)
            raise ValueError(f"ADD_ONION command seemed to succeed, but failed to parse valid ServiceID/OnionAddress from response. Raw content: {raw_response_content}")
        logger.info("Onion service attached: %s", parsed_onion_address)
        logger.info("Service points to http://%s:%s", FLASK_HOST, FLASK_PORT)
        tor_controller = controller
        tor_service_id = parsed_service_id
        onion_address = parsed_onion_address
        SITE_NAME = parsed_service_id
        atexit.register(cleanup_tor_service)
        return True
    except ProtocolError as pe:
         logger.error("Tor Protocol Error: %s", pe)
         logger.error("Ensure Tor is running with ControlPort 9051 enabled and accessible.")
         logger.error("Check Tor logs for more details.")
         if tor_controller:
             try: 
                 tor_controller.close()
             except Exception:
                 pass
         tor_controller = None
         return False
    except Exception as e:
        logger.error("Error communicating with Tor controller: %s", e)
        logger.error("Ensure Tor is running with ControlPort enabled (e.g., ControlPort 9051) and")
        logger.error("CookieAuthentication is enabled (CookieAuthentication 1).")
        if tor_controller:
            try: 
                tor_controller.close()
            except Exception:
                pass
        tor_controller = None
        return False

def cleanup_tor_service():
    global tor_controller, tor_service_id, fetch_timer, fetch_executor
    if fetch_timer:
        logger.info("Cancelling background fetch timer...")
        fetch_timer.cancel()
        fetch_timer = None
    logger.info("Shutting down background fetch executor...")
    fetch_executor.shutdown(wait=True, cancel_futures=True)
    logger.info("Fetch executor shut down.")
    if tor_controller and tor_service_id:
        logger.info("Cleaning up Tor service: %s", tor_service_id)
        try:
            if tor_controller.is_authenticated() and tor_controller.is_alive():
                 logger.info("Attempting DEL_ONION for %s ...", tor_service_id) # Note: may fail if service is detached
                 response = tor_controller.msg(f"DEL_ONION {tor_service_id}")
                 if response.is_ok():
                     logger.info("Successfully removed service %s", tor_service_id)
                 else:
                     logger.info("DEL_ONION command response for %s: %s %s - %s", tor_service_id, response.status_type, response.status_severity, response.content(decode=False))
                     is_gone_error = any("HiddenServiceNonExistent" in str(line) for line in response.content())
                     if not is_gone_error:
                          logger.warning("Failed to explicitly remove service %s. It might persist if Tor continues running.", tor_service_id)
            else:
                 logger.warning("Tor controller connection lost or unauthenticated before cleanup of %s.", tor_service_id)
        except ProtocolError as pe:
             logger.warning("Tor Protocol Error during cleanup: %s", pe)
        except Exception as e:
            logger.warning("Error during Tor service cleanup: %s", e)
        finally:
            if tor_controller:
                try:
                    tor_controller.close()
                    logger.info("Tor controller connection closed.")
                except Exception as close_e:
                    logger.warning("Error closing Tor controller during cleanup: %s", close_e)
            tor_controller = None
            tor_service_id = None
    elif tor_service_id:
        logger.warning("Tor controller not available for cleanup of service %s. Service might persist if Tor continues running.", tor_service_id)

# --- Template Strings ---

CSS_BASE = """
    <link rel="icon" type="image/x-icon" href="/favicon.ico?v=blitter-01">
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
        textarea, input[type=text] {
            width: 100%; background-color: #444; color: #eee;
            border: 1px solid #555; padding: 6px; font-family: inherit;
            border-radius: 3px; box-sizing: border-box;
        }
        input[type=submit], button {
            padding: 6px 12px; background-color: #555;
            border: none; color: #eee; cursor: pointer;
            border-radius: 3px; margin-top: 10px;
        }
        input[type=text],
        input[type=password] {
            width: 100%; background-color: #444; color: #eee;
            border: 1px solid #555; padding: 6px; font-family: inherit;
            border-radius: 3px; box-sizing: border-box;
        }
        button:disabled { background-color: #444; color: #888; cursor: not-allowed;}
        a { color: #7af; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .form-container {
            max-width: 500px; margin: 20px auto;
            background-color: #2a2a2a; padding: 20px;
            border-radius: 5px; border: 1px solid #444;
        }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; color: #ccc; }
        .form-links { text-align: center; margin-top: 10px; font-size: 0.9em; }
        .remove-link { margin-left: 5px; color: #f88; font-size: 0.8em; cursor: pointer; }
        .blat-link { margin-left: 5px; color: #ffcc00; font-size: 0.8em; cursor: pointer; }
        .site-info { margin-left: 10px; font-size: 0.9em; }
        .nickname { font-family: 'Courier New', Courier, monospace; color: #ff9900; }
        .subscription-site-name { font-weight: bold; color: #aaa; }

    </style>

"""

JS_FORM = """
    <script>
    const textarea = document.getElementById('content');
    if (textarea) {
        textarea.addEventListener('keydown', e => {
            if (e.key === 'Enter' || e.key === '|') e.preventDefault();
        });

        textarea.addEventListener('input', () => {
            textarea.value = textarea.value.replace(/[\\r\\n|]+/g, ' ');
        });

        document.addEventListener("DOMContentLoaded", function () {
            const counter = document.getElementById("byte-count");
            const maxBytes = {{ MAX_MSG_LENGTH }};
            if (counter) {
                const updateCounter = () => {
                    const text = textarea.value;
                    const byteLength = new TextEncoder().encode(text).length;
                    counter.textContent = `${byteLength} / ${maxBytes} bytes`;
                    counter.style.color = (byteLength > maxBytes) ? "red" : "#aaa";
                };
                textarea.addEventListener("input", updateCounter);
                updateCounter();
            }
        });
    }
    </script>

"""

LOGIN_TEMPLATE = """
<!doctype html>
<html>
<head><title>Login</title>
{{ css_base|safe }}
</head>
<body>
    <div class="header">
        <span class="logo">
            <img src="{{ url_for('static', filename='logo_128.png') }}" height="32" width="32" style="margin-right:10px;"/>
            Blitter
        </span>
        <div class="site-name">
            <span id="site-name">{{ site_name }}</span>
        </div>
    </div>
    <div>
    <div class="form-container">
        <h2>Login</h2>
        {% if error %}<p style="color:red;"><strong>Error:</strong> {{ error }}</p>{% endif %}
        <form method="post">
        <div class="form-group">
            <label for="passphrase">Passphrase:</label>
            <input type="password" name="passphrase" value=""><br>
            <input type="submit" value="Login">
        </div>
        </form>
        <p><a href="{{ url_for('index') }}">Back to Feed</a></p>
    </div>
</body>
</html>
"""

PROFILE_TEMPLATE = """
<!doctype html>
<html>
<head><title>Profile</title>
{{ css_base|safe }}
</head>
<body>
    <div class="form-container">
        <h2>Profile</h2>
    <div class="form-links">
        <a href="/logout">Logout</a> | <a href="/">Home</a>
    </div>
    <form method="post">
        <div class="form-group">
        <label for="nickname">Nickname</label>
        <input type="text" name="nickname" id="nickname" value="{{ profile.nickname }}">
        </div>
        <div class="form-group">
        <label for="location">Location</label>
        <input type="text" name="location" id="location" value="{{ profile.location }}">
        </div>
        <div class="form-group">
        <label for="description">Description</label>
        <textarea name="description" id="description" rows="4">{{ profile.description }}</textarea>
        </div>
        <div class="form-group">
        <label for="email">Email</label>
        <input type="text" name="email" id="email" value="{{ profile.email }}">
        </div>
        <div class="form-group">
        <label for="website">Website</label>
        <input type="text" name="website" id="website" value="{{ profile.website }}">
        </div>
        <input type="submit" value="Update Profile">
    </form>
    </div>
</body>
</html>
"""

INDEX_TEMPLATE = """
<!doctype html>
<html>
<head>
    <title>Blitter Feed - {{ site_name }}</title>
{{ css_base|safe }}
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
                <input type="submit" value="Bleet" style="margin: 5px;">
                <span id="byte-count" style="font-size: 0.8em; margin-left: 10px;">0 / {{ MAX_MSG_LENGTH }} bytes</span>
                <span style="font-size: 0.8em; margin-left: 10px;"> Markdown: *italic*, **bold**, [link](url) </span>
            </form>
            <hr/>
            {% endif %}
            {% for post in user_feed %}
            <div class="post-box {% if post.site == site_name %}own-post-highlight{% endif %}">
                <div class="post-meta">
                    Posted: {{ post.display_timestamp }}
                     | <a href="{{ url_for('view_bleet', timestamp=post.timestamp) }}" title="View raw bleet format">Raw</a>
                     | <a href="{{ url_for('view_thread', bleet_id=post.site + ':' + post.timestamp) }}" title="View thread">Thread</a>
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
                      const siteDir = event.target.dataset.site;
                      const siteOnion = siteDir + ".onion";
                      if (confirm(`Are you sure you want to remove the subscription for ${siteOnion}? This will delete the cached bleets.`)) {
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

      setInterval(refreshSubscriptionsPanel, 60000);

      document.addEventListener("DOMContentLoaded", function () {
          bindRemoveLinks();
      });

    </script>

{% if logged_in %}
{{ js_form|safe }}
{% endif %}

</body>
</html>
"""

SUBSCRIPTIONS_TEMPLATE = """
<div class="subscriptions-header">
    Bleet Timeline 
    <span style="font-size: 0.6em; margin-left:20px;">{{ utc_time }}</span>
    {% if logged_in %}
    <span style="margin-left:40px;"><a href="/view_blats" title="View your Blat encrypted direct messages">View Blats</a></span>
    {% endif %}
</div>
{% for post in combined_feed %}
<div class="post-box {% if post.site == site_name %}own-post-highlight{% endif %}">
    <div class="post-meta">
        {% if post.site == site_name %}
            <span class="nickname">{{ profile.nickname if profile else 'Local user' }}: </span>
            <span class="subscription-site-name">{{ post.site }}.onion</span> <br>
            {{ post.display_timestamp }}
            | <a href="{{ url_for('view_bleet', timestamp=post.timestamp) }}" title="View raw bleet">Raw</a>
        {% else %}
            {% if post.nickname %}
                <span class="nickname">{{ post.nickname }}: </span>
            {% endif %}
            <span class="subscription-site-name">{{ post.site }}.onion</span> <br>
            {{ post.display_timestamp }}
            | <a href="http://{{ post.site }}.onion/{{ post.timestamp }}" target="_blank" title="View raw bleet on originating site">Raw</a>
        {% endif %}
        | <a href="{{ url_for('view_thread', bleet_id=post.site + ':' + post.timestamp) }}" title="View thread">Thread</a>
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
<p>No bleets found in timeline.</p>
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
               <a href="/blat/{{ sub.site }}" class="blat-link" title="Send an encrypted private direct message to {{ sub.nickname or sub.site }}">[ Blat ]</a>
               <a href="#" class="remove-link" data-site="{{ sub.site }}" title="Remove subscription for {{ sub.site }}.onion">[ Remove ]</a>
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

FOOTER_TEMPLATE = """
       <p style="text-align: center; font-size: 0.8em;">Blitter Node v{{ app_version }} | Protocol v{{ protocol_version }}</p>
"""

VIEW_BLATS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Blats View for {{ site_name }}</title>
    <style>
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
    </style>
{{ css_base|safe }}
</head>
<body>
    <div class="header">
        <span class="logo">
            <img src="{{ url_for('static', filename='logo_128.png') }}" height="32" width="32" style="margin-right:10px;"/>
            Blitter
        </span>
        <span class="controls">
            <a href="{{ url_for('profile') }}">Profile</a> |
            <a href="{{ url_for('logout') }}">Logout</a>
        </span>
        <div class="site-name">
            {{ ('<a href="http://' ~ site_name ~ '.onion">' ~ profile.nickname ~ '</a>') | safe }}:
            <span id="site-name">{{ site_name }}</span>
            <button title="Copy" onclick="navigator.clipboard.writeText(document.getElementById('site-name').innerText)" style="font-family: system-ui, sans-serif;">⧉</button>
        </div>
    </div>
    <hr/>
    <div class="content">
        <table>
            <thead>
                <tr>
                    {% if rows|length > 0 %}
                    <th>recipient</th>
                    <th>sender</th>
                    <th>timestamp</th>
                    <th>subject</th>
                    <th>content</th>
                    <th>Delivered/Read</th>
                    {% else %}
                    <th>No Data</th>
                    {% endif %}
                </tr>
            </thead>
            <tbody>
                {% for blat in rows %}
                <tr>
                    <td>{{ blat.recipient }}</td>
                    <td>{{ blat.sender }}</td>
                    <td>{{ blat.timestamp }}</td>
                    <td>{{ blat.subject }}</td>
                    <td>{{ blat.content }}</td>
                    <td>{{ blat.flags }}</td>
                </tr>
                {% else %}
                    <tr>
                        <td colspan="6">No records found.</td>
                    </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    <div class="footer">
{{ footer_section|safe }}
    </div>  
</body>
</html>
"""

VIEW_THREAD_TEMPLATE = """
<!doctype html>
<html>
<head>
    <title>Blitter Thread - {{ site_name }}</title>
{{ css_base|safe }}
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
    </div>
    <hr/>
    <div class="content">
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
                        | <a href="{{ url_for('view_bleet', timestamp=parent_post.timestamp) }}" title="View raw bleet">Raw</a>
                        | <a href="http://{{ parent_post.site }}.onion/thread/{{ parent_post.site }}:{{ parent_post.timestamp }}"{% if parent_post.site != site_name %} target="_blank"{% endif %} title="View">Thread</a>
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
                        | <a href="{{ url_for('view_bleet', timestamp=selected_post.timestamp) }}" title="View raw bleet">Raw</a>
                    {% else %}
                        {% if selected_post.nickname %}
                            <span class="nickname">{{ selected_post.nickname }}: </span>
                        {% endif %}
                        <span class="subscription-site-name">{{ selected_post.site }}.onion</span> <br>
                        {{ selected_post.display_timestamp }}
                        | <a href="http://{{ selected_post.site }}.onion/{{ selected_post.timestamp }}" target="_blank" title="View raw bleet on originating site">Raw</a>
                    {% endif %}
                    | <a href="{{ url_for('view_thread', bleet_id=selected_post.site + ':' + selected_post.timestamp) }}" title="View thread">Thread</a>
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
    </div>
    <div class="footer">
{{ footer_section|safe }}
    </div>
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
{% if logged_in %}
{{ js_form|safe }}
{% endif %}

</body>
</html>
"""

BLAT_TEMPLATE = """
<!doctype html>
<html>
<head>
    <title>Blitter Blat Out- {{ site_name }}</title>
{{ css_base|safe}}
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
        </div>
    </div>
    <hr/>
    <div class="content">
        <hr/>
        {% if logged_in %}
        <form method="post" action="{{ url_for('send_blat') }}">
            <label for="blat_recipient">Blat @:</label>
            <input type="text" name="blat_recipient" value="{{ blat_recipient }}" readonly title="You are sending an encrypted direct message to this blitter user." size="70">
            <label for="subject">Blat Subject:</label>
            <textarea id="subject" name="subject" rows="1" placeholder="Enter the subject of your private direct message here" maxlength="80" required></textarea><br>
            <label for="content">Blat content:</label>
            <textarea id="content" name="content" rows="3" placeholder="Enter your private direct message here" maxlength="{{ MAX_MSG_LENGTH }}" required></textarea><br>
            <input type="submit" value="Post" style="margin: 5px;">
            <span id="byte-count" style="font-size: 0.8em; margin-left: 10px;">0 / {{ MAX_MSG_LENGTH }} bytes</span>
        </form>
        <hr/>
        {% else %}
        <h2>Log in to blat people</h2>
        {% endif %}
    </div>
    <div class="footer">
        {{ footer_section|safe }}
    </div>
{% if logged_in %}
{{ js_form|safe }}
{% endif %}

</body>
</html>
"""

# --- Flask Routes ---

@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static', 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/')
def index():
    common = get_common_context()
    local_feed = get_local_feed()
    return render_template_string(
        INDEX_TEMPLATE,
        css_base=CSS_BASE,
        js_form=render_template_string(JS_FORM, MAX_MSG_LENGTH=MAX_MSG_LENGTH),
        header_section=common['header_section'],
        footer_section=common['footer_section'],
        user_feed=local_feed,
        subscriptions_panel=subscriptions_panel(),
        logged_in=common['logged_in'],
        site_name=SITE_NAME,
        onion_address=onion_address,
        profile=common['profile'],
        MAX_MSG_LENGTH=MAX_MSG_LENGTH,
        bmd2html=bmd2html
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('index'))
    error = None
    if request.method == 'POST':
        secret_word_data = None
        secret_word_file = os.path.join(KEYS_DIR, SECRET_WORD_FILE)
        try:
            with open(secret_word_file, 'r', encoding='utf-8') as f:
                secret_word_data = json.load(f)
        except Exception as e:
            logger.error("Login failed: Secret word file error (%s).", e)
        if not secret_word_data or 'secret_word' not in secret_word_data:
             error = 'Secret word configuration is missing or invalid.'
             logger.error("Login failed: Secret word file error.")
             return render_template_string(LOGIN_TEMPLATE, error=error)
        secret_word = secret_word_data.get("secret_word")
        onion_dir = find_first_onion_service_dir(KEYS_DIR)
        if not onion_dir:
            error = 'Cannot locate Tor key directory to verify passphrase.'
            logger.error("Login failed: Could not find Tor key directory.")
            return render_template_string(LOGIN_TEMPLATE, error=error)
        try:
            correct_passphrase = " ".join(get_passphrase(onion_dir, secret_word))
        except FileNotFoundError:
             error = 'Tor key file not found. Cannot verify passphrase.'
             logger.error("Login failed: Tor key file missing.")
             return render_template_string(LOGIN_TEMPLATE, error=error)
        except Exception as e:
            error = f'Error generating expected passphrase: {e}'
            logger.error("Login failed: Error during passphrase generation - %s", e)
            return render_template_string(LOGIN_TEMPLATE, error=error)
        if request.form.get('passphrase') == correct_passphrase:
            session['logged_in'] = True
            session.permanent = True
            app.permanent_session_lifetime = datetime.timedelta(days=7)
            logger.info("User logged in.")
            return redirect(url_for('index'))
        else:
            logger.error("Login failed: Invalid Credentials.")
            error = 'Invalid Credentials. Please try again.'
            time.sleep(1)
    return render_template_string(LOGIN_TEMPLATE, css_base=CSS_BASE, site_name=SITE_NAME, error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    logger.info("User logged out.")
    return redirect(url_for('index'))

@app.route('/about')
def about():
    local_profile = get_local_profile()
    display_site_name = onion_address or SITE_NAME
    if display_site_name.startswith("tor_"):
         display_site_name = "Unknown Site (Tor Setup Issue)"
    about_profile = []
    if not display_site_name.startswith("Unknown"):
        about_profile.append(f'{display_site_name}')
    if local_profile.get("nickname"): about_profile.append(f'nickname: {local_profile["nickname"]}')
    if local_profile.get("location"): about_profile.append(f'Loc: {local_profile["location"]}')
    if local_profile.get("description"): about_profile.append(f'Desc: {local_profile["description"]}')
    if local_profile.get("email"): about_profile.append(f'Email: {local_profile["email"]}')
    if local_profile.get("website"): about_profile.append(f'Website: {local_profile["website"]}')
    # Append our public key; if not already stored (should be set via update_local_profile)
    pubkey = local_profile.get("pubkey") or get_public_key_x25519()
    about_profile.append(f'pubkey: {pubkey}')
    if not about_profile:
         return "No profile information available.", 200, {'Content-Type': 'text/plain; charset=utf-8'}
    return "\n".join(about_profile), 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if not is_logged_in():
        return redirect(url_for('login'))
    local_profile = get_local_profile()
    if request.method == 'POST':
        new_profile = {
            'nickname': request.form.get('nickname', '').strip(),
            'location': request.form.get('location', '').strip(),
            'description': request.form.get('description', '').strip(),
            'email': request.form.get('email', '').strip(),
            'website': request.form.get('website', '').strip()
        }
        update_local_profile(new_profile)
        logger.info("Local profile updated.")
        return redirect(url_for('profile'))
    local_profile.setdefault('nickname', '')
    local_profile.setdefault('location', '')
    local_profile.setdefault('description', '')
    local_profile.setdefault('email', '')
    local_profile.setdefault('website', '')
    return render_template_string(PROFILE_TEMPLATE, profile=local_profile, css_base=CSS_BASE)

@app.route('/post', methods=['POST'])
def post():
    if not is_logged_in():
        logger.error("Unauthorized attempt to post.")
        abort(403)
    # Note: bars ("|") are reserved, hence stripped from all posts
    content = request.form.get('content').replace("|","")
    if not content or not content.strip():
         logger.info("Post rejected: Empty content.")
         return redirect(url_for('index'))
    new_bleet_str, timestamp = create_bleet_string(content, request.form.get('reply_id'))
    if not new_bleet_str:
        logger.error("Failed to create bleet string (check logs). Post rejected.")
        return redirect(url_for('index'))
    if insert_bleet_from_string(new_bleet_str):
        logger.info("New bleet added with timestamp: %s", timestamp)
    else:
        logger.error("Error inserting post into database.")
    return redirect(url_for('index'))

@app.route('/feed')
def feed():
    bleets = get_local_feed()
    feed_lines = []
    for bleet in bleets:
         bleet = f"|{bleet['protocol']}|{bleet['site']}|{bleet['timestamp']}|{bleet['reply_id']}|{bleet['expiration']}|{bleet['flags']}|{bleet['len']}|{bleet['content']}|"
         feed_lines.append(bleet)
    return "\n".join(feed_lines), 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/subs')
def subs():
    subs = get_all_subscriptions()
    sites = [sub['site'] for sub in subs]
    return "\n".join(sorted(sites)), 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/<string:timestamp>')
def view_bleet(timestamp):
    if not (len(timestamp) == 16 and all(c in string.hexdigits for c in timestamp)):
        abort(404, description="Invalid timestamp format.")
    post = get_post(SITE_NAME, timestamp)
    if post:
        bleet = f"|{post['protocol']}|{post['site']}|{post['timestamp']}|{post['reply_id']}|{post['expiration']}|{post['flags']}|{post['len']}|{post['content']}|"
        try:
            ascii_msg = bleet.encode('ascii').decode('ascii')
            return ascii_msg, 200, {'Content-Type': 'text/plain; charset=ascii'}
        except UnicodeEncodeError:
            return bleet, 200, {'Content-Type': 'text/plain; charset=utf-8'}
    abort(404, description="Bleet not found.")

@app.route('/thread/<string:bleet_id>')
def view_thread(bleet_id):
    local_profile = get_local_profile()
    if (':' not in bleet_id) or (len(bleet_id) != len(NULL_REPLY_ADDRESS)):
        abort(400, description="Invalid bleet id format.")
    bleet_site, bleet_timestamp = bleet_id.split(':')
    if not is_valid_onion_address(bleet_site):
        abort(400, description="Invalid blitter (onion) address.")
    if not (len(bleet_timestamp) == 16 and all(c in string.hexdigits for c in bleet_timestamp)):
        abort(400, description="Invalid timestamp format.")

    combined_feed = get_combined_feed()
    selected_post = None
    parent_post = None
    for post in combined_feed:
        if post['site'] == bleet_site and post['timestamp'] == bleet_timestamp:
            selected_post = post
            if post['reply_id'] != NULL_REPLY_ADDRESS:
                for parent in combined_feed:
                    if parent['site'] + ':' + parent['timestamp'] == post['reply_id']:
                        parent_post = parent
                        break
                if not parent_post:
                    parent_post = f"Parent post is not cached locally: http://{bleet_site}.onion/thread/{post['reply_id']}"
            else:
                parent_post = "This post is not a reply. It is an original bleet."
            break

    if not selected_post:
        abort(404, description="Bleet not stored or cached on this Blitter site.")

    def generate_children_html(parent, feed, level=1):
        parent_id = f"{parent['site']}_{parent['timestamp']}"
        children = [child for child in feed if child['reply_id'] == f"{parent['site']}:{parent['timestamp']}"]
        if not children:
            return ""
        html = f'<div class="children" style="margin-left:{level * 20}px; border-left:1px dashed #555; padding-left:10px;">'
        html += f'<a href="javascript:void(0);" onclick="toggleChildren(\'{parent_id}-children\');" id="{parent_id}-toggle">[-] Collapse replies</a>'
        html += f'<div id="{parent_id}-children">'
        for child in children:
            child_id = f"{child['site']}_{child['timestamp']}"
            if child['site'] == SITE_NAME:
                html += '<div class="post-box own-post-highlight" style="margin-top:10px;">'
            else:
                html += '<div class="post-box" style="margin-top:10px;">'
            html += '<div class="post-meta">'
            if child['site'] == SITE_NAME:
                html += f'<span class="nickname">{local_profile.get("nickname", "Local user")}: </span>'
            else:
                if child.get("nickname"):
                    html += f'<span class="nickname">{child["nickname"]}: </span>'
            html += f'<span class="subscription-site-name">{child["site"]}.onion</span> <br>'
            html += f'{child["display_timestamp"]} '
            html += f'| <a href="{url_for("view_bleet", timestamp=child["timestamp"])}" title="View raw bleet">Raw</a> '
            if child["site"] != SITE_NAME:
                html += f'| <a href="http://{child["site"]}.onion/thread/{child["site"]}:{child["timestamp"]}" target="_blank" title="View thread">Thread</a>'
            else:
                html += f'| <a href="{url_for("view_thread", bleet_id=child["site"] + ":" + child["timestamp"])}" title="View thread">Thread</a>'
            if child["reply_id"] != NULL_REPLY_ADDRESS:
                html += f'<br><em>In reply to:</em> <a href="http://{child["reply_id"].split(":")[0]}.onion/thread/{child["reply_id"]}">{child["reply_id"]}</a>'
            html += '</div>'
            html += f'<div class="post-content">{bmd2html(child["display_content"])}</div>'
            html += generate_children_html(child, feed, level+1)
            html += '</div>'
        html += '</div></div>'
        return html

    thread_section = generate_children_html(selected_post, combined_feed, 1)
    common = get_common_context()
    view_thread_html = render_template_string(
        VIEW_THREAD_TEMPLATE,
        css_base=CSS_BASE,
        js_form=render_template_string(JS_FORM, MAX_MSG_LENGTH=MAX_MSG_LENGTH),
        header_section=common['header_section'],
        utc_now=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        logged_in=common['logged_in'],
        parent_post=parent_post,
        selected_post=selected_post,
        thread_section=thread_section,
        footer_section=common['footer_section'],
        site_name=SITE_NAME,
        onion_address=onion_address,
        profile=common['profile'],
        MAX_MSG_LENGTH=MAX_MSG_LENGTH,
        bmd2html=bmd2html,
        null_reply_address=NULL_REPLY_ADDRESS
    )
    return view_thread_html

@app.route('/view_blats')
def view_blats():
    if not is_logged_in():
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    rows = conn.execute('SELECT * FROM blats').fetchall()
    conn.close()

    parsed_rows = []
    for row in rows:
        row_dict = dict(row)  # make a mutable copy

        if row_dict['recipient'] == SITE_NAME:
            row_dict['recipient'] = 'you'
            if row_dict['flags'] == '0' * 16:
                row_dict['flags'] = 'Unread'
            else:
                row_dict['flags'] = 'Read'

        if row_dict['sender'] == SITE_NAME:
            row_dict['sender'] = 'you'
            if row_dict['flags'] == '0' * 16:
                row_dict['flags'] = 'Undelivered'
            else:
                row_dict['flags'] = 'Delivered'

        row_dict['timestamp'] = format_timestamp_for_display(row_dict['timestamp'])
            
        parsed_rows.append(row_dict)

    common = get_common_context()
    return render_template_string(
        VIEW_BLATS_TEMPLATE,
        css_base=CSS_BASE,
        header_section=common['header_section'],
        footer_section=common['footer_section'],
        site_name=common['site_name'],
        profile=common['profile'],
        rows=parsed_rows)

@app.route('/blat/<string:blat_recipient>')
def blat(blat_recipient):
    common = get_common_context()
    return render_template_string(
        BLAT_TEMPLATE, 
        css_base=CSS_BASE, js_form=render_template_string(JS_FORM, MAX_MSG_LENGTH=MAX_MSG_LENGTH * 32),
        logged_in=common['logged_in'],
        profile=common['profile'],
        onion_address=onion_address,
        blat_recipient=blat_recipient,
        site_name=SITE_NAME,
        MAX_MSG_LENGTH=MAX_MSG_LENGTH * 32) 

def deliver_blat(recipient, timestamp, subject, content, flags):
    """Post blat directly to recipient's /rx_blat endpoint using X25519 key exchange."""
    logger.info("Attempting to deliver blat to: %s", recipient)
    onion_dir = find_first_onion_service_dir(KEYS_DIR)
    # Look up the recipient's stored public key (from the subscription profile)
    remote_profile = get_profile(recipient)
    remote_pubkey = remote_profile.get("pubkey")
    if not remote_pubkey:
         logger.error("Missing remote public key for recipient %s", recipient)
         return "Error sending message: missing remote public key.", 500
    shared_secret = compute_shared_secret_x25519(get_blitsec(onion_dir), remote_pubkey)
    encrypted_message = encrypt(shared_secret, f"{subject}|{content}")
    payload = {
        'recipient': recipient,
        'sender': SITE_NAME,
        'timestamp': timestamp,
        'encrypted_message': encrypted_message,
        'flags': flags
    }
    print(f"TX Payload:\n\n{payload}\n\n")
    try:
        response = requests.post(
            f'http://{recipient}.onion/rx_blat',
            json=payload,
            proxies={"http": SOCKS_PROXY, "https": SOCKS_PROXY},
            timeout=30
        )

        if response.ok:
            result = response.json()
            if result.get('status') == 'received':
                logger.info("Blat successfully delivered and acknowledged.")
                 
                 # Mark blat as delivered by setting last bit of flags to 1
                conn = get_db_connection()
                conn.execute(
                    'UPDATE blats SET flags = ? WHERE sender = ? AND timestamp = ?',
                    ('0000000000000001', SITE_NAME, timestamp)
                )
                conn.commit()
                conn.close()

            else:
                logger.warning("Blat delivered but response not acknowledged as expected: %s", result)
        else:
            logger.error("Blat delivery failed with status: %d", response.status_code)
        return redirect(url_for('view_blats'))

    except requests.exceptions.Timeout:
        logger.error("Timed out attempting to deliver blat to %s.", recipient)
    except requests.exceptions.RequestException as e:
        logger.error("Error communicating with %s: %s", recipient, e)
    except Exception as e:
        logger.error("Unexpected error delivering to %s: %s", recipient, e)
    return "Error sending message.", 500

@app.route('/send_blat', methods=['POST'])
def send_blat():
    if not is_logged_in():  
        logger.error("Unauthorized attempt to blat.")
        abort(403)

    blat_recipient=request.form.get('blat_recipient')
    subs = [sub['site'] for sub in get_all_subscriptions()]
    if blat_recipient not in subs:
        logger.error("Blat recipient (%s) not in subscriptions list.", blat_recipient)
        return redirect(url_for('index'))

    timestamp = get_current_timestamp_hex()

    subject = request.form.get('subject')
    if not subject or not subject.strip():
         logger.info("Blat rejected: Empty subject.")
         return redirect(url_for('index'))

    content = request.form.get('content')
    if not content or not content.strip():
         logger.info("Blat rejected: Empty content.")
         return redirect(url_for('index'))

    if insert_blat(blat_recipient, SITE_NAME, timestamp, subject, content, '0'*16):
        logger.info("New blat added with timestamp: %s", timestamp)

        # Attempt to deliver blat immediately
        deliver_blat(blat_recipient, timestamp, subject, content, '0'*16)

    else:
        logger.error("Error inserting blat into database.")
    return redirect(url_for('index'))

@app.route('/add_subscription', methods=['POST'])
def add_subscription():
    if not is_logged_in():
        abort(403)
    onion_input_raw = request.form.get('onion_address', '')
    onion_input, dir_name = normalize_onion_address(onion_input_raw)
    if not onion_input:
        return redirect(url_for('index'))
    if not (len(dir_name) == 56 and all(c in string.ascii_lowercase + string.digits + '234567' for c in dir_name)):
         logger.error("Add subscription failed: Invalid address format for %s", onion_input)
         return redirect(url_for('index'))
    if dir_name == SITE_NAME:
         logger.error("Add subscription failed: Cannot subscribe to own site %s", onion_input)
         return redirect(url_for('index'))
    about_info = {}
    try:
        logger.info("Attempting to fetch /about for new subscription: %s", onion_input)
        proxies = {"http": SOCKS_PROXY, "https": SOCKS_PROXY}
        about_url = f"http://{onion_input}/about"
        r = requests.get(about_url, proxies=proxies, timeout=FETCH_TIMEOUT)
        r.raise_for_status()
        about_text = r.text.strip()
        if about_text:
            lines = about_text.splitlines()
            temp_info = {}
            if lines and lines[0].strip().lower() != onion_input:
                 logger.warning("/about first line '%s' does not match expected onion address '%s'", lines[0], onion_input)
            # Process key/value lines 
            for line in lines[1:]:
                 if ":" in line:
                     try:
                         key, value = line.split(":", 1)
                         key = key.strip().lower()
                         value = value.strip()
                         if key in ['nickname', 'loc', 'desc', 'email', 'website', 'pubkey']:
                              if key == 'loc': key = 'location'
                              if key == 'desc': key = 'description'
                              temp_info[key] = value
                     except ValueError:
                          logger.warning("Malformed line in /about from %s: %s", onion_input, line)
            about_info = temp_info
            logger.info("Successfully fetched /about info for %s: %s", onion_input, about_info)
        else:
            logger.warning("/about for %s returned empty response.", onion_input)
    except requests.exceptions.Timeout:
        logger.error("Error fetching /about from %s: Timeout after %s seconds", onion_input, FETCH_TIMEOUT)
    except requests.exceptions.RequestException as e:
        logger.error("Error fetching /about from %s: %s", onion_input, e)
    except Exception as e:
        logger.error("Unexpected error fetching /about from %s: %s", onion_input, e)
    upsert_subscription_profile(dir_name, about_info)
    logger.info("Subscription profile for %s upserted into database.", onion_input)
    logger.info("Submitting initial fetch task for new subscription %s", dir_name)
    fetch_executor.submit(fetch_and_process_feed, dir_name)
    return redirect(url_for('index'))

def fetch_and_process_feed(site):
    site_onion = f"{site}.onion"
    feed_url = f"http://{site_onion}/feed"
    logger.info("[Fetcher] Starting fetch for: %s", site_onion)
    new_bleets_added = 0
    try:
        proxies = {"http": SOCKS_PROXY, "https": SOCKS_PROXY}
        fetched_content = None
        try:
             with requests.get(feed_url, proxies=proxies, timeout=FETCH_TIMEOUT, stream=True) as response:
                 response.raise_for_status()
                 try:
                     fetched_content = response.content.decode('utf-8', errors='replace')
                 except UnicodeDecodeError:
                     fetched_content = response.content.decode('latin-1', errors='replace')
        except requests.exceptions.Timeout:
             logger.error("[Fetcher] Timeout fetching %s", feed_url)
             return 0
        except requests.exceptions.RequestException as e:
             logger.error("[Fetcher] Error fetching %s: %s", feed_url, e)
             return 0
        except Exception as e:
             logger.error("[Fetcher] Unexpected error during fetch request for %s: %s", feed_url, e)
             return 0
        if fetched_content is None:
             logger.error("[Fetcher] Failed to retrieve content from %s", feed_url)
             return 0
        if not fetched_content.strip():
            logger.info("[Fetcher] Empty feed received from %s", site_onion)
            return 0
        malformed_lines = 0
        mismatched_site_lines = 0
        duplicate_timestamps = 0
        for line in fetched_content.strip().splitlines():
              msg_str = line.strip()
              if not msg_str:
                  continue
              parsed_msg = parse_bleet_string(msg_str)
              if not parsed_msg:
                  if malformed_lines < 5:
                      logger.warning("[Fetcher] Invalid bleet format received from %s: %s...", site_onion, msg_str)
                  malformed_lines += 1
                  continue
              if parsed_msg['site'] != site:
                  if mismatched_site_lines < 5:
                      logger.warning("[Fetcher] SECURITY WARNING: Bleet received from %s claims to be from %s. DISCARDING: %s...", site_onion, parsed_msg['site'], msg_str[:100])
                  mismatched_site_lines += 1
                  continue
              conn = get_db_connection()
              c = conn.cursor()
              c.execute("SELECT 1 FROM posts WHERE site = ? AND timestamp = ?", (parsed_msg['site'], parsed_msg['timestamp']))
              exists = c.fetchone()
              conn.close()
              if exists:
                  duplicate_timestamps += 1
                  continue
              if insert_bleet_from_string(msg_str):
                  new_bleets_added += 1
        if malformed_lines > 5:
             logger.warning("[Fetcher] ...skipped %d more malformed lines from %s.", malformed_lines - 5, site_onion)
        if mismatched_site_lines > 5:
             logger.warning("[Fetcher] ...skipped %d more mismatched site lines from %s.", mismatched_site_lines - 5, site_onion)
        if duplicate_timestamps > 0:
             logger.info("[Fetcher] Skipped %d dupes: %s.", duplicate_timestamps, site_onion)
        if new_bleets_added > 0:
             logger.info("[Fetcher] Added %d new bleets for %s.", new_bleets_added, site_onion)
        else:
             logger.info("[Fetcher] No new bleets for: %s.", site_onion)
    except Exception as e:
         logger.error("[Fetcher] Unexpected error processing feed for %s: %s", site_onion, e, exc_info=True)
         return 0
    return new_bleets_added

def run_fetch_cycle():
    global fetch_lock, fetch_executor, fetch_timer, FETCH_CYCLE
    logger.info("Attempting scheduled fetch cycle...")
    if fetch_lock.acquire(blocking=False):
        logger.info("[Fetcher] Acquired lock for scheduled run.")
        total_new_bleets = 0
        sites_fetched_count = 0
        try:
            start_time = time.time()
            subscriptions = get_all_subscriptions()
            if not subscriptions:
                logger.info("[Fetcher] No subscriptions found.")
            else:
                logger.info("[Fetcher] Submitting %d subscriptions for background fetching...", len(subscriptions))
                futures = {fetch_executor.submit(fetch_and_process_feed, sub['site']): sub['site'] for sub in subscriptions}
                results = concurrent.futures.wait(futures)
                sites_fetched_count = len(futures)
                for future in results.done:
                     site = futures[future]
                     try:
                         new_count = future.result()
                         if new_count is not None:
                              total_new_bleets += new_count
                         else:
                              logger.error("[Fetcher] Warning: Task for site %s returned None.", site)
                     except Exception as exc:
                          logger.error("[Fetcher] Subscription %s generated an exception during fetch: %s", site, exc, exc_info=True)
                if results.not_done:
                     logger.warning("[Fetcher] %d fetch tasks did not complete.", len(results.not_done))
        except Exception as e:
            logger.error("[Fetcher] Error during scheduled fetch cycle: %s", e, exc_info=True)
        finally:
            fetch_lock.release()
            logger.info("[Fetcher] Released lock for scheduled run.")
        end_time = time.time()
        duration = end_time - start_time
        logger.info("[Fetcher] Fetch cycle completed in %.2f seconds. Fetched %d subscriptions, %d new bleets.", duration, sites_fetched_count, total_new_bleets)
    else:
        logger.info("[Fetcher] Skipping scheduled run: Fetch lock already held.")
    app_is_exiting = getattr(sys, 'is_exiting', False)
    if not app_is_exiting:
        fetch_timer = threading.Timer(FETCH_CYCLE, run_fetch_cycle)
        fetch_timer.daemon = True
        fetch_timer.start()
    else:
         logger.info("[Fetcher] Application is exiting, not scheduling next fetch cycle.")

@app.route('/fetch_subscriptions', methods=['POST'])
def fetch_subscriptions():
    if not is_logged_in():
        return jsonify({"error": "Authentication required"}), 403
    global fetch_lock, fetch_executor
    logger.info("[Fetcher] Received manual fetch request.")
    if fetch_lock.acquire(blocking=False):
        submitted_tasks = 0
        try:
            subscriptions = get_all_subscriptions()
            if not subscriptions:
                fetch_lock.release()
                return jsonify({"message": "No subscriptions to fetch."})
            for sub in subscriptions:
                fetch_executor.submit(fetch_and_process_feed, sub['site'])
                submitted_tasks += 1
            return jsonify({"message": f"Started background fetch for {submitted_tasks} subscription(s). Refresh later to see results."})
        except Exception as e:
            logger.error("[Fetcher] Error during manual fetch submission: %s", e, exc_info=True)
            return jsonify({"error": "Failed to start fetch process."}), 500
        finally:
             fetch_lock.release()
    else:
        return jsonify({"message": "Fetch operation already in progress. Please wait."}), 429

@app.route('/remove_subscription/<string:site>', methods=['POST'])
def remove_subscription(site):
    if not is_logged_in():
        logger.error("Unauthorized attempt to remove subscription: %s", site)
        return jsonify({"error": "Authentication required"}), 403
    if not (len(site) == 56 and all(c in string.ascii_lowercase + string.digits + '234567' for c in site)):
        logger.error("Invalid site identifier format in removal request: %s", site)
        return jsonify({"error": "Invalid subscription identifier format."}), 400
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("DELETE FROM profiles WHERE site = ? AND site <> ?", (site, SITE_NAME))
        c.execute("DELETE FROM posts WHERE site = ? AND site <> ?", (site, SITE_NAME))
        conn.commit()
        if c.rowcount == 0:
            return jsonify({"error": "Subscription not found."}), 404
    except Exception as e:
        conn.rollback()
        logger.error("Error removing subscription %s: %s", site, e)
        return jsonify({"error": "An error occurred while removing the subscription."}), 500
    finally:
        conn.close()
    return jsonify({"success": True, "message": f"Subscription {site}.onion removed."})

@app.route('/subscriptions_panel')
def subscriptions_panel():
    combined_feed = get_all_posts()
    for post in combined_feed:
        if post['site'] != SITE_NAME:
            prof = get_profile(post['site'])
            post['nickname'] = prof.get('nickname', '')
    common = get_common_context()
    utc_now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    subscriptions = get_all_subscriptions()
    return render_template_string(
        SUBSCRIPTIONS_TEMPLATE,
        utc_time=utc_now,
        combined_feed=combined_feed,
        subscriptions=subscriptions,
        logged_in=common['logged_in'],
        profile=common['profile'],
        bmd2html=bmd2html,
        null_reply_address=NULL_REPLY_ADDRESS,
        site_name=SITE_NAME
    )

@app.route('/rx_blat', methods=['POST'])
def rx_blat():
    """Receive encrypted blat from another user using X25519 key exchange."""
    data = request.get_json()
    recipient = data.get('recipient')
    sender = data.get('sender')
    timestamp = data.get('timestamp')
    encrypted_message = data.get('encrypted_message')
    flags = data.get('flags') or '0'*16
    payload = {
        'recipient': recipient,
        'sender': sender,
        'timestamp': timestamp,
        'encrypted_message': encrypted_message,
        'flags': flags
    }
    print(f"RX Payload:\n\n{payload}\n\n")
    if not recipient or recipient != SITE_NAME:
        logger.warning("Failed delivery attempt: recipient unknown")
        abort(403)
    subs = [sub['site'] for sub in get_all_subscriptions()]
    if not sender or sender not in subs:
        logger.warning("Failed delivery attempt: sender unknown")
        abort(403)
    if not timestamp:
        logger.warning("Failed delivery attempt: timestamp not included")
        abort(403)
    # Look up sender's public key from our subscription records
    sender_profile = get_profile(sender)
    sender_pubkey = sender_profile.get("pubkey")
    if not sender_pubkey:
        logger.error("Missing sender public key for %s", sender)
        abort(403)
    onion_dir = find_first_onion_service_dir(KEYS_DIR)
    shared_secret = compute_shared_secret_x25519(get_blitsec(onion_dir), sender_pubkey)
    try:
        plaintext = decrypt(shared_secret, encrypted_message)
        subject, content = plaintext.split('|', 1)
    except Exception as e:
        logger.error("Error during decryption for blat from %s: %s", sender, e)
        abort(500)
    logger.info(f"Blat received from {sender}:\n\n{plaintext}\n\n")
    recorded = insert_blat(SITE_NAME, sender, timestamp, subject, content, flags)
    if not recorded:
        logger.error("Failed to add received blat (%s) to database.", f"sender:timestamp")
        abort(500)
    else:
        logger.info("Incoming blat added to local database.")

    return jsonify({'status': 'received'})

def get_common_context():
    local_profile = get_local_profile()
    return {
        'header_section': render_template_string(HEADER_TEMPLATE, logged_in=is_logged_in(), profile=local_profile, site_name=SITE_NAME, onion_address=onion_address),
        'footer_section': render_template_string(FOOTER_TEMPLATE, protocol_version=PROTOCOL_VERSION, app_version=APP_VERSION),
        'site_name': SITE_NAME,
        'onion_address': onion_address,
        'profile': local_profile,
        'MAX_MSG_LENGTH': MAX_MSG_LENGTH,
        'bmd2html': bmd2html,
        'null_reply_address': NULL_REPLY_ADDRESS,
        'logged_in': is_logged_in()
    }

def is_logged_in():
    return 'logged_in' in session and session['logged_in']

def initialize_app():
    global SITE_NAME, onion_address
    logger.info("Initializing Blitter Node v%s (Protocol: %s)...", APP_VERSION, PROTOCOL_VERSION)
    os.makedirs(KEYS_DIR, exist_ok=True)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    static_dir = os.path.join(script_dir, 'static')
    os.makedirs(static_dir, exist_ok=True)
    logo_path = os.path.join(static_dir, 'logo_128.png')
    if not os.path.exists(logo_path):
         logger.warning("Logo file not found at %s. Ensure 'static/logo_128.png' exists.", logo_path)
    logger.info("Directories checked/created: %s, static", KEYS_DIR)

    # Check secret word file exists
    secret_file_path = os.path.join(KEYS_DIR, SECRET_WORD_FILE)
    if not os.path.exists(secret_file_path):
        with open(secret_file_path, 'w', encoding='utf-8') as f:
            json.dump({'secret_word': 'changeme'}, f, indent=2)
            logger.info(f"{secret_file_path} created with default secret word.")
        logger.warning("*"*72)
        logger.warning("* WARNING: default secret word of 'changeme' has been set.             *")
        logger.warning("* Change default secret word soon in order to change your passphrase.  *")
        logger.warning("*"*72)

    # Initialize the SQLite database
    init_db()

    logger.info("--- Starting Tor Onion Service Setup ---")
    onion_dir = find_first_onion_service_dir(KEYS_DIR)
    if onion_dir:
        key_blob = get_key_blob(onion_dir)
        if key_blob:
            logger.info("Using key from: %s", onion_dir)
            if start_tor_hidden_service(key_blob):
                logger.info("--- Tor Onion Service setup successful. ---")
                logger.info("Site Name: %s", SITE_NAME)

                # Ensure a matching local profile exists in the database.
                local_profile = get_local_profile()
                if not local_profile:
                     default_profile = {
                          "nickname": SITE_NAME[:4],
                          "location": "",
                          "description": f"Blitter profile for {SITE_NAME[:8]}...{SITE_NAME[-8:]}.onion",
                          "email": "",
                          "website": ""
                     }
                     update_local_profile(default_profile)
                     logger.info("Default local profile inserted into DB.")
                else:
                     logger.info("Local profile loaded from DB.")
            else:
                logger.error("--- Tor Onion Service setup failed. ---")
                SITE_NAME = "tor_failed"
                onion_address = None
        else:
            logger.error("Failed to extract key blob from %s.", onion_dir)
            SITE_NAME = "tor_key_error"
            onion_address = None
    else:
        logger.error("No suitable Tor key directory found. Onion service can not be started.")
        logger.warning("No keys have been created; No Blitter name (onion address) can be unlocked.")
        logger.info("Create a random key with: \n")
        logger.info("python keygen.py\n")
        logger.info("You could also choose the first few characters (the 'prefix') e.g.\n")
        logger.info("python keygen.py --prefix noob\n")
        logger.info("Creating keys can take a few seconds, minutes, days or even longer.")
        logger.info("Keep the prefix short to speed up the generation. On older hardware, keep it very short.")
        logger.info(f"Note that the files created in the new onion directory unlock your Blitter identity.")
        logger.info("Keep them safe and secure!")
        logger.warning("Create a valid key and try again.\n")
        logger.error("Exiting...")
        exit()

    if SITE_NAME.startswith("tor_"):
        logger.error("*"*72)
        logger.error("* ERROR: Tor setup did not complete successfully (Status: %s).", SITE_NAME)
        logger.error("* Ensure Tor service is running, configured with ControlPort 9051")
        logger.error("* and a valid v3 key exists in the 'keys' directory.")
        logger.error("* Check Tor logs (usually /var/log/tor/log or similar) for details.")
        logger.error("* Check Python requirements with: \n{REQUIREMENTS_INSTALL_STRING} *")
        logger.error(f'{"*"*72}\n')
        logger.error("Exiting...")
        exit()  

    # Parse secret word and display passphrase
    try:
        secret_word = None
        secret_word_data = None
        secret_file_path = os.path.join(KEYS_DIR, SECRET_WORD_FILE)
        with open(secret_file_path, 'r', encoding='utf-8') as f:
            secret_word_data = json.load(f)
        if secret_word_data and 'secret_word' in secret_word_data:
            secret_word = secret_word_data.get("secret_word")
        if secret_word:
                if secret_word == 'changeme': logger.warning("Default secret word remains unchanged. Change it soon.")
                logger.info("Using secret word from %s to derive passphrase.", secret_file_path)
                passphrase_words = get_passphrase(onion_dir, secret_word)
                passphrase = " ".join(passphrase_words)
                logger.info("-" * (len(passphrase)+ 22) )
                logger.info('--- Passphrase: "%s" ---', passphrase)
                logger.info("-" * (len(passphrase)+ 22) )
        else:
            logger.info("--- Cannot display passphrase: Could not read secret word from file. ---")
    except FileNotFoundError:
            logger.info("--- Cannot display passphrase: Necessary file not found (key or secret word). ---")
    except Exception as e:
            logger.info("--- Warning: Error generating or displaying passphrase: %s ---", e)

if __name__ == '__main__':
    sys.is_exiting = False
    initialize_app()

    # Optionally assign custom Flask port
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    if args.port:
        FLASK_PORT = args.port

    logger.info("--- Starting initial background fetch cycle ---")
    initial_fetch_thread = threading.Thread(target=run_fetch_cycle, daemon=True)
    initial_fetch_thread.start()

    logger.info("--- Starting Flask server ---")
    logger.info("Site Address: http://%s", onion_address)
    logger.info("Local Access: http://%s:%s", FLASK_HOST, FLASK_PORT)
    logger.info("Press Ctrl+C to stop.")
    try:
        app.run(debug=False, host=FLASK_HOST, port=FLASK_PORT, threaded=True, use_reloader=False)
    except KeyboardInterrupt:
         logger.info("Ctrl+C received, shutting down...")
    except SystemExit as e:
         logger.info("System exit called (%s). Shutting down...", e)
    except Exception as e:
         logger.error("Flask server encountered an error: %s", e, exc_info=True)
    finally:
         logger.info("Initiating shutdown sequence...")
         sys.is_exiting = True
         cleanup_tor_service()
         logger.info("Exiting Blitter Node.")
