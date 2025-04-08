#!/usr/bin/env python
APP_VERSION = '0.0.1'
import nacl.bindings
import os
import hashlib
import base64
import time
import re
import multiprocessing
import argparse

# --- Constants ---
TOR_V3_SECRET_KEY_HEADER = b"== ed25519v1-secret: type0 ==\x00\x00\x00"
SECRET_KEY_FILENAME = "hs_ed25519_secret_key"
CHECKSUM_SALT = b".onion checksum"
TOR_VERSION = b"\x03"
EXPECTED_SK_LEN = 64
EXPECTED_PK_LEN = 32
BASE32_CHARS = 'abcdefghijklmnopqrstuvwxyz234567'
BASE32_REGEX = re.compile(f'^[{BASE32_CHARS}]*$')
MAX_PREFIX_LEN = 6

# --- Helper Function ---
def calculate_v3_onion_address(public_key_bytes):
    """Calculates the v3 onion address from the Ed25519 public key."""
    if len(public_key_bytes) != EXPECTED_PK_LEN:
        raise ValueError(f"Public key must be {EXPECTED_PK_LEN} bytes, got {len(public_key_bytes)}.")
    hasher = hashlib.sha3_256()
    hasher.update(CHECKSUM_SALT)
    hasher.update(public_key_bytes)
    hasher.update(TOR_VERSION)
    checksum = hasher.digest()[:2]
    data_to_encode = public_key_bytes + checksum + TOR_VERSION
    onion_address_str = base64.b32encode(data_to_encode).lower().rstrip(b'=').decode('utf-8')
    return onion_address_str

# --- Worker Function ---
def worker_process(worker_id, prefix, progress_counter, found_event, result_queue):
    local_count = 0
    while not found_event.is_set():
        local_count += 1
        pk_bytes_candidate, sk_bytes_candidate = nacl.bindings.crypto_sign_keypair()

        # Basic sanity check (should not fail normally)
        if len(sk_bytes_candidate) != EXPECTED_SK_LEN or len(pk_bytes_candidate) != EXPECTED_PK_LEN:
            continue

        address_candidate = calculate_v3_onion_address(pk_bytes_candidate)
        if not prefix or address_candidate.startswith(prefix):
            # Flush any remaining attempts
            with progress_counter.get_lock():
                progress_counter.value += local_count
            result_queue.put((worker_id, address_candidate, pk_bytes_candidate, sk_bytes_candidate))
            found_event.set()
            return

        # Update shared counter every 1,000 attempts to reduce lock overhead
        if local_count >= 1000:
            with progress_counter.get_lock():
                progress_counter.value += local_count
            local_count = 0

# --- Main Function ---
def create_onion_service_files(key_dir='keys', prefix='', num_workers=None):
    # Validate prefix
    prefix = prefix.lower()
    if not (0 <= len(prefix) <= MAX_PREFIX_LEN):
        raise ValueError(f"Prefix length must be between 0 and {MAX_PREFIX_LEN} characters, got {len(prefix)} ('{prefix}').")
    if prefix and not BASE32_REGEX.match(prefix):
        raise ValueError(f"Invalid prefix characters. Only use Base32 characters ({BASE32_CHARS}), got '{prefix}'.")

    if num_workers is None:
        num_workers = multiprocessing.cpu_count()
    print(f"Using {num_workers} worker process{'es' if num_workers > 1 else ''}...")
    if prefix:
        print(f"Searching for onion address starting with prefix: '{prefix}'...")
        print("(This could take a while depending on luck and the prefix!)")
    else:
        print("Generating a random onion address...")

    # Set up multiprocessing primitives
    found_event = multiprocessing.Event()
    result_queue = multiprocessing.Queue()
    workers = []
    progress_counters = []
    for i in range(num_workers):
        counter = multiprocessing.Value('L', 0)
        progress_counters.append(counter)
        p = multiprocessing.Process(target=worker_process, args=(i, prefix, counter, found_event, result_queue))
        p.start()
        workers.append(p)

    # Progress monitoring loop
    start_time = time.time()
    last_counters = [0] * num_workers
    try:
        while not found_event.is_set():
            time.sleep(1)
            elapsed = time.time() - start_time
            total_attempts = 0
            per_worker_rates = []
            for idx, counter in enumerate(progress_counters):
                current = counter.value
                delta = current - last_counters[idx]
                per_worker_rates.append(delta)
                last_counters[idx] = current
                total_attempts += current
            overall_rate = total_attempts / elapsed if elapsed > 0 else 0
            rate_info = " | ".join([f" {i}: {rate:,.0f} keys/s" for i, rate in enumerate(per_worker_rates)])
            print(f"[{elapsed:.2f}s] Overall: {total_attempts:,} keys, {overall_rate:,.0f} keys/s. Workers:\n{rate_info}")
        # Retrieve result when found
        winner_worker, onion_address, pk_bytes, sk_bytes = result_queue.get()
    finally:
        # Terminate any remaining worker processes
        for p in workers:
            p.terminate()
        for p in workers:
            p.join()

    end_time = time.time()
    total_elapsed = end_time - start_time
    total_attempts_sum = sum([counter.value for counter in progress_counters])
    print(f"\nFound matching key from worker {winner_worker} after approx {total_attempts_sum:,} attempts in {total_elapsed:.2f} seconds.")
    print(f"Generated Onion Address: {onion_address}.onion")

    # --- Create Service Files ---
    parent_dir_path = os.path.abspath(key_dir)
    try:
        os.makedirs(parent_dir_path, exist_ok=True)
    except OSError as e:
        print(f"Error creating parent directory '{parent_dir_path}': {e}")
        raise

    onion_service_dirname = f"{onion_address}.onion"
    onion_service_dir_path = os.path.join(parent_dir_path, onion_service_dirname)
    try:
        os.makedirs(onion_service_dir_path)
        print(f"Created service directory: {onion_service_dir_path}")
    except FileExistsError:
        raise FileExistsError(f"Service directory '{onion_service_dir_path}' already exists. Please check the directory.")
    except OSError as e:
        print(f"Error creating service directory '{onion_service_dir_path}': {e}")
        raise

    secret_key_file_path = os.path.join(onion_service_dir_path, SECRET_KEY_FILENAME)
    file_content = TOR_V3_SECRET_KEY_HEADER + sk_bytes
    try:
        with open(secret_key_file_path, "wb") as f:
            f.write(file_content)
        print(f"Created secret key file: {secret_key_file_path}")
    except (IOError, OSError) as e:
        print(f"Error writing file '{secret_key_file_path}': {e}")
        raise

    return onion_address, onion_service_dir_path

# --- Command-Line Interface ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate Tor v3 Onion Service keys with optional vanity prefix.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--key-dir", default="keys", help="Parent directory to create the <onion_address>.onion service directory.")
    parser.add_argument("--prefix", default="", help=f"Desired vanity prefix (max {MAX_PREFIX_LEN} Base32 characters: {BASE32_CHARS}).")
    parser.add_argument("--workers", type=int, default=multiprocessing.cpu_count(), help="Number of worker processes to use.")
    args = parser.parse_args()

    try:
        onion_addr, service_dir = create_onion_service_files(key_dir=args.key_dir, prefix=args.prefix, num_workers=args.workers)
        print("\n--- Summary ---")
        print(f"Full Onion Address: {onion_addr}.onion")
        print(f"Service Directory:  {service_dir}")
        print(f"Secret Key File:  {os.path.join(service_dir, SECRET_KEY_FILENAME)}")
    except (ValueError, FileExistsError) as e:
        print(f"\nError: {e}")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
