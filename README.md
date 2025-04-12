<img src="https://github.com/user-attachments/assets/be252f14-5e89-4dff-bb6b-6825c5dc12d5" width="128" height="128" align="left">

### Blitter: A decentralised anti-fragile message network

**Blitter** is a self-hosted, decentralised Tor-based microblogging platform where every user is their own server.
<hr/>
<p>
Think of it as a federated Twitter in the dark—only you control your identity, your content, and who you follow. No account. No centralised servers. No ads. No cancellation. No manipulation. 
</p>

## 🔍 What Is Blitter?

Blitter is:

- 🧱 A **minimalist microblog** engine. Anonymous and secure.
- 🧅 **Tor-native**, hosting each user's feed as a v3 onion service.
- 📡 **Federated**, with each instance pulling updates from subscribed peers.
- 🔒 **Anti-fragile** and **censorship-resistant** by design.
- 🧬 Self-contained in a **single Python file** for simplicity and deployability.

## 🧑‍💻 Key concepts

- Self hosted **Blitter** server: your 'username' is your 56 character onion address (with custom nicknames)
- You can broadcast status updates or **_Bleets_**, which are available to anyone visiting your **Blitter** site.
- Other users can subscribe to your feed to receive it aggregated into their own timeline.
- You can subscribe to other **Blitter** feeds to aggregate them into your own timeline.
- You can also send **_Blats_** (direct private messages), which are end-to-end encrypted, to any **Blitter** user suscribed to your feed. 

---

## 💡 How It Works

1. You run **Blitter** and it spins up a Tor hidden service.
2. Your updates (called **_Bleets_**) are broadcast as a text-based feed over tor, with its secure `.onion` addresses.
3. You can subscribe to other **Blitter** sites (by onion address), and your node will fetch their feeds periodically.
4. That’s it. You’re on your own dark microblog island, linking arms with others.
5. As well as **_Bleets_**, you can send and recieve direct encryped messages called **_Blats_** with other **Blitter** users. 

## Technical Details

1. ed25519 secret keys are used, along with a changeable secret word to generate a pass phrase for authenticating the **Blitter** user, who acts as the sole user and administrator of their own site.
2. **_Bleets_** are fetched by way of regular timed pulls from subscribed sites, directly over tor socks proxy.
3. **_Blats_** are negotiated using a public key derived from the site's identity and a Diffie-Hellman exchange ensures secure end-to-end encryption.

---

## ⚙️ Install & Run (Quickstart)

### Requirements:

- Python 3.8+
- Tor with ControlPort enabled (e.g., `/etc/tor/torrc` must include):
  ```
  ControlPort 9051
  CookieAuthentication 1
  ```
- A valid tor service directory and ed25519 secret key file (see below)

### Installation:

```bash
sudo apt install tor
pip install flask stem requests[socks]
```

## Key Generation

A tor v3 vanity onion address generator is now included, however it should be noted that a tool like [mkp224o](https://github.com/cathugger/mkp224o) leverages lower level code and optimisations and will generate keys **_much_** faster, making slightly longer vanity prefixes viable. 

## Keygen Requirements

Before you can use the included keygen, you'll need to install PyNaCl via pip:

```bash
pip install pynacl
```

## Keygen Usage

Run the script from the command line. Example:

```bash
python keygen.py --prefix abcd --key-dir keys --workers 4
```

### Keygen Command-Line Arguments

- `--prefix`: Desired vanity prefix (max 4 Base32 characters). Leave empty for a random address.
- `--key-dir`: Parent directory to create the onion service directory (default: `keys`).
- `--workers`: Number of worker processes to use (default: the number of CPU cores).


Most new **Blitter** users may want to simply generate an address without a custom "vanity" prefix, which should be near-instantaneous:

```bash
python keygen.py
```

---

## How the Keygen works

1. **Key Generation:** Each worker process generates Ed25519 key pairs.
2. **Address Calculation:** Computes the Tor v3 onion address using the public key.
3. **Prefix Matching:** Workers check if the onion address starts with the specified prefix.
4. **Progress Reporting:** The main process aggregates per-worker metrics and prints overall and individual key generation rates.
5. **Service Setup:** Upon a match, the script creates a dedicated service directory and writes out the `hs_ed25519_secret_key` file.

---


## Launching **Blitter**:

```bash
python blitter.py
```

On first run:
- **A Tor onion service key will be required (see above).**
- You’ll get a passphrase derived from your key and a local secret word.
- Visit `http://127.0.0.1:5000` and login with that passphrase.

Your **Blitter** site will be available (using the [tor browser](https://www.torproject.org/)) at something like:
```
http://bleetmsropwd4542scsvoep3odcqof5hxgvt42heqw5zbsjxatcmxnyd.onion
```

---

## 📐 Technical Summary

### 🌐 Network Architecture

Each node:
- Exposes a v3 onion service on port 80.
- Publishes messages in a plaintext feed format (`/feed` endpoint).
- Responds to `/about` with basic profile metadata.
- Periodically fetches posts from subscribed nodes via Tor SOCKS5 proxy.

### 🔐 Protocol Format

Messages use a structured bar-delimited string:

```
|PROT|SITE|TIMESTAMP|REPLY_ID|EXPIRATION|FLAGS|LEN|CONTENT|
```

Example:

```
|0002|abcdef...56chars|0173fcabc...|000...:000...|ffffffffffffffff|0000000000000000|012|hello world!|
```

- **PROT**: Protocol version (e.g., `0002`)
- **SITE**: Onion address of this message's origin (56 chars)
- **TIMESTAMP**: Nanosecond-precision timestamp in hex used as a unique message identifier
- **REPLY_ID**: Optional `site:timestamp` this message replies to
- **EXPIRATION**: Reserved for future TTL
- **FLAGS**: Reserved
- **LEN**: UTF-8 byte length of content (max 512)
- **CONTENT**: The actual message

### 🧬 Data Model

- SQLite DB with three tables:
  - `profiles`: nickname, description, email, etc.
  - `posts`: all bleets, indexed by site + timestamp
  - `blats`: all blats, outbox, sent, received and read

### 📥 Subscriptions

Add other **Blitter** `.onion` sites as subscriptions:
- **Blitter** fetches `/about` and `/feed` over Tor.
- **_Bleets_** are verified, parsed, and stored locally.
- Feeds are merged in the UI, sorted by timestamp.
- Send and receive direct secure private **_Blats_**

---

## 🧠 Features & Design Highlights

- 🔑 Passphrase-based login derived from secret Tor key + BIP-39.
- 🔐 Diffie-Hellman secure end-to-end encryption for private messages.
- 🔁 Fully offline-capable (local-only viewing possible).
- 🔂 Threaded replies.
- 🔍 View raw message format for transparency.
- 🧱 Entire app in one file for auditability and deployment ease.
- 📦 Minimal external dependencies.
- 📛 Markdown support (*italic*, **bold**, [links](https://github.com/KF-R/blitter))

---

## 🚧 Roadmap Ideas

- Signed message support (deterministic Ed25519)
- Custom backgrounds or avatar support
- Graph-based network visualiser
- Secure direct messages
- Crypto co-signatures

---

## 👤 Who Should Use This?

- Journalists.
- Whistleblowers.
- Dissenters.
- Organisers.
- Democracy defenders.
- "Annexation" defenders.
- Nerds with taste.
- You.

---

## ☠️ Disclaimer

This is an experimental project. It’s built for resilience and independence. Use responsibly. 

---

## License

**Blitter** is proudly open-source under the GPLv3 license, promoting transparency, freedom, and collaboration.

## 🤝 Acknowledgments

- Tor Project (for the incredible onion routing platform)
- Bitcoin project (for the BIP-0039 word list)
- OpenAI (o3-mini-high greatly accelerated development)
- The Internet (for still being broken enough to inspire projects like this)
- You, for resisting authoritarian despots, imperialism, oligarchs and warmongers.
  
---
