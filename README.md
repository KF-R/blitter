# Blitter: A decentralised anti-fragile message network

<img src="https://github.com/user-attachments/assets/be252f14-5e89-4dff-bb6b-6825c5dc12d5" width="128" height="128" align="left">

**Blitter** is a self-hosted, decentralised Tor-based microblogging platform where every user is their own server.
<p>
Think of it as a federated Twitter in the dark—only you control your identity, your content, and who you follow. No account. No centralised servers. No ads. No cancellation. No manipulation. 
</p>

<hr>

## 🔍 What Is Blitter?

- 🧱 A **minimalist microblog** engine. Anonymous and secure.
- 🔒 **Anti-fragile** and **censorship-resistant** by design.
- 🧅 **Tor-native**, hosting each user's feed as a v3 onion service.
- 📡 **Federated**, with each instance pulling updates from subscribed peers.
- 🧬 Source code consists of a **single Python file** for simplicity, deployability and easy auditing.

## 🧑‍💻 Key concepts

- Self hosted **Blitter** server: your 'username' is your 56 character onion address (with custom nicknames)
- You can broadcast status updates or **_Bleets_**, which are available to anyone visiting your **Blitter** site.
- Other users can subscribe to your feed to receive it aggregated into their own timeline.
- You can subscribe to other **Blitter** feeds to aggregate them into your own timeline.
- You can also send **_Blats_** (direct private messages), which are end-to-end encrypted, to any **Blitter** user suscribed to your feed.
- No account - not even a username/password; just six memorable words to log in remotely from anywhere in the world
- If you leave it running on your Linux, MacOS or Windows device, you can log in from any other Internet-connected device using the [Tor browser](https://www.torproject.org/).

---

## 💡 How It Works

1. You run **Blitter** and it spins up a Tor hidden service with a unique _.onion_ address.
2. You visit your own Blitter site using the [Tor browser](https://www.torproject.org/).
3. You publish updates (called **_Bleets_**), which are visible to any visitor to your **Blitter** site using its _.onion_ address.
4. You can subscribe to other **Blitter** sites (by _.onion_ address), and your node will fetch their feeds periodically and integrate them into your site's timeline.
5. As well as **_Bleets_**, you can securely send and recieve direct **encrypted** messages called **_Blats_** with other **Blitter** users.
6. That’s it. You’re on your own dark microblog island, linking arms with others.

## Technical Details

1. ed25519 secret keys are used, along with a changeable secret word to generate a pass phrase for authenticating the **Blitter** user, who acts as the sole user and administrator of their own site.
2. **_Bleets_** are fetched by way of regular timed pulls from subscribed sites, directly over tor socks proxy.
3. **_Blats_** are negotiated using a public key derived from the site's identity and a Diffie-Hellman exchange ensures secure end-to-end encryption.

---

# Installing **_Blitter_**

## Either Quickstart:

For quickstart, check the [releases](https://github.com/KF-R/blitter/releases) to see if there's a prepared binary-based package for your platform.
If so, check `quickstart.md` for the quickstart guide.  Thea application executables are fully portable and do not require a full installation process. 
In other words, unzip and run. _Remember to run the included **keygen** once before running **blitter**_.

## Or opt for full manual Python-based Installation _(requires Python 3.8+)_:

### Install Requirements
```bash
sudo apt install tor
pip install flask stem requests[socks] cryptography
```

### Install **Blitter**
```bash
git clone https://github.com/KF-R/blitter
cd blitter
```

## Key Generation

Before you can launch **Blitter** you'll need to generate a key. You can just run the included **keygen** or you can try to generate a custom vanity address.
Note that a dedicated low-level tool like [mkp224o](https://github.com/cathugger/mkp224o) will generate keys _much_ faster, making slightly longer vanity prefixes viable. 

### Manually installed _Keygen_ Requirements

Before you can use the included **keygen**, if it was manually installed, you'll also need to install PyNaCl via pip. This step is unnecessary if using a _Quickstart_ release:

```
pip install pynacl
```

### _Keygen_ Usage

Run the script from the command line. Either run `keygen` or `python keygen.py` depending on whether you are using a quickstart release or a manual Python installation. 
For a custom vanity prefix, use the `--prefix` command-line argument, e.g. `keygen --prefix noob` or `python keygen.py --prefix noob`.
If no prefix is specified, your _.onion_ address will be randomly (and immediately) generated.

### All _Keygen_ Command-Line Arguments

- `--prefix`: Desired vanity prefix (max 8 Base32 characters). Leave empty for a random address.
- `--key-dir`: Parent directory to create the onion service directory (default: `keys`).
- `--workers`: Number of worker processes to use (default: the number of CPU cores).

### How the _Keygen_ works

1. **Key Generation:** Each worker process generates Ed25519 key pairs.
2. **Address Calculation:** Computes the Tor v3 onion address using the public key.
3. **Prefix Matching:** Workers check if the onion address starts with the specified prefix.
4. **Progress Reporting:** The main process aggregates per-worker metrics and prints overall and individual key generation rates.
5. **Service Setup:** Upon a match, the script creates a dedicated service directory and writes out the `hs_ed25519_secret_key` file.

### Alternative keygen notes

If you use an alternative ed25519 (tor v3) keygen, like the aforementioned [mkp224o](https://github.com/cathugger/mkp224o) for example, simply drop the resulting `xxx...xxx.onion` directory containing the key files in `<your blitter directory>/keys/`.

_Note that if multiple key directories are found, the first found will be used, so manage your keys directory appropriately._

---

# Launching **Blitter**:

Either run the **Blitter** executable if using a release, or run `python blitter.py` if using a manual installation.

- **A Tor onion service key will be required (see above).**
- You’ll get a six word passphrase derived from your key and a local secret word.
- Your **Blitter** site will be available (using the [tor browser](https://www.torproject.org/)) at something like:
```
http://bleetmsropwd4542scsvoep3odcqof5hxgvt42heqw5zbsjxatcmxnyd.onion
```
- Use the six word passphrase to log in and start broadcasting your **_Bleets_**.

---

## 📐 Technical Summary

### 🌐 Network Architecture

Each node:
- Exposes a v3 onion service on port 80.
- Publishes messages in a plaintext feed format (`/feed` endpoint).
- Responds to `/about` with basic profile metadata and pubkey for private messages.
- Periodically fetches posts from subscribed nodes via Tor SOCKS5 proxy.
- Uses secure Diffie-Hellman exchange to transfer private messages directly. 

### 🔐 **_Bleet_** Protocol Format

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

---

## 🧠 Features & Design Highlights

- 🔑 Six word passphrase-based login derived from the same unique secret Tor key that unlocks the site's _.onion_ address.
- 🔐 End-to-end encryption for private messages.
- 🔁 Fully offline-capable (local-only viewing possible).
- 🔂 Threaded replies.
- 🔍 View raw message format for transparency.
- 🧱 Entire app in one file for auditability and deployment ease.
- 📦 Minimal external dependencies.
- 📛 Markdown support (*italic*, **bold**, [links](https://github.com/KF-R/blitter))

---

## 🚧 Roadmap Ideas

- Blitter tray: an optional universal inbox for guests
- Image support
- Optionally automatically sending a **_Bleet_** when adding a **Blitter** subscription 
- Custom backgrounds and avatar support
- UI improvements, themes, & customisation
- Expand markdown
- Graph-based network visualiser
- Crypto co-signatures
- File drop

---

## 👤 Who Should Use This?

- Journalists
- Whistleblowers
- Dissenters
- Organisers
- Democracy defenders
- "Annexation" defenders
- Nerds with taste
- You

---

## ☠️ Disclaimer

This is an experimental project. It’s built for resilience and independence. Use responsibly. 

---

## License

**Blitter** is proudly open-source under the GPLv3 license, promoting transparency, freedom, and collaboration.

## 🤝 Acknowledgments

- Tor Project (for the incredible onion routing platform)
- Bitcoin project (for the BIP-0039 word list)
- OpenAI (o3-mini-high greatly accelerated development, RIP)
- The Internet (for still being broken enough to inspire projects like this)
- You, for resisting authoritarianism, imperialism, oligarchs and warmongers
  
---

### Note:
_If Blitter fails to connect to Tor, ensure that your `/etc/tor/torrc` config file contains these lines:_
```
ControlPort 9051
CookieAuthentication 1
```
