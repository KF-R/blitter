<img src="https://github.com/user-attachments/assets/46dc3c95-9391-4448-9950-65164bdf3228" width="128" height="128" align="left">

### Blitter: A decentralised anti-fragile message network

**Blitter** is a self-hosted, decentralised Tor-based microblogging platform where every user is their own server.
<hr/>
<p>
Think of it as a federated Twitter in the dark—only you control your identity, your content, and who you follow. No centralised servers. No ads. No cancellation. No manipulation. 
</p>

## 🔍 What Is Blitter?

Blitter is:

- 🧱 A **minimalist microblog** engine.
- 🧅 **Tor-native**, hosting each user's feed as a v3 onion service.
- 📡 **Federated**, with each instance pulling updates from subscribed peers.
- 🔒 **Private** and **censorship-resistant** by design.
- 🧬 Fully contained in a **single Python file** for simplicity and deployability.

---

## 💡 How It Works (For Humans)

1. You run Blitter and it spins up a Tor hidden service.
2. Your posts (called *bleets*) are broadcast as a text-based feed over tor, with its `.onion` addresses.
3. You can subscribe to other Blitter sites (by onion address), and your node will fetch their feeds periodically.
4. That’s it. You’re on your own dark microblog island, linking arms with others.

---

### 🧠 Conceptual Diagram

```
          .--------.             .--------.
          | Blitter| <--fetch--> | Blitter|
          |  Node A|             |  Node B|
          '--------'             '--------'
              |                       |
              |                       |
         v3 Onion                 v3 Onion
          Service                 Service
              |                       |
          User A's                User B's
          microblog               microblog
```

---

## ⚙️ Install & Run (Quickstart)

### Requirements:

- Python 3.8+
- Tor with ControlPort enabled (e.g., `/etc/tor/torrc` must include):
  ```
  ControlPort 9051
  CookieAuthentication 1
  ```

### Installation:

```bash
sudo apt install tor
pip install flask stem requests[socks]
```

### Launch:

```bash
python blitter.py
```

On first run:
- A Tor onion service key will be generated.
- You’ll get a passphrase derived from your key and a local secret word.
  
_Note: key generation not yet implemented; currently expects `hs_ed25519_secret_key` in the `keys/` directory.`_

_Keys can be generated using a third party tool such as [mkp224o](https://github.com/cathugger/mkp224o), for example._

- Visit `http://127.0.0.1:5000` and login with that passphrase.

Your Blitter site will be available at something like:
```
http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion
```

---

## 📐 How It Works 

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
- **SITE**: Your onion address (56 chars)
- **TIMESTAMP**: Nanosecond-precision timestamp in hex
- **REPLY_ID**: Optional `site:timestamp` this message replies to
- **EXPIRATION**: Reserved for future TTL
- **FLAGS**: Reserved
- **LEN**: UTF-8 byte length of content (max 512)
- **CONTENT**: The actual message

### 🧬 Data Model

- SQLite DB with two tables:
  - `profiles`: nickname, description, email, etc.
  - `posts`: all bleets, indexed by site + timestamp

### 📥 Subscriptions

Add other Blitter `.onion` sites as subscriptions:
- Blitter fetches `/about` and `/feed` over Tor.
- Messages are verified, parsed, and stored locally.
- Feeds are merged in the UI, sorted by timestamp.

---

## 🧠 Features & Design Highlights

- 🔑 Passphrase-based login derived from secret Tor key + BIP-39.
- 🔁 Fully offline-capable (local-only viewing possible).
- 🔂 Threaded replies.
- 🔍 View raw message format for transparency.
- 🧱 Entire app in one file for auditability and deployment ease.
- 📦 Minimal external dependencies.
- 📛 Markdown support (*italic*, **bold**, [links](https://github.com/KF-R/blitter))

---

## 🚧 Roadmap Ideas

- 🧾 Signed message support (deterministic Ed25519).
- 🪪 Profile verification or avatar support.
- 📈 Graph-based social visualiser.

---

## 👤 Who Should Use This?

- Journalists.
- Whistleblowers.
- Dissenters.
- Organisers.
- Democracy defenders.
- "Annexation" defenders (e.g. 🇺🇦,🇨🇦,🇬🇱,🇵🇦,🇹🇼 etc.).
- Nerds with taste.
- You.

---

## ☠️ Disclaimer

This is an experimental project. It’s built for resilience and independence, not convenience or mainstream use. Use responsibly. And pseudonymously.

---

## License

Blitter is proudly open-source under the GPLv3 license, promoting transparency, freedom, and collaboration.

## 🤝 Acknowledgments

- Tor Project (for the incredible onion routing platform)
- The Internet (for being broken enough to warrant this)
- You, for resisting authoritarian despots, imperialism, oligarchs and warmongers.

---
