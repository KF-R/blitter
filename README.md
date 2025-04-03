# Blitter: Decentralized Minimalist Messenger 

<img src="https://github.com/user-attachments/assets/46dc3c95-9391-4448-9950-65164bdf3228" width="128" height="128" align="right">

**Blitter** is a radically minimalist, decentralized open source messaging platform inspired by the simplicity and brevity of Twitter but designed with robust privacy, cryptographic identity, and decentralization at its core. Leveraging the established Tor v3 onion routing network, Blitter connects a network of self-hosted sites, creating a resilient anti-fragile platform. An individual site (and therefore user) can only be knocked off the network by their ed25519 secret key being compromised. 

Each Blitter site/user instance also maintains its own list of Blitter sites, subscribed to (i.e. followed) by that user.  General visitors to an individual Blitter site will be able to see both the pure feed of that particular site and its current list of cached messages from its subscriptions to other Blitter sites. 

...

## Installation Requirements:
```
sudo apt install tor
pip install stem Flask requests[socks]
```

## Community & Contribution
Blitter thrives on community collaboration. We welcome developers, security researchers, and privacy advocates to contribute to the evolution of this platform.

- **Report issues:** Open issues on GitHub.
- **Contribute code:** Fork the project and submit pull requests.
- **Community discussions:** Join our forums and chat groups (links coming soon).

## License
Blitter is proudly open-source under the **GPLv3 license**, promoting transparency, freedom, and collaboration.

## Ethos
Blitter developers are proud defenders and proponents of peer-reviewed science, democracy, empathy, individiual personal freedoms, and the rule of law. 
