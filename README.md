# Transmitic: In Development Alpha

Transmitic is an encrypted, peer to peer, file transfer program.  
Transmitic is an early development.

Discord: https://discord.gg/tRT3J6T  
Reddit: https://www.reddit.com/r/transmitic/   
Twitter: https://twitter.com/transmitic  
Website: https://transmitic.io/

## Support Transmitic

<a href="https://www.buymeacoffee.com/andrewshay" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-blue.png" alt="Buy Me A Coffee" height="40" width="150" style="height: 40px !important;width: 150px !important;" ></a>


[![ko-fi](https://www.ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/J3J626I8G)

[Patreon](https://www.patreon.com/andrewshay)

## Comparison To Other Tools

**Bittorrent**  
Transmitic is not bittorrent, and cannot download the same file from multiple peers to download it faster.  
Users connect to one another directly via IP.  

**File Syncing**  
Transmitic does not have any file syncing capability and should never be used for this purpose.

## Development Status

Transmitic is an alpha that is in early development.  
Only power users who are curious about this project should use it right now.   
At this time, expect:  

- No error handling
- No attention to performance
- CLI usage required
- Manual config file usage
- No code reviews
- No tests
- No code quality

This project is slowly being hacked on during nights and weekends.  
It will eventually reach a stable and tested point.

## Contributing

The only area of contribution that is needed at this time is a review of the cryptography usage.  
If you are interested please visit the chat.

## Tech Stack

- Rust (backend)
- Ring
- aes-gcm
- x25519_dalek
- Sciter (GUI)

## Goals (Short Term and Long Term)

- Full GUI support. CLI and manual config not required at all.
- Code refactor
- Error handling
- GUI redesign
- Tests
- Add Users with a "friend request"
- Auto updates
- Transmitic Mini
  - CLI only version with minimal dependencies
- Transmitic Discovery
  - Server to discover users without requiring IPs to be known by users (optional to users)
- Rewrite for performance?
  - tokio?
- Verify file downloads with hashes?

## Cryptography Usage

- Public, Private signing keys generated with `ring`
- Signing `ring` keys are exchanged out of band
- Diffie-Hellman key generation with `x25519_dalek`
  - Diffie-Hellman keys are regenerated for every new TCP stream. Never reused.
- Diffie-Hellman `x25519_dalek` keys are signed with the `ring` keys
- Remote user verifies `x25519_dalek` key with that user's `ring` public key
- AES key generated
- All further communication encrypted with `AES-GCM` with `ring`

## Protocol Overview

- TODO

## Screenshots

![Transmitic](./screenshot.png)

## License

This project is provided "AS IS" and makes no warranties, express or implied.  

To be determined.