<div align="center">
<img src="./src/window_icon.svg" alt="Transmitic Logo" height="150"> 
<h1>Transmitic Beta</h1>
<strong>Encrypted, peer to peer, file transfer and sharing, with download pause and resume</strong>
<br/>
<a href="https://discord.gg/tRT3J6T">Discord</a> ● <a href="https://www.reddit.com/r/transmitic/">Reddit</a> ● <a href="https://twitter.com/transmitic">Twitter</a> ● <a href="https://techhub.social/@transmitic">Mastodon</a> ● <a href="https://transmitic.net/">transmitic.net</a>
</div>
<br/>

- Encrypted
- P2P
- Built with Rust  
- No third party server involved  
- No file size limits  

The goal is to make transferring files and folders as easy as possible.  
If you have ever thought `I just want to send these files directly from this computer to another`, Transmitic can help.   

## How it Works

1. Users exchange Public IDs that Transmitic automatically generates.
1. Add users' Public IDs and IPs that you want to share with.
1. Add files or folders you want to share, and which users you want to share with.
1. Turn sharing on! Users can choose which files they want to download directly from your device.
1. View all files that are shared with you, and download directly from the other user's device.
1. Connections are encrypted with AES256-GCM.
1. Users behind NATs and firewalls can use the "Reverse Connection" feature to still share with users that do not have networking limitations.

See [Demo below](#demo)

## Features

1. Secure
    1. AES-GCM 256 Encryption
    1. Ed25519 Signing Keys
    1. x25519 Diffie-Hellman Key Exchange
1. Easy to use GUI
1. Cross Platform
    1. Windows MSI Installer & Portable
    1. macOS Universal Bundle & Portable
    1. Linux Portable
1. Private
    1. P2P
    1. No third party servers in any way
1. Lan & Internet
1. Share files and folders
1. No file size limits
1. Pause and Resume
    1. Downloads can be paused, or interrupted, but will continue where they left off
1. Reverse Connection
    1. If you're behind a NAT, or have network limitations, but your Users _do not_, you can still share with each other.

## Support Transmitic

Please 🌟 the repo!  

If you get value from Transmitic, please donate

<a href="https://www.buymeacoffee.com/andrewshay" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-blue.png" alt="Buy Me A Coffee" height="40" width="150" style="height: 40px !important;width: 150px !important;" ></a>&nbsp;&nbsp;&nbsp;&nbsp;[![ko-fi](https://www.ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/J3J626I8G) &nbsp;&nbsp;&nbsp;&nbsp;<a href="https://www.patreon.com/andrewshay" target="_blank"><img src="https://user-images.githubusercontent.com/4878195/161663353-d78961a3-71e6-4353-9a2e-3028e64c72e1.png" alt="Patreon" height="40" width="40" style="height: 40px !important;width: 40px !important;" > Patreon</a>

## Comparison To Other Tools

**FTP**  
Transmitic is most similar to FTP (though the FTP protocol is not supported). You choose which files and folders you want to download from other computers that are shared with you.

**BitTorrent**  
Transmitic does not support BitTorrent, or BitTorrent like functionality, in that Transmitic cannot download the same file from multiple peers to download it faster.  

**File Syncing**  
Transmitic is _not_ designed for "file syncing" and should not be used for this purpose.

## Development Status

Transmitic is currently in beta. Please report any bugs that you encounter.

## More Info

See wiki for more information, networking help, and limitations [https://github.com/transmitic/transmitic/wiki](https://github.com/transmitic/transmitic/wiki)

## Contributing

The only area of contribution that is needed at this time is a review of the cryptography usage.  
If you are interested, please visit the [Discord](https://discord.gg/tRT3J6T).

## Dependencies

- [Rust (backend)](https://www.rust-lang.org/)
- [Sciter (GUI)](http://sciter.com/)
- [ring](https://briansmith.org/rustdoc/ring/)
- [aes-gcm](https://docs.rs/aes-gcm/)
- [x25519_dalek](https://docs.rs/x25519-dalek/)

## Future Features

- UPnP
- Transmitic Discovery
  - Server to discover users without requiring IPs to be known by users (optional feature)
- Auto updates
- Transmitic Mini
  - CLI only version with minimal dependencies

See [GitHub Issues](https://github.com/transmitic/transmitic/issues) and [Discussions](https://github.com/transmitic/transmitic/discussions) for more

## Cryptography

- Public, Private signing keys generated with `ring`
- Signing `ring` keys ("Public IDs") are exchanged out of band, manually
- Diffie-Hellman key generation with `x25519_dalek`
  - Diffie-Hellman keys are regenerated for every new TCP stream. Never reused.
- Diffie-Hellman `x25519_dalek` keys are signed with the `ring` keys
- Remote user verifies `x25519_dalek` key with that user's `ring` public key ("Public ID")
- AES key generated
- All further communication encrypted with `AES-GCM` with `ring`

See these modules to review the cryptography in [transmitic-core](https://github.com/transmitic/transmitic-core)

- [crypto.rs](https://github.com/transmitic/transmitic-core/blob/main/src/crypto.rs)
- [transmitic_stream.rs](https://github.com/transmitic/transmitic-core/blob/main/src/transmitic_stream.rs)
- [encrypted_stream.rs](https://github.com/transmitic/transmitic-core/blob/main/src/encrypted_stream.rs)

## Demo

![Transmitic](./screenshot.png)

https://github.com/transmitic/transmitic/assets/4878195/cdca58fc-7de9-4d5e-9057-3dbd339cece6

## Pricing

At this time Transmitic is free for personal and commercial use.  

## Build

Prebuilt binaries available at [Releases](https://github.com/transmitic/transmitic/releases)

```
$ mkdir transmitic_workspace
$ cd transmitic_workspace
$ git clone git@github.com:transmitic/transmitic.git
$ git clone git@github.com:transmitic/transmitic-core.git

# You need the sciter 4 dll. Either pull the repo and put the x64 folder in path
#   OR just download sciter.dll, put it in your sys path, or next to transmitic.exe
$ git clone git@gitlab.com:sciter-engine/sciter-js-sdk.git
# Add to sys path sciter-js-sdk\bin\windows\x64

# Create transmitic_workspace\Cargo.toml
[workspace]

members = [
    "transmitic",
    "transmitic-core"
]


$ cargo run -p transmitic
```


## License

This project is provided "AS IS" and makes no warranties, express or implied.  

To be determined.
