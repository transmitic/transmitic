# <img src="./src/window_icon.svg" alt="Transmitic Logo" height="30"> Transmitic Beta

Transmitic is an encrypted, peer to peer, file transfer program with download pause and resume.  
Built with Rust.  
No third party server is involved.  
No file size limit!

The goal is to make transferring files and folders as easy as possible.  
If you have ever thought _"I just want to send these files directly from this computer to another"_, Transmitic can help.   

Discord: [https://discord.gg/tRT3J6T](https://discord.gg/tRT3J6T)  
Reddit: [https://www.reddit.com/r/transmitic/](https://www.reddit.com/r/transmitic/)  
Twitter: [https://twitter.com/transmitic](https://twitter.com/transmitic)  
Website: [https://transmitic.net/](https://transmitic.net/)  

## Support Transmitic

Your support is greatly needed  

<a href="https://www.buymeacoffee.com/andrewshay" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-blue.png" alt="Buy Me A Coffee" height="40" width="150" style="height: 40px !important;width: 150px !important;" ></a>

[![ko-fi](https://www.ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/J3J626I8G)

<a href="https://www.patreon.com/andrewshay" target="_blank"><img src="https://user-images.githubusercontent.com/4878195/161663353-d78961a3-71e6-4353-9a2e-3028e64c72e1.png" alt="Patreon" height="40" width="40" style="height: 40px !important;width: 40px !important;" > Patreon</a>


## Comparison To Other Tools

**FTP**  
Transmitic is most similar to FTP (though the FTP protocol is not supported). You choose which files and folders you want to download from other computers that are shared with you.

**BitTorrent**  
Transmitic does not support BitTorrent, or BitTorrent like functionality, in that Transmitic cannot download the same file from multiple peers to download it faster.  

**File Syncing**  
Transmitic is _not_ designed for "file syncing" and should _never_ be used for this purpose.

## Development Status

Transmitic is currently in beta. Please report any bugs that you encounter.

## More Info

See wiki for more information, help, and limitations [https://github.com/transmitic/transmitic/wiki](https://github.com/transmitic/transmitic/wiki)

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

- Linux support
- macOS support
- Add users with a "friend request"
- UPnP
- Transmitic Discovery
  - Server to discover users without requiring IPs to be known by users (optional feature)
- Auto updates
- Transmitic Mini
  - CLI only version with minimal dependencies

See [GitHub Issues](https://github.com/transmitic/transmitic/issues) and [Discussions](https://github.com/transmitic/transmitic/discussions) for more

## Cryptography Usage

- Public, Private signing keys generated with `ring`
- Signing `ring` keys ("PublicIDs") are exchanged out of band, manually
- Diffie-Hellman key generation with `x25519_dalek`
  - Diffie-Hellman keys are regenerated for every new TCP stream. Never reused.
- Diffie-Hellman `x25519_dalek` keys are signed with the `ring` keys
- Remote user verifies `x25519_dalek` key with that user's `ring` public key ("PublicID")
- AES key generated
- All further communication encrypted with `AES-GCM` with `ring`

See these modules to review the cryptography usage in [transmitic-core](https://github.com/transmitic/transmitic-core)

- [crypto.rs](https://github.com/transmitic/transmitic-core/blob/main/src/crypto.rs)
- [transmitic_stream.rs](https://github.com/transmitic/transmitic-core/blob/main/src/transmitic_stream.rs)
- [encrypted_stream.rs](https://github.com/transmitic/transmitic-core/blob/main/src/encrypted_stream.rs)

## Screenshots

### Current

![Transmitic](./screenshot.png)

https://user-images.githubusercontent.com/4878195/161657290-e15fae8f-3fa3-4a4a-8c52-3700cf024e37.mp4

## Pricing

At this time Transmitic is free for personal and commercial use.  

## Build

```
$ mkdir transmitic_workspace
$ cd transmitic_workspace
$ git clone git@github.com:transmitic/transmitic.git
$ git clone git@github.com:transmitic/transmitic-core.git

# You need the sciter dll. Either pull the repo and put the x64 folder in path
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
