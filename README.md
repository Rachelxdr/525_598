# Nemocracy

This is the Rust implementation of Nemocracy, which provides the anonymization of distributed public key infrastructure. The current implementation supports 4 honest parties and 3 Byzantine parties. The current set up uses the virtual machines provided by CS525 at UIUC. The implementation used the Traceable Ring Signature algorithm by [Eiichiro Fujisaki and Koutarou Suzuki](https://eprint.iacr.org/2006/389.pdf). The Traceable Signature implementation is imported from [rozbb/fujisaki-ringsig](https://github.com/rozbb/fujisaki-ringsig).

## Installation

Use the following commands to install Rust and Cargo.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

## Usage

```bash
git clone https://github.com/Rachelxdr/525_598.git

cd 525_598
cargo run
```

## License
[MIT](https://choosealicense.com/licenses/mit/)