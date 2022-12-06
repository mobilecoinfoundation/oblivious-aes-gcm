# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.10.1 (2022-07-31)
### Fixed
- rustdoc typos and formatting ([#461], [#462])

[#461]: https://github.com/RustCrypto/AEADs/pull/461
[#462]: https://github.com/RustCrypto/AEADs/pull/462

## 0.10.0 (2022-07-31)
### Added
- `getrandom` feature ([#446])

### Changed
- Bump `aes` dependency to v0.8 ([#430])
- Rust 2021 edition upgrade; MSRV 1.56+ ([#435])
- Bump `aead` dependency to v0.5 ([#444])
- Bump `ghash` dependency to v0.5 ([#454])

[#435]: https://github.com/RustCrypto/AEADs/pull/435
[#444]: https://github.com/RustCrypto/AEADs/pull/444
[#446]: https://github.com/RustCrypto/AEADs/pull/446
[#454]: https://github.com/RustCrypto/AEADs/pull/454

## 0.9.4 (2021-08-28)
### Changed
- Relax `subtle` and `zeroize` requirements ([#360])

[#360]: https://github.com/RustCrypto/AEADs/pull/360

## 0.9.3 (2021-07-20)
### Changed
- Pin `zeroize` dependency to v1.3 and `subtle` to v2.4 ([#349])

[#349]: https://github.com/RustCrypto/AEADs/pull/349

## 0.9.2 (2021-05-31)

- Initial version, merge of the [original form](https://github.com/mobilecoinofficial/AEADs) into it's own crate based on [upstream](https://github.com/RustCrypto/AEADs).
