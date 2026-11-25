# FirmwareLens

Client-side binwalk-style firmware entropy graph, magic signature scanner, security string triage, and hex inspector running 100% locally in your browser.

[![License: MIT](https://img.shields.io/badge/License-MIT-3FB950?style=flat-square)](LICENSE)
[![Language: JavaScript](https://img.shields.io/badge/JavaScript-Vanilla_ES2022-15E0ED?style=flat-square)](https://github.com/shrijeetdev/firmware-lens)
[![Live Demo](https://img.shields.io/badge/Live_Demo-GitHub_Pages-3FB950?style=flat-square)](https://shrijeetdev.github.io/firmware-lens/)
[![Privacy: No Uploads](https://img.shields.io/badge/Uploads-None_(100%25_Client--Side)-0D1117?style=flat-square)](https://shrijeetdev.github.io/firmware-lens/)

**[▶ Open the live tool](https://shrijeetdev.github.io/firmware-lens/)**

---

## Why FirmwareLens Exists

Classic firmware analysis tools like `binwalk` are indispensable for deep extraction, but they require setting up a Python or Rust environment, native decompression libraries, and terminal access. When you just want fast initial triage on a `.bin`, `.img`, `.trx`, or `.chk` dump—whether you are an IoT security researcher, student, or CTF player—installing dependencies slows down the first look.

FirmwareLens packages entropy visualization, header-validated signature scanning, credential/network string triage, and a hex viewer into a single zero-dependency `index.html` file that runs offline in any modern desktop or mobile browser.

---

## Features

- **Chunked Web Worker Processing:** Streams firmware images in 4 MB slices (`File.slice`) inside an inline Blob Web Worker with a live progress bar so multi-hundred-megabyte dumps never freeze the browser UI.
- **Interactive Shannon Entropy Graph:** Plots per-block Shannon entropy ($0.000$ to $8.000$ bits/byte) on an HTML5 `<canvas>` with configurable block sizes (`256 B`, `512 B`, `1 KB`, `4 KB`, `16 KB`, `64 KB`), colour-coded bands (Low `< 3.5`, Medium `3.5–6.8`, High `> 6.8`), hover crosshair readouts, and clickable rising/falling edge detection ($\Delta \ge 2.2$).
- **Header-Validated Signature Scanner:** Scans across chunk boundaries with a 4 KB overlap buffer and validates structural header fields (endianness, block logs, architecture enums, dictionary sizes) to cut false positives, displaying both hexadecimal and decimal offsets.
- **Security-Focused ASCII String Triage:** Extracts printable ASCII runs (configurable minimum length, default `6`) and flags high-signal patterns: `/etc/shadow` and `/etc/passwd` entries, `password=` / `wpa_psk=` / default credential hints, PEM/OpenSSH private key headers, API keys/tokens, HTTP(S) URLs, IPv4 addresses, and embedded daemons (`telnetd`, `dropbear`, `busybox`, `sshd`, `uhttpd`, `dnsmasq`, `hostapd`).
- **256-Byte Hex & ASCII Inspector:** Clicking any signature offset, string offset, entropy edge chip, or point on the entropy chart jumps directly to a 16-byte-aligned 256-byte hex and ASCII dump with byte-class highlighting and `±256B` navigation.
- **Triage Summary & Encryption Heuristic:** Displays human-readable and exact byte size, WebCrypto `SHA-256` digest, overall Shannon entropy, finding counts, and an automated encryption/packing assessment.
- **One-Click Report Exports:** Exports full triage results—including metadata, entropy edges, validated signatures, and highlighted strings—as structured `.json` or `.md` reports.
- **Built-In Synthetic Sample (`Try a sample`):** Generates a 64 KB sample firmware image in memory containing a U-Boot `uImage` header, `gzip` stream, `/etc/shadow` and credential strings, `SquashFS` superblock, 32 KB CSPRNG high-entropy block, and PEM certificate so you can test every panel immediately.

---

## Supported Signatures

FirmwareLens validates structural fields beyond raw magic bytes to suppress false positives:

| Category | Format / Signature | Validated Header Details |
| :--- | :--- | :--- |
| **Compression** | `gzip` (`1F 8B 08`) | Validates flags, extra flags, OS byte, timestamp, and optional original filename |
| **Compression** | `LZMA` standalone | Checks `lc`/`lp`/`pb` props (`< 225`), power-of-2 dictionary size, uncompressed size, and `0x00` range-coder start byte |
| **Compression** | `XZ` (`FD 37 7A 58 5A 00`) | Validates stream flags and integrity check type (`None`, `CRC32`, `CRC64`, `SHA-256`) |
| **Compression** | `Zstandard` (`28 B5 2F FD`) | Verifies reserved frame header descriptor bit and extracts descriptor byte |
| **Compression** | `bzip2` (`BZh[1-9]` + pi magic) | Confirms block size compression level (`100k`–`900k`) |
| **Archives** | `ZIP` (`50 4B 03 04`) | Checks version, compression method, and embedded entry filename |
| **Archives** | `7-zip` (`37 7A BC AF 27 1C`) | Extracts archive format major/minor version |
| **Archives** | `ASCII cpio` (`070701` / `070702`) | Parses hex filename length and extracts first archive entry path |
| **Filesystems** | `SquashFS` (`hsqs` LE / `sqsh` BE) | Validates major version (`1–4`), `block_log` (`2^block_log == block_size`), compression algorithm, and inode count |
| **Filesystems** | `JFFS2` (`85 19` LE / `19 85` BE) | Checks valid node types (`0xE001–0xE009`) and node byte length |
| **Filesystems** | `UBI` (`UBI#`) & `UBIFS` (`31 18 10 06`) | Parses UBI erase-count header VID/data offsets and UBIFS superblock (`node_type=6`) |
| **Filesystems** | `CramFS` (`45 3D CD 28` LE / BE) | Verifies `"Compressed ROMFS"` signature and partition size bounds |
| **Filesystems** | `romfs` (`-rom1fs-`) | Parses full filesystem size and volume name |
| **Filesystems** | `Linux ext2 / ext3 / ext4` (`0xEF53`) | Validates superblock state, error policy, block size, journal/extent feature flags, and volume label |
| **Boot / Firmware** | `U-Boot uImage` (`27 05 19 56`) | Parses image name, payload size, load address, entry point, OS, CPU architecture, and compression type |
| **Boot / Firmware** | `Flattened Device Tree / FIT` (`D0 0D FE ED`) | Validates DTB total size and format version |
| **Boot / Firmware** | `Broadcom TRX` (`HDR0`) | Extracts header version (`v1`/`v2`), image length, flags, and partition offsets |
| **Boot / Firmware** | `Android Boot Image` (`ANDROID!`) | Validates power-of-2 page size (`2048–16384` B), kernel size, and ramdisk size |
| **Executables** | `ELF` (`7F 45 4C 46`) | Parses 32/64-bit class, LSB/MSB endianness, object type, and target CPU architecture |
| **Executables** | `Microsoft PE` (`MZ` + `PE\0\0`) | Follows `e_lfanew` pointer and identifies target machine (`x86`, `x64`, `ARM`, `ARM64`) |
| **Crypto / Keys** | `PEM X.509 Certificate` | Detects `-----BEGIN CERTIFICATE-----` blocks |
| **Crypto / Keys** | `PEM & OpenSSH Private Keys` | Detects `-----BEGIN OPENSSH PRIVATE KEY-----` and `-----BEGIN ... PRIVATE KEY-----` headers |
| **Media Assets** | `PNG`, `JPEG`, `GIF` | Validates `IHDR` dimensions (`PNG`), `JFIF`/`EXIF`/`DQT` markers (`JPEG`), and `GIF87a`/`GIF89a` dimensions |

---

## How to Use

1. **Open FirmwareLens:** Visit https://shrijeetdev.github.io/firmware-lens/ or open `index.html` locally in your browser.
2. **Load a Firmware Image:** Drag and drop a firmware file (`.bin`, `.img`, `.trx`, `.chk`, or raw flash dump) onto the dropzone, click **Select Firmware File**, or click **Try a sample** to synthesize a test image.
3. **Inspect Entropy & Signatures:** Review the summary verdict, hover or click across the Shannon entropy plot to locate compressed/encrypted boundaries, and filter validated filesystem or bootloader headers.
4. **Triage Strings & Export:** Filter interesting strings by category (`Credentials`, `Network`, `System`), click any hex offset to inspect the surrounding 256 bytes in the hex viewer, and download a `.json` or `.md` report.

---

## How Entropy Analysis Works

FirmwareLens divides the input binary into fixed-size blocks (defaulting automatically based on file size, adjustable from `256 B` to `64 KB`) and computes Shannon entropy over each block's 256-value byte frequency histogram:

$$H = -\sum_{i=0}^{255} p_i \log_2(p_i)$$

- **Low Entropy (`0.0 – 3.5`):** Erased flash padding (`0xFF` or `0x00`), sparse tables, or plain ASCII configuration text.
- **Medium Entropy (`3.5 – 6.8`):** Uncompressed machine instructions (ARM, MIPS, x86, RISC-V) and structured binary tables.
- **High Entropy (`6.8 – 8.0`):** Compressed archives/filesystems (`LZMA`, `XZ`, `gzip`, `SquashFS`) or encrypted payloads.

**Honest limitations & false positives:** High entropy alone cannot mathematically distinguish strong encryption from modern compression (such as `LZMA` or `zstd`). FirmwareLens uses a heuristic that cross-references high-entropy blocks against validated compression/filesystem headers—if a file exhibits uniformly high entropy (`> 7.75`) with zero recognized container headers, it is flagged as likely encrypted or obfuscated, though raw headerless compressed streams can occasionally trigger the same profile. Similarly, short signature patterns in random data can occasionally align with valid header constraints; always verify offsets in the hex inspector.

---

## Privacy

**Nothing leaves your browser.** FirmwareLens is a single self-contained HTML file with zero external scripts, zero analytics, and zero network calls. File slicing, `SHA-256` hashing via WebCrypto, entropy math, signature scanning, and string extraction execute strictly inside your local browser tab and Web Worker.

---

## Legal and Ethical Use

Only analyse firmware images that you own, hold explicit written authorization to assess, or are legally permitted to research under applicable local laws. FirmwareLens is built for defensive security research, vulnerability triage, and educational reverse engineering.

---

## Run Locally & Deploy on GitHub Pages

### Run Locally

No build step, Node.js installation, or package manager is required:

~~~bash
git clone https://github.com/shrijeetdev/firmware-lens.git
cd firmware-lens
# Open index.html directly in your browser, or serve locally:
python3 -m http.server 8080
~~~

### Deploy Your Own on GitHub Pages

1. Fork or push `index.html` to a GitHub repository.
2. Open **Settings → Pages** in your repository.
3. Under **Build and deployment**, select **Deploy from a branch**, choose `main` and `/ (root)`, and click **Save**.

---

## Contributing

Contributions are welcome! High-impact areas to extend FirmwareLens:

- **More Signatures:** Add validated header parsers for YAFFS2, UBIFS data nodes, MikroTik NPK, TP-Link/Netgear/D-Link vendor headers, Intel HEX, or Motorola S-Record.
- **Checksums:** Add CRC32 verification for `uImage` data payloads and `TRX` headers.
- **Multi-byte Encodings:** Add UTF-16LE string extraction for Windows CE / UEFI firmware modules.

Open an issue or submit a pull request at https://github.com/shrijeetdev/firmware-lens.

---

## License

Released under the [MIT License](LICENSE).

---

Made by [Shrijeet Singh](https://github.com/shrijeetdev). If this saved you time, a ⭐ helps others find it.
