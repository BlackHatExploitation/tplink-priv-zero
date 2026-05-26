# Firmware Reference

The firmware binary itself is **not stored in this repository** — TP-Link already hosts the official copy, and the SHA-256 below lets the PSIRT validation team confirm they are looking at the exact image that was analysed.

## Analysed firmware image

| Field                | Value                                                                                                            |
|----------------------|------------------------------------------------------------------------------------------------------------------|
| Product              | TP-Link TL-WR841N                                                                                                |
| Hardware version     | V14                                                                                                              |
| Firmware version     | `0.9.1 Build 260107 rel.51385`                                                                                   |
| Release date         | 2026-01-07                                                                                                       |
| Filename             | `TL-WR841Nv14_US_0.9.1_4.19_up_boot[260107-rel51385]_2026-01-07_16.02.28.bin`                                    |
| File size            | 4,063,744 bytes                                                                                                  |
| Architecture         | MIPS32, big-endian, uClibc Linux                                                                                 |
| SHA-256              | `c5e86a8aa029a091cad1c75417b6646a448bdeca09846f6b1d0d428795da3e13`                                               |
| Image format         | Unencrypted SquashFS (header magic `ver. 2.0`)                                                                   |

## Official download location

- Vendor page: <https://www.tp-link.com/us/support/download/tl-wr841n/v14/>
- Direct binary (subject to TP-Link CDN URL changes):
  `https://static.tp-link.com/upload/firmware/2026/202601/TL-WR841Nv14_US_0.9.1_4.19_up_boot[260107-rel51385]_2026-01-07_16.02.28.bin`

## Reproducing the extraction

```bash
# Identify the SquashFS payload offset
binwalk TL-WR841Nv14_US_0.9.1_4.19_up_boot[260107-rel51385]_2026-01-07_16.02.28.bin

# Carve and decompress (binwalk will create _<file>.extracted/ with squashfs-root/)
binwalk -Me TL-WR841Nv14_US_0.9.1_4.19_up_boot[260107-rel51385]_2026-01-07_16.02.28.bin

# Confirm the vulnerable binary
file squashfs-root/lib/libcmm.so
# squashfs-root/lib/libcmm.so: ELF 32-bit MSB executable, MIPS, MIPS32 ...

# Quick static-analysis sanity check
strings squashfs-root/lib/libcmm.so | grep -E '^ipping -c|^traceroute -m'
# ipping -c %d -s %d -w %d %s
# traceroute -m %d -q %d -w %d %s %d &
```

## Key files inside `squashfs-root/`

| Path                                      | Relevance                                                                                |
|-------------------------------------------|------------------------------------------------------------------------------------------|
| `lib/libcmm.so`                           | Contains `rsl_setIppingDiagObj` (`+0x6E7D8`), `rsl_ipping_start` (`+0x6EF48`), `oal_startPing` (`+0xAB110`), `util_execSystem`, `validateInHost` (uncalled), `validateExHost` (uncalled). |
| `usr/bin/httpd`                           | Web server / CGI dispatcher; decrypts `/cgi_gdpr` requests and calls into `libcmm.so`.   |
| `web/js/oid_str.js`                       | Build flags — `INCLUDE_ENABLE_REFER=0` (CSRF off), `INCLUDE_LOGIN_GDPR_ENCRYPT=1`.       |
| `web/js/tpEncrypt.js`                     | AES-128-CBC + RSA-512 transport-encryption implementation (used to derive the PoC).      |
| `web/main/pingNTraceRoute.htm`            | Client-side `isdomain()` regex — bypassable client-only validation.                      |
| `web/js/lib.js`                           | Login form encryption (`exe()`), MD5(user+pass), AES key derivation.                     |
