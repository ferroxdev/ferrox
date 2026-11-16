#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

status=0

python3 - <<'EOF'
import os, re, subprocess, sys
result = subprocess.run(
    ["git", "grep", "-I", "-z", "--name-only", "-E",
     r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", "--", "."],
    capture_output=True)
if result.returncode not in (0, 1):
    sys.exit(result.returncode)
raw = result.stdout
files = [os.fsdecode(f) for f in raw.split(b"\0") if f]
ip = re.compile(r"([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})")
WARP = {
    ".github/workflows/warp-parity.yml",
    "crates/ferrox-app/src/warp.rs",
    "crates/ferrox-app/src/warp_scan.rs",
    "scripts/run-warp-parity.py",
}
SCAN = {"crates/ferrox-app/src/warp_scan.rs"}
PSIPHON = {"crates/ferrox-app/src/psiphon.rs"}
def allowed(a, b, c, d, f):
    if (a, b, c, d) == (0, 0, 0, 0) or (a, b, c, d) == (0, 0, 0, 1) or (a, b, c, d) == (255, 255, 255, 255):
        # 0.0.0.0 is "this network" and 0.0.0.1 is the SOCKS4a marker a client
        # puts in the address field to say a name follows; neither is routable.
        return True
    if a == 127 or a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 169 and b == 254:
        # Link-local, the VPN lane's bypass default; not routable.
        return True
    if a == 192 and b == 168:
        return True
    if a == 198 and b in (18, 19):
        # RFC 2544 benchmarking space, the reference FakeDNS pool's default.
        return True
    if (a, b, c, d) == (1, 1, 1, 1) or (a, b) == (162, 159):
        # Cloudflare's WARP plane: resolvers and the edge the WARP lane dials
        # are runtime data in warp.rs and warp_scan.rs, not test material.
        return f in WARP
    if (a == 188 and b == 114) or (a, b, c) == (172, 65, 251):
        # Cloudflare's other WARP edge ranges, also runtime scan data in warp_scan.rs.
        return f in SCAN
    if (a, b, c, d) in (
        (23, 215, 0, 206), (23, 215, 0, 203), (23, 212, 250, 91),
        (23, 212, 250, 78), (23, 12, 147, 13), (23, 12, 147, 29),
        (23, 73, 207, 8), (23, 73, 207, 15), (92, 123, 102, 43),
    ):
        # The Android client's CDN edge scan data in psiphon.rs, not test material.
        return f in PSIPHON
    if (a, b) in ((192, 0), (198, 51), (203, 0)) and (
        (c == 2 and a == 192) or (c == 100 and a == 198) or (c == 113 and a == 203)):
        return True
    return False
bad = 0
for f in files:
    try:
        text = open(f, encoding="utf-8", errors="strict").read()
    except (UnicodeError, OSError):
        continue
    for n, line in enumerate(text.splitlines(), 1):
        for m in ip.finditer(line):
            a, b, c, d = (int(m.group(i)) for i in range(1, 5))
            if not all(x <= 255 for x in (a, b, c, d)):
                continue
            if not allowed(a, b, c, d, f):
                print(f"::error::{f}:{n}: routable IPv4 literal {m.group(0)} — use TEST-NET (192.0.2.0/24)")
                bad += 1
sys.exit(1 if bad else 0)
EOF

python3 - <<'EOF'
import base64, json, re, subprocess, sys
link = re.compile(r"(?:vless|vmess|trojan|ss)://[^@#? ]+@([^/?# ]+)")
vmess = re.compile(r"vmess://([A-Za-z0-9+/=_-]+)")
allowed = re.compile(
    r"^(\[::1\]|::1|(127|10)\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}"
    r"|(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}"
    r"|localhost|example\.(com|net|org)"
    r"|[A-Za-z0-9.-]+\.(test|invalid|localhost|example)"
    r"|uuid|host|\{host\})([:/?#]|$)"
)
result = subprocess.run(
    ["git", "grep", "-I", "-n", "-E",
     r"(vless|vmess|trojan|ss)://[^@#? ]+@[^/:?# ]+", "--", "."],
    capture_output=True, text=True)
if result.returncode not in (0, 1):
    sys.exit(result.returncode)
bad = 0
for line in result.stdout.splitlines():
    for match in link.finditer(line):
        if allowed.match(match.group(1)):
            continue
        where = re.match(r"^(.*?):(\d+):", line)
        prefix = f"{where.group(1)}:{where.group(2)}" if where else "?"
        print(f"::error::{prefix}: share-link with a non-documentation host — working configs arrive as masked CI input only")
        bad += 1
vmess_result = subprocess.run(
    ["git", "grep", "-I", "-n", "-E", r"vmess://[A-Za-z0-9+/=_-]+", "--", "."],
    capture_output=True, text=True)
if vmess_result.returncode not in (0, 1):
    sys.exit(vmess_result.returncode)
for line in vmess_result.stdout.splitlines():
    for match in vmess.finditer(line):
        token = match.group(1) + "=" * (-len(match.group(1)) % 4)
        try:
            document = json.loads(base64.b64decode(token, altchars=b"-_", validate=False))
        except (ValueError, json.JSONDecodeError):
            continue
        host = document.get("add") or document.get("host") if isinstance(document, dict) else ""
        if not isinstance(host, str) or not host or allowed.match(host + ":"):
            continue
        where = re.match(r"^(.*?):(\d+):", line)
        prefix = f"{where.group(1)}:{where.group(2)}" if where else "?"
        print(f"::error::{prefix}: vmess link with a non-documentation host — working configs arrive as masked CI input only")
        bad += 1
sys.exit(1 if bad else 0)
EOF

if git grep -I -n -E -e '-----BEGIN .*PRIVATE KEY-----' -- . ':!scripts/check-fixture-safety.sh'; then
  echo "::error::private key block in the tree — test material is generated at runtime"
  status=1
fi

exit "$status"
