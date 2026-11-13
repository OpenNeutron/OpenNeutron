#!/usr/bin/env python3
"""An independent DKIM verification of a message this server signed.

Deliberately not the server's own code: RFC 6376 written out from scratch, the
public key fetched from DNS, the RSA check done by `cryptography`. If this says
PASS, a stranger's implementation agrees with ours.
"""
import base64
import json
import re
import sys
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def split_message(raw: bytes):
    head, body = raw.split(b"\r\n\r\n", 1)
    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    headers = []
    for line in lines:
        if line[:1] in (b" ", b"\t") and headers:
            headers[-1] = (headers[-1][0], headers[-1][1] + b" " + line.strip())
        else:
            name, _, value = line.partition(b":")
            headers.append((name.decode(), value.strip().decode("utf-8", "replace")))
    return headers, body


def canon_header(name: str, value: str) -> str:
    """relaxed: lowercase name, unfold, collapse WSP runs, strip trailing WSP."""
    return f"{name.strip().lower()}:{' '.join(value.split())}\r\n"


def canon_body_relaxed(body: bytes) -> bytes:
    out = []
    for line in body.replace(b"\r\n", b"\n").split(b"\n"):
        collapsed = bytearray()
        in_run = False
        for byte in line:
            if byte in (0x20, 0x09):
                if not in_run:
                    collapsed += b" "
                    in_run = True
            else:
                collapsed.append(byte)
                in_run = False
        out.append(bytes(collapsed).rstrip(b" "))
    while out and out[-1] == b"":
        out.pop()
    return b"\r\n".join(out) + b"\r\n" if out else b"\r\n"


def tags(sig: str) -> dict:
    out = {}
    for part in " ".join(sig.split()).split(";"):
        if "=" in part:
            key, _, value = part.partition("=")
            out[key.strip()] = value.strip()
    return out


def dns_public_key(selector: str, domain: str) -> bytes:
    url = f"https://dns.google/resolve?name={selector}._domainkey.{domain}&type=TXT"
    data = json.load(urllib.request.urlopen(url, timeout=20))
    for answer in data.get("Answer", []):
        txt = answer["data"].strip('"').replace('" "', "")
        if "p=" in txt:
            return base64.b64decode(tags(txt)["p"])
    raise SystemExit(f"no DKIM key at {selector}._domainkey.{domain}")


def verify_one(headers, body, sig: str, index: int) -> None:
    t = tags(sig)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(canon_body_relaxed(body))
    computed_bh = base64.b64encode(digest.finalize()).decode()

    print(f"signature {index}: d={t['d']} s={t['s']} c={t.get('c', 'simple/simple')}")
    print(f"  body hash signed   {t['bh']}")
    print(f"            computed {computed_bh}  {'MATCH' if computed_bh == t['bh'] else 'MISMATCH'}")

    canon = t.get("c", "simple/simple").split("/")
    if len(canon) < 2 or canon[1] != "relaxed":
        print("  (this checker only implements relaxed body canonicalization)")
        return

    pool = [(n, v) for n, v in headers if n.lower() != "dkim-signature"]
    signed = ""
    for name in [x.strip().lower() for x in t["h"].split(":")]:
        for i in range(len(pool) - 1, -1, -1):
            if pool[i][0].lower() == name:
                signed += canon_header(*pool.pop(i))
                break
        else:
            print(f"  h= names '{name}' but the message has no such header — cannot verify")
            return

    # The signature header itself, with the b= value emptied.
    sig_empty = re.sub(r"b=[^;]*", "b=", sig, count=1)
    sig_empty = " ".join(sig_empty.split())
    signed += f"dkim-signature:{sig_empty}"

    key = serialization.load_der_public_key(dns_public_key(t["s"], t["d"]))
    try:
        key.verify(base64.b64decode(t["b"]), signed.encode(), padding.PKCS1v15(), hashes.SHA256())
        print("  rsa-sha256 PASS — an independent implementation agrees with the server")
    except Exception as error:  # noqa: BLE001
        print(f"  rsa-sha256 FAIL — {error}")


def main(path: str) -> int:
    raw = open(path, "rb").read()
    headers, body = split_message(raw)
    sigs = [v for n, v in headers if n.lower() == "dkim-signature"]
    if not sigs:
        print("no DKIM-Signature: the server did not sign this message")
        return 1
    for index, sig in enumerate(sigs, 1):
        verify_one(headers, body, sig, index)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/opt/on/data/capture.eml"))
