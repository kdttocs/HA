"""Pairing: hands the gateway secret from Hark to the app through Home Assistant without anyone pasting it,
and without the secret ever sitting readable in Home Assistant's history.

1. The app (no secret yet) makes a one-time Diffie-Hellman key pair and publishes only the PUBLIC half in
   sensor.hark_gateway_pairing_request.
2. Hark (`gw.py pair`) reads it, makes its own one-time key pair, derives the shared key, encrypts the secret with
   it, and writes its public half + the ciphertext to sensor.hark_gateway_pairing.
3. The app derives the same key, decrypts, checks the secret with Hark's server, saves it in /data, and deletes
   both sensors.
Anyone reading Home Assistant's history sees two public numbers and ciphertext: useless without a private half.
Stdlib only; used by both the app and Hark's tools/gw.py so the two sides can never drift apart.
"""
import hashlib, hmac, secrets

# RFC 3526 group 14 (2048-bit MODP), generator 2
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
G = 2


def keypair():
    priv = secrets.randbits(320) | (1 << 319)
    return priv, pow(G, priv, P)


def _check_pub(pub):
    if not (2 <= pub <= P - 2):
        raise ValueError("bad public value")


def _key(priv, other_pub, a_pub, b_pub):
    _check_pub(other_pub)
    z = pow(other_pub, priv, P).to_bytes(256, "big")
    return hashlib.sha256(b"hark-gateway-pairing-v1|" + z + b"|" + format(a_pub, "x").encode() + b"|" + format(b_pub, "x").encode()).digest()


def _stream(key, n):
    out, i = b"", 0
    while len(out) < n:
        out += hmac.new(key, b"ks" + i.to_bytes(4, "big"), hashlib.sha256).digest(); i += 1
    return out[:n]


def seal(app_pub_hex, secret_text):
    """Hark side. Returns the dict to write as sensor.hark_gateway_pairing attributes."""
    a_pub = int(app_pub_hex, 16)
    b_priv, b_pub = keypair()
    k = _key(b_priv, a_pub, a_pub, b_pub)
    pt = secret_text.encode()
    ct = bytes(x ^ y for x, y in zip(pt, _stream(k, len(pt))))
    tag = hmac.new(k, b"tag" + ct, hashlib.sha256).hexdigest()
    return {"hark_public": format(b_pub, "x"), "for_app_public": app_pub_hex[-16:], "ciphertext": ct.hex(), "tag": tag}


def open_sealed(a_priv, a_pub, msg):
    """App side. Returns the secret text, or raises ValueError if it was not sealed for this key pair."""
    if str(msg.get("for_app_public", "")) != format(a_pub, "x")[-16:]:
        raise ValueError("pairing answer is for a different (older) request")
    b_pub = int(str(msg["hark_public"]), 16)
    k = _key(a_priv, b_pub, a_pub, b_pub)
    ct = bytes.fromhex(str(msg["ciphertext"]))
    if not hmac.compare_digest(hmac.new(k, b"tag" + ct, hashlib.sha256).hexdigest(), str(msg.get("tag", ""))):
        raise ValueError("pairing answer failed its integrity check")
    return bytes(x ^ y for x, y in zip(ct, _stream(k, len(ct)))).decode()


def fingerprint(pub_hex):
    """Short fingerprint of a pairing public key. The app prints it in its own log (which only Home Assistant admins
    and Hark, through the Supervisor's log API, can read); Hark refuses to pair if the published key doesn't match."""
    return hashlib.sha256(("hark-gateway-pair-fp|" + str(pub_hex).lower()).encode()).hexdigest()[:20]


# ---- sealing with a shared key (used for command results written to Home Assistant) ----
def _subkey(secret, label, salt):
    return hmac.new(str(secret).encode(), b"hark-gateway-" + label.encode() + b"|" + salt, hashlib.sha256).digest()


def box(secret, label, plaintext):
    """Encrypt + authenticate text with a key derived from the gateway secret. Returns a small dict of hex strings.
    `label` binds the box to its purpose (e.g. the command id), so a box can't be moved to another command."""
    salt = secrets.token_bytes(16)
    k = _subkey(secret, label, salt)
    pt = plaintext.encode()
    ct = bytes(x ^ y for x, y in zip(pt, _stream(k, len(pt))))
    return {"v": 1, "salt": salt.hex(), "ct": ct.hex(), "tag": hmac.new(k, b"tag" + ct, hashlib.sha256).hexdigest()}


def unbox(secret, label, b):
    salt, ct = bytes.fromhex(str(b["salt"])), bytes.fromhex(str(b["ct"]))
    k = _subkey(secret, label, salt)
    if not hmac.compare_digest(hmac.new(k, b"tag" + ct, hashlib.sha256).hexdigest(), str(b.get("tag", ""))):
        raise ValueError("sealed result failed its integrity check")
    return bytes(x ^ y for x, y in zip(ct, _stream(k, len(ct)))).decode()
