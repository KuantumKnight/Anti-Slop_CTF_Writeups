#!/usr/bin/env python3
import struct, sys

def fnv1a_ci(path: bytes) -> int:
    h = 0x811c9dc5
    for c in path:
        if 0x41 <= c <= 0x5a:  # A-Z lowercase
            c = c + 0x20
        h ^= c
        h = (h * 0x1000193) & 0xffffffff
    return h

def enc_path(path: bytes, kind: int) -> bytes:
    out = bytearray()
    key = (0x17 * kind + 0x41) & 0xff
    for i, c in enumerate(path):
        out.append((c ^ key) & 0xff)
        key = (key + 0x11) & 0xff
    return bytes(out)

def enc_body(body: bytes, kind: int) -> bytes:
    out = bytearray()
    k = (19 * kind) & 0xff
    for i, c in enumerate(body):
        out.append((c ^ (0x1d * i) ^ k ^ 0xa7) & 0xff)
    return bytes(out)

def build(entries):
    # entries: list of (path: bytes, body: bytes, kind: int)
    recs = []
    for path, body, kind in entries:
        h = fnv1a_ci(path)
        recs.append((h, path, body, kind))
    recs.sort(key=lambda r: r[0])  # non-decreasing hash order
    out = bytearray()
    out += b'GLYP'
    out += bytes([1, len(recs), 0, 0])
    for h, path, body, kind in recs:
        out += struct.pack('<IHIB', h, len(path), len(body), kind)
        out += enc_path(path, kind)
        out += enc_body(body, kind)
    return bytes(out)

if __name__ == '__main__':
    # reproduce demo
    manifest = (b"name=Monet Warmup\n"
                b"profile.theme=linen\n"
                b"profile.card.title=Monet Warmup\n"
                b"preview.card=<em>Layer paint, preview locally, then publish.</em>\n")
    svg = (b"<svg xmlns='http://www.w3.org/2000/svg' width='320' height='120'>\n"
           b"  <rect width='320' height='120' fill='#f4efe1'/>\n"
           b"  <text x='18' y='68' font-size='28' fill='#835f2d'>graybox demo</text>\n"
           b"</svg>\n")
    data = build([
        (b"manifest.mf", manifest, 1),
        (b"covers/demo.svg", svg, 2),
    ])
    with open('test.glyp', 'wb') as f:
        f.write(data)
    print("wrote test.glyp", len(data), "bytes")
