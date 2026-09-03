#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["resvg-py", "pillow", "fonttools"]
# ///
"""Generate the pacvamp brand assets (logo, wordmark, OG image, favicons).

    uv run assets/generate.py            # writes into assets/
    uv run assets/generate.py some/dir   # writes elsewhere

Everything is drawn in code; the wordmark uses Fredoka (SIL OFL), which is
downloaded next to this script on first run and converted to outlines so the
SVGs never depend on an installed font.
"""
import io
import math
import os
import struct
import sys
import urllib.request

import resvg_py
from PIL import Image
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = sys.argv[1] if len(sys.argv) > 1 else HERE
os.makedirs(OUT, exist_ok=True)
os.makedirs(os.path.join(OUT, "favicon"), exist_ok=True)

# ---------------------------------------------------------------- palette
BODY = "#B993FF"        # lavender pac
BODY_SHADE = "#9A6FF0"  # bottom shade
INK = "#2B1D4D"         # outlines, pupil, dark text
CAPE = "#3A2A66"
CAPE_EDGE = "#221838"
LINING = "#E5405E"
FANG = "#FFFFFF"
BLUSH = "#FF8FB3"
BG_DARK = "#17112B"
TEXT_DARK_BG = "#F3ECFF"
TEXT_MUTED = "#B9A9E6"


# ---------------------------------------------------------------- the mark
def mark(size=256, tiny=False, micro=False):
    """Return SVG elements for the pacvamp mark inside a `size` x `size` box.

    `tiny` drops fine detail that turns to mud at 16-32px."""
    s = size / 256.0
    cx, cy, r = 124 * s, 136 * s, 92 * s
    if micro:
        tiny = True
        cx, cy, r = 122 * s, 130 * s, 112 * s
    half = math.radians(32)

    def pol(a, rad=r):
        return cx + rad * math.cos(a), cy + rad * math.sin(a)

    ux, uy = pol(-half)
    lx, ly = pol(half)

    sw = (7 if tiny else 6) * s  # outline stroke

    parts = []

    # -- cape (behind everything)
    # symmetric high collar, scalloped hem
    cape = (
        f"M {26*s:.1f} {50*s:.1f} "
        f"C {44*s:.1f} {104*s:.1f} {10*s:.1f} {168*s:.1f} {18*s:.1f} {238*s:.1f} "
        f"Q {52*s:.1f} {222*s:.1f} {84*s:.1f} {240*s:.1f} "
        f"Q {124*s:.1f} {222*s:.1f} {164*s:.1f} {240*s:.1f} "
        f"Q {196*s:.1f} {222*s:.1f} {230*s:.1f} {238*s:.1f} "
        f"C {238*s:.1f} {168*s:.1f} {204*s:.1f} {104*s:.1f} {222*s:.1f} {50*s:.1f} "
        f"Q {200*s:.1f} {70*s:.1f} {176*s:.1f} {96*s:.1f} "
        f"L {124*s:.1f} {78*s:.1f} "
        f"L {72*s:.1f} {96*s:.1f} "
        f"Q {48*s:.1f} {70*s:.1f} {26*s:.1f} {50*s:.1f} Z"
    )
    if micro:
        mx1, my1 = pol(-half, r * 1.02)
        mx2, my2 = pol(half, r * 1.02)
        parts.append(
            f'<path d="M {cx:.1f} {cy:.1f} L {mx1:.1f} {my1:.1f} L {mx2:.1f} {my2:.1f} Z" fill="{LINING}"/>'
        )
    else:
        parts.append(
            f'<path d="{cape}" fill="{CAPE}" stroke="{CAPE_EDGE}" '
            f'stroke-width="{sw:.1f}" stroke-linejoin="round"/>'
        )
    # red lining peeking out inside the collar (hidden by the body lower down)
    lining = (
        f"M {40*s:.1f} {64*s:.1f} "
        f"C {50*s:.1f} {104*s:.1f} {40*s:.1f} {150*s:.1f} {70*s:.1f} {182*s:.1f} "
        f"L {178*s:.1f} {182*s:.1f} "
        f"C {208*s:.1f} {150*s:.1f} {198*s:.1f} {104*s:.1f} {208*s:.1f} {64*s:.1f} "
        f"Q {194*s:.1f} {82*s:.1f} {172*s:.1f} {102*s:.1f} "
        f"L {124*s:.1f} {88*s:.1f} L {76*s:.1f} {102*s:.1f} "
        f"Q {54*s:.1f} {82*s:.1f} {40*s:.1f} {64*s:.1f} Z"
    )
    if not micro:
        parts.append(f'<path d="{lining}" fill="{LINING}"/>')

    # -- body
    body = (
        f"M {cx:.1f} {cy:.1f} L {ux:.1f} {uy:.1f} "
        f"A {r:.1f} {r:.1f} 0 1 0 {lx:.1f} {ly:.1f} Z"
    )
    parts.append(f'<path d="{body}" fill="{BODY}"/>')
    # soft shade on the lower half (clipped to the body)
    if not tiny:
        parts.append(
            f'<clipPath id="pv-body"><path d="{body}"/></clipPath>'
            f'<ellipse clip-path="url(#pv-body)" cx="{cx:.1f}" cy="{(cy+r*1.05):.1f}" '
            f'rx="{r*1.15:.1f}" ry="{r*0.62:.1f}" fill="{BODY_SHADE}" opacity="0.55"/>'
        )
    parts.append(
        f'<path d="{body}" fill="none" stroke="{INK}" stroke-width="{sw:.1f}" '
        f'stroke-linejoin="round"/>'
    )

    # -- fangs hanging from the upper lip
    dx, dy = math.cos(-half), math.sin(-half)          # along the lip
    px, py = -dy, dx                                    # perpendicular, into the mouth
    fw = (34 if micro else 20 if tiny else 15) * s
    fl = (40 if micro else 30 if tiny else 24) * s
    for t in ((0.62,) if micro else (0.50, 0.76)):
        bx, by = cx + dx * r * t, cy + dy * r * t
        ax, ay = bx - dx * fw / 2, by - dy * fw / 2
        bx2, by2 = bx + dx * fw / 2, by + dy * fw / 2
        tx, ty = bx + px * fl, by + py * fl
        # nudge base under the lip stroke
        ax, ay = ax - px * sw * 0.3, ay - py * sw * 0.3
        bx2, by2 = bx2 - px * sw * 0.3, by2 - py * sw * 0.3
        parts.append(
            f'<path d="M {ax:.1f} {ay:.1f} L {bx2:.1f} {by2:.1f} L {tx:.1f} {ty:.1f} Z" '
            f'fill="{FANG}" stroke="{INK}" stroke-width="{(3.5 if tiny else 3)*s:.1f}" '
            f'stroke-linejoin="round"/>'
        )

    # -- blush
    if not tiny:
        parts.append(
            f'<ellipse cx="{104*s:.1f}" cy="{128*s:.1f}" rx="{13*s:.1f}" ry="{8*s:.1f}" '
            f'fill="{BLUSH}" opacity="0.75"/>'
        )

    # -- eye
    ex, ey = (150 * s, 90 * s) if not micro else (156 * s, 76 * s)
    if micro:
        parts.append(f'<circle cx="{ex:.1f}" cy="{ey:.1f}" r="{24*s:.1f}" fill="{INK}"/>')
        parts.append(f'<circle cx="{(ex+8*s):.1f}" cy="{(ey-8*s):.1f}" r="{8*s:.1f}" fill="#fff"/>')
    elif tiny:
        parts.append(f'<circle cx="{ex:.1f}" cy="{ey:.1f}" r="{18*s:.1f}" fill="{INK}"/>')
        parts.append(f'<circle cx="{(ex+6*s):.1f}" cy="{(ey-6*s):.1f}" r="{6*s:.1f}" fill="#fff"/>')
    else:
        parts.append(
            f'<ellipse cx="{ex:.1f}" cy="{ey:.1f}" rx="{17*s:.1f}" ry="{19*s:.1f}" '
            f'fill="#fff" stroke="{INK}" stroke-width="{4*s:.1f}"/>'
        )
        parts.append(f'<circle cx="{(ex+3*s):.1f}" cy="{(ey+3*s):.1f}" r="{9.5*s:.1f}" fill="{INK}"/>')
        parts.append(f'<circle cx="{(ex+6.5*s):.1f}" cy="{(ey-1.5*s):.1f}" r="{3.5*s:.1f}" fill="#fff"/>')

    return "\n".join(parts)


def svg(w, h, body, extra_attrs=""):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
        f'viewBox="0 0 {w} {h}" {extra_attrs}>\n{body}\n</svg>\n'
    )


def png(svg_text, w, h=None):
    data = resvg_py.svg_to_bytes(svg_string=svg_text, width=w, height=h or w)
    return bytes(data)


def save(name, data):
    path = os.path.join(OUT, name)
    mode = "w" if isinstance(data, str) else "wb"
    with open(path, mode) as f:
        f.write(data)
    print("wrote", path)


# ---------------------------------------------------------------- text as paths
def load_font(path, wght):
    f = TTFont(path)
    return instancer.instantiateVariableFont(f, {"wght": wght, "wdth": 100})


FREDOKA = os.path.join(HERE, "Fredoka.ttf")
FREDOKA_URL = "https://github.com/google/fonts/raw/main/ofl/fredoka/Fredoka%5Bwdth%2Cwght%5D.ttf"
if not os.path.exists(FREDOKA):
    print("downloading Fredoka ->", FREDOKA)
    urllib.request.urlretrieve(FREDOKA_URL, FREDOKA)
_font_cache = {}


def text_path(text, size, x, y, wght=600, tracking=0.0, path=FREDOKA):
    """Return an SVG path `d` for `text` rendered at `size`px with its baseline at (x,y)."""
    key = (path, wght)
    if key not in _font_cache:
        _font_cache[key] = load_font(path, wght)
    f = _font_cache[key]
    upem = f["head"].unitsPerEm
    cmap = f.getBestCmap()
    gs = f.getGlyphSet()
    hmtx = f["hmtx"]
    kern = {}
    # simple pair kerning from GPOS PairPos format 1/2 (best-effort)
    try:
        gpos = f["GPOS"].table
        for lk in gpos.LookupList.Lookup:
            for st in lk.SubTable:
                if getattr(st, "LookupType", lk.LookupType) != 2:
                    continue
                if st.Format == 1:
                    firsts = st.Coverage.glyphs
                    for i, ps in enumerate(st.PairSet):
                        for pvr in ps.PairValueRecord:
                            v = pvr.Value1.XAdvance if pvr.Value1 else 0
                            if v:
                                kern[(firsts[i], pvr.SecondGlyph)] = v
                elif st.Format == 2:
                    c1 = st.ClassDef1.classDefs
                    c2 = st.ClassDef2.classDefs
                    cov = set(st.Coverage.glyphs)
                    for g1 in cov:
                        k1 = c1.get(g1, 0)
                        for g2, k2 in list(c2.items()) + [(None, 0)]:
                            pass
                    # expand lazily below
                    kern.setdefault("_fmt2", []).append((cov, c1, c2, st))
    except KeyError:
        pass

    def pair_kern(a, b):
        if (a, b) in kern:
            return kern[(a, b)]
        for cov, c1, c2, st in kern.get("_fmt2", []):
            if a in cov:
                k1 = c1.get(a, 0)
                k2 = c2.get(b, 0)
                rec = st.Class1Record[k1].Class2Record[k2]
                if rec.Value1 and rec.Value1.XAdvance:
                    return rec.Value1.XAdvance
        return 0

    scale = size / upem
    d = []
    pen_x = 0.0
    glyphs = [cmap.get(ord(c), ".notdef") for c in text]
    for i, g in enumerate(glyphs):
        sp = SVGPathPen(gs)
        tp = TransformPen(sp, (scale, 0, 0, -scale, x + pen_x * scale, y))
        gs[g].draw(tp)
        d.append(sp.getCommands())
        adv = hmtx[g][0]
        if i + 1 < len(glyphs):
            adv += pair_kern(g, glyphs[i + 1])
        pen_x += adv + tracking * upem / size
    width = pen_x * scale
    return " ".join(d), width


# ---------------------------------------------------------------- outputs
# 1. mark (transparent), SVG + PNGs
logo_svg = svg(256, 256, mark(256))
save("logo.svg", logo_svg)
save("logo.png", png(logo_svg, 512))

# 2. wordmark: mark + "pacvamp", light and dark variants
def wordmark(text_fill):
    m = 160
    d, w = text_path("pacvamp", 132, 0, 0, wght=600, tracking=-1.0)
    gap = 18
    total_w = m + gap + w + 8
    H = 176
    # mark vertically centred, text baseline aligned to mark's middle
    body = (
        f'<g transform="translate(0 {(H-m)/2:.1f})">{mark(m)}</g>\n'
        f'<path transform="translate({m+gap:.1f} {H/2+46:.1f})" d="{d}" fill="{text_fill}"/>'
    )
    return svg(math.ceil(total_w), H, body), math.ceil(total_w), H


wm_light, wm_w, wm_h = wordmark(INK)
wm_dark, _, _ = wordmark(TEXT_DARK_BG)
save("wordmark.svg", wm_light)
save("wordmark-dark.svg", wm_dark)
save("wordmark.png", png(wm_light, wm_w * 3, wm_h * 3))
save("wordmark-dark.png", png(wm_dark, wm_w * 3, wm_h * 3))

# 3. OG image 1200x630
def og():
    W, H = 1200, 630
    m = 350
    mx, my = 84, (H - m) / 2 - 4
    tx = mx + m + 52
    avail = W - tx - 64

    def fit(text, size, wght, tracking=0.0):
        d, w = text_path(text, size, 0, 0, wght=wght, tracking=tracking)
        sc = min(1.0, avail / w)
        return d, w * sc, sc

    title_d, title_w, title_sc = fit("pacvamp", 164, 600, -1.5)
    tag_d, tag_w, tag_sc = fit("a pacman frontend with fangs", 42, 500)
    sub_d, sub_w, sub_sc = fit("official repos  ·  third-party repos  ·  aur  —  one command, trust tiers built in", 25, 400)
    body = f"""
<defs>
  <radialGradient id="glow" cx="0.28" cy="0.5" r="0.7">
    <stop offset="0" stop-color="#4A2F8A" stop-opacity="0.9"/>
    <stop offset="1" stop-color="{BG_DARK}" stop-opacity="0"/>
  </radialGradient>
  <pattern id="dots" width="40" height="40" patternUnits="userSpaceOnUse">
    <circle cx="20" cy="20" r="2" fill="#FFFFFF" opacity="0.06"/>
  </pattern>
</defs>
<rect width="{W}" height="{H}" fill="{BG_DARK}"/>
<rect width="{W}" height="{H}" fill="url(#glow)"/>
<rect width="{W}" height="{H}" fill="url(#dots)"/>
<g transform="translate({mx} {my})">{mark(m)}</g>
<path transform="translate({tx} 296) scale({title_sc:.4f})" d="{title_d}" fill="{TEXT_DARK_BG}"/>
<rect x="{tx+6}" y="326" width="{title_w-10:.0f}" height="4" rx="2" fill="{LINING}" opacity="0.9"/>
<path transform="translate({tx+6} 372) scale({tag_sc:.4f})" d="{tag_d}" fill="{TEXT_MUTED}"/>
<path transform="translate({tx+6} 420) scale({sub_sc:.4f})" d="{sub_d}" fill="{TEXT_MUTED}" opacity="0.7"/>
"""
    return svg(W, H, body)


og_svg = og()
save("og-image.svg", og_svg)
save("og-image.png", png(og_svg, 1200, 630))

# 4. favicons: mark on a rounded dark tile
def tile(size, tiny=False, radius_frac=0.22, pad_frac=0.06, micro=False):
    pad = size * pad_frac
    inner = size - 2 * pad
    body = (
        f'<rect width="{size}" height="{size}" rx="{size*radius_frac:.1f}" fill="{BG_DARK}"/>\n'
        f'<g transform="translate({pad:.1f} {pad:.1f})">{mark(inner, tiny=tiny, micro=micro)}</g>'
    )
    return svg(size, size, body)


fav_svg = tile(256)
save("favicon/favicon.svg", fav_svg)
save("favicon/favicon-16x16.png", png(tile(16, micro=True, pad_frac=0.0, radius_frac=0.18), 16))
save("favicon/favicon-32x32.png", png(tile(32, tiny=True, pad_frac=0.03), 32))
save("favicon/favicon-48x48.png", png(tile(48, tiny=True, pad_frac=0.04), 48))
save("favicon/apple-touch-icon.png", png(tile(180, radius_frac=0.0, pad_frac=0.10), 180))
save("favicon/icon-192.png", png(tile(192), 192))
save("favicon/icon-512.png", png(tile(512), 512))
save("favicon/maskable-512.png", png(tile(512, radius_frac=0.0, pad_frac=0.18), 512))

# .ico with 16/32/48 (PNG-compressed entries; Pillow only keeps one frame)
def write_ico(path, pngs):
    entries, blobs = [], []
    offset = 6 + 16 * len(pngs)
    for sz, blob in pngs:
        entries.append(struct.pack("<BBBBHHII", sz % 256, sz % 256, 0, 0, 1, 32, len(blob), offset))
        blobs.append(blob)
        offset += len(blob)
    with open(path, "wb") as f:
        f.write(struct.pack("<HHH", 0, 1, len(pngs)))
        f.writelines(entries)
        f.writelines(blobs)
    print("wrote", path)


write_ico(
    os.path.join(OUT, "favicon", "favicon.ico"),
    [
        (sz, png(tile(sz, tiny=True, micro=(sz == 16), pad_frac=p, radius_frac=rf), sz))
        for sz, p, rf in ((16, 0.0, 0.18), (32, 0.03, 0.22), (48, 0.04, 0.22))
    ],
)

save(
    "favicon/site.webmanifest",
    """{
  "name": "pacvamp",
  "short_name": "pacvamp",
  "icons": [
    { "src": "/icon-192.png", "sizes": "192x192", "type": "image/png" },
    { "src": "/icon-512.png", "sizes": "512x512", "type": "image/png" },
    { "src": "/maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable" }
  ],
  "theme_color": "#17112B",
  "background_color": "#17112B",
  "display": "standalone"
}
""",
)

