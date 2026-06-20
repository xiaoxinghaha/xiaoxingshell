# -*- coding: utf-8 -*-
"""Generate the meatshell app icon (braised pork-belly + terminal prompt).

Pure-Pillow, 4x supersampled for crisp anti-aliasing.
Outputs:  icon.png (256), icon@512.png, xiaoxingshell.ico (multi-size)
"""
import math
from PIL import Image, ImageDraw, ImageFilter, ImageFont, ImageChops

SS = 4
BASE = 256
S = BASE * SS  # working canvas 1024

OUT_DIR = "."  # script is run from assets/


def lerp(a, b, t):
    return int(round(a + (b - a) * t))


def vgradient(size, top, bot):
    """Vertical gradient RGB image."""
    w, h = size
    col = Image.new("RGB", (1, h))
    px = col.load()
    for y in range(h):
        t = y / (h - 1)
        px[0, y] = (lerp(top[0], bot[0], t),
                    lerp(top[1], bot[1], t),
                    lerp(top[2], bot[2], t))
    return col.resize((w, h))


def wavy_band(x0, x1, y_top, y_bot, amp, phase, n=60):
    """Polygon points for a horizontal band with wavy top & bottom edges."""
    pts = []
    for i in range(n + 1):
        x = x0 + (x1 - x0) * i / n
        y = y_top + amp * math.sin(i / n * math.pi * 2.5 + phase)
        pts.append((x, y))
    for i in range(n, -1, -1):
        x = x0 + (x1 - x0) * i / n
        y = y_bot + amp * math.sin(i / n * math.pi * 2.5 + phase + 0.6)
        pts.append((x, y))
    return pts


img = Image.new("RGBA", (S, S), (0, 0, 0, 0))

# ---------------------------------------------------------------- tile (dark terminal)
tile_mask = Image.new("L", (S, S), 0)
ImageDraw.Draw(tile_mask).rounded_rectangle(
    [0, 0, S - 1, S - 1], radius=int(S * 0.22), fill=255)

grad = vgradient((S, S), (37, 36, 46), (22, 21, 28)).convert("RGBA")
img.paste(grad, (0, 0), tile_mask)

# subtle top sheen on the tile
sheen = Image.new("RGBA", (S, S), (0, 0, 0, 0))
ImageDraw.Draw(sheen).ellipse(
    [int(-S * 0.3), int(-S * 0.55), int(S * 1.3), int(S * 0.35)],
    fill=(255, 255, 255, 22))
sheen.putalpha(ImageChops.multiply(sheen.getchannel("A"), tile_mask))
img = Image.alpha_composite(img, sheen)

# ---------------------------------------------------------------- meat block geometry
mx0, my0 = int(S * 0.165), int(S * 0.175)
mx1, my1 = int(S * 0.835), int(S * 0.825)
mw, mh = mx1 - mx0, my1 - my0
block_radius = int(mw * 0.17)

# drop shadow under the block
shadow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
ImageDraw.Draw(shadow).rounded_rectangle(
    [mx0, my0 + int(S * 0.02), mx1, my1 + int(S * 0.03)],
    radius=block_radius, fill=(0, 0, 0, 150))
shadow = shadow.filter(ImageFilter.GaussianBlur(S * 0.025))
img = Image.alpha_composite(img, shadow)

# meat layers on their own layer, then clip to rounded rect
meat = Image.new("RGBA", (S, S), (0, 0, 0, 0))
md = ImageDraw.Draw(meat)
# base fill so wavy edges never leave gaps
md.rounded_rectangle([mx0, my0, mx1, my1], radius=block_radius,
                     fill=(178, 47, 38, 255))

amp = mh * 0.025
# (start_frac, end_frac, color)  top -> bottom, 五花肉 cross-section
layers = [
    (-0.02, 0.15, (94, 52, 32)),     # skin / caramel glaze
    (0.13, 0.31, (255, 224, 209)),   # fat
    (0.29, 0.52, (199, 60, 45)),     # lean
    (0.50, 0.66, (255, 216, 201)),   # fat
    (0.64, 1.04, (181, 48, 39)),     # lean
]
for idx, (a, b, col) in enumerate(layers):
    yt = my0 + mh * a
    yb = my0 + mh * b
    md.polygon(wavy_band(mx0 - 4, mx1 + 4, yt, yb, amp, idx * 1.7),
               fill=col + (255,))

# marbling: faint warm streaks of fat running through the lean layers
for (ly, ph) in [(0.42, 0.0), (0.74, 1.1), (0.92, 2.0)]:
    yc = my0 + mh * ly
    pts = []
    n = 60
    for i in range(n + 1):
        x = mx0 + mw * i / n
        y = yc + mh * 0.010 * math.sin(i / n * math.pi * 3 + ph)
        pts.append((x, y))
    md.line(pts, fill=(255, 228, 214, 70), width=int(S * 0.007), joint="curve")

# glossy highlight on the glaze (top skin) — warm, not gray
md.ellipse([mx0 + mw * 0.12, my0 + mh * 0.012,
            mx0 + mw * 0.60, my0 + mh * 0.085],
           fill=(255, 240, 224, 90))

# clip meat to rounded-rect
meat_mask = Image.new("L", (S, S), 0)
ImageDraw.Draw(meat_mask).rounded_rectangle(
    [mx0, my0, mx1, my1], radius=block_radius, fill=255)
meat.putalpha(ImageChops.multiply(meat.getchannel("A"), meat_mask))
img = Image.alpha_composite(img, meat)

# thin inner rim to define the block edge
rim = Image.new("RGBA", (S, S), (0, 0, 0, 0))
ImageDraw.Draw(rim).rounded_rectangle(
    [mx0, my0, mx1, my1], radius=block_radius, outline=(40, 18, 12, 160),
    width=int(S * 0.006))
img = Image.alpha_composite(img, rim)

# ---------------------------------------------------------------- terminal prompt  >_
def load_font(size):
    for path in (r"C:\Windows\Fonts\consolab.ttf",
                 r"C:\Windows\Fonts\consola.ttf",
                 r"C:\Windows\Fonts\lucon.ttf"):
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    return ImageFont.load_default()


prompt = Image.new("RGBA", (S, S), (0, 0, 0, 0))
pd = ImageDraw.Draw(prompt)
font = load_font(int(S * 0.30))
text = ">_"
bbox = pd.textbbox((0, 0), text, font=font)
tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
tx = (S - tw) / 2 - bbox[0]
ty = (S - th) / 2 - bbox[1]

# dark shadow for legibility on the meat
pd.text((tx + S * 0.012, ty + S * 0.012), text, font=font, fill=(20, 8, 4, 180))
# bright terminal green
pd.text((tx, ty), text, font=font, fill=(126, 255, 122, 255))
prompt = prompt.filter(ImageFilter.GaussianBlur(1.2))
img = Image.alpha_composite(img, prompt)

# ---------------------------------------------------------------- export
img256 = img.resize((BASE, BASE), Image.LANCZOS)
img512 = img.resize((512, 512), Image.LANCZOS)
img256.save("icon.png")
img512.save("icon@512.png")
img.resize((512, 512), Image.LANCZOS).save("icon@1024_preview.png")  # for review
img256.save("xiaoxingshell.ico", format="ICO",
            sizes=[(256, 256), (128, 128), (64, 64),
                   (48, 48), (32, 32), (16, 16)])
print("OK: icon.png, icon@512.png, xiaoxingshell.ico written")
