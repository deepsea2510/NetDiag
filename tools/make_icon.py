# -*- coding: utf-8 -*-
"""生成 NetDiag 应用图标（PNG + 多尺寸 ICO），只依赖 PySide6。

图标构成（与 GUI 主色一致）：
  深青绿圆角方块（squircle）+ 一条「网络总线」串三个节点 + 上方一道信号弧。

小尺寸不靠缩放，而是按尺寸重新计算线宽与留白，保证 16px 下仍可辨认。

用法：
    python tools/make_icon.py                 # 输出到 assets/
    python tools/make_icon.py --out assets --preview
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import (
    QColor, QGuiApplication, QImage, QLinearGradient, QPainter, QPainterPath, QPen,
)

# ---- 配色（与 main_qt.py 的深青绿主题一致）----
C_TOP = QColor("#1E8C6E")      # 渐变顶端
C_BOTTOM = QColor("#0A3A36")   # 渐变底端
C_NODE = QColor("#FFFFFF")
C_ARC = QColor("#7CF0C8")      # 薄荷色信号弧
C_RIM = QColor(255, 255, 255, 26)

BASE = 1024                     # 设计基准画布
SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]


def _squircle(p: QPainter, rect: QRectF, radius: float):
    path = QPainterPath()
    path.addRoundedRect(rect, radius, radius)
    p.fillPath(path, _bg_gradient(rect))
    p.setPen(QPen(C_RIM, max(0.6, rect.width() * 0.008)))
    p.setBrush(Qt.NoBrush)
    path2 = QPainterPath()
    inset = rect.width() * 0.018
    path2.addRoundedRect(rect.adjusted(inset, inset, -inset, -inset),
                         radius - inset, radius - inset)
    p.drawPath(path2)


def _bg_gradient(rect: QRectF) -> QLinearGradient:
    g = QLinearGradient(rect.topLeft(), rect.bottomRight())
    g.setColorAt(0.0, C_TOP)
    g.setColorAt(1.0, C_BOTTOM)
    return g


def paint(size: int) -> QImage:
    """按目标像素尺寸直接绘制（不缩放），每个尺寸都能有正确的线宽与抗锯齿。"""
    s = float(size)
    img = QImage(size, size, QImage.Format_ARGB32_Premultiplied)
    img.fill(Qt.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing, True)
    p.setRenderHint(QPainter.SmoothPixmapTransform, True)

    u = s / BASE                       # 1 设计单位 = u 像素
    tiny = size <= 24                  # 极小尺寸走简化版
    small = size <= 48

    # 1) 底：圆角方块（小尺寸减少圆角，避免边缘被吃掉）
    radius = s * (0.22 if size >= 64 else 0.19)
    _squircle(p, QRectF(0.5, 0.5, s - 1, s - 1), radius)

    # 2) 几何量（设计单位）；tiny 走另一套绝对像素，避免小尺寸糊成一团
    cx = s / 2
    if tiny:
        # 16/20/24px：细链路 + 小节点 + 一道细弧，靠像素级线宽保证可辨
        cy = 0.640 * s
        span = 0.335 * s
        bus_w = max(1.4, 48 * u)
        node_mid = max(2.1, 132 * u)
        node_side = max(1.5, 96 * u)
    else:
        cy = 0.632 * s
        span = 0.362 * s
        bus_w = max(2.0, 62 * u)
        node_mid = max(3.2, 98 * u)
        node_side = max(2.6, 70 * u)

    # 信号弧：以中心节点为圆心向上张开（Qt 0° 在 3 点方向，逆时针为正）
    arc_w = max(1.7 if tiny else 2.0, (70 if small and not tiny else 56) * u)
    # 极小块上青色被抗锯齿稀释得几乎看不见，改用高对比近白色
    pen = QPen(QColor("#D9FFF1") if tiny else QColor("#8CF3CE"), arc_w)
    pen.setCapStyle(Qt.RoundCap)
    p.setPen(pen)
    if tiny:
        radii = [0.355]
    else:
        radii = [0.352, 0.250] if size >= 48 else [0.372]
    for i, rf in enumerate(radii):
        r_arc = rf * s
        rect = QRectF(cx - r_arc, cy - r_arc, r_arc * 2, r_arc * 2)
        color = QColor("#D9FFF1" if tiny else "#8CF3CE")
        color.setAlpha(255 if i == 0 else 165)
        pen.setColor(color)
        p.setPen(pen)
        if tiny:
            p.drawArc(rect, int(54 * 16), int(72 * 16))
        else:
            p.drawArc(rect, int(44 * 16), int(92 * 16))

    # 3) 总线
    pen = QPen(C_NODE, bus_w)
    pen.setCapStyle(Qt.RoundCap)
    p.setPen(pen)
    p.drawLine(QPointF(cx - span, cy), QPointF(cx + span, cy))

    # 4) 三个节点（中间大、两端小）
    p.setPen(Qt.NoPen)
    p.setBrush(C_NODE)
    for x, r in ((cx - span, node_side), (cx + span, node_side), (cx, node_mid)):
        p.drawEllipse(QPointF(x, cy), r, r)

    # 5) 中心节点挖一个底色小孔，让小尺寸也有「环」的层次
    if size >= 32 and not tiny:
        hole = node_mid * 0.36
        ring = QLinearGradient(cx - hole, cy - hole, cx + hole, cy + hole)
        ring.setColorAt(0.0, QColor("#12735C"))
        ring.setColorAt(1.0, QColor("#0A3A36"))
        p.setBrush(ring)
        p.drawEllipse(QPointF(cx, cy), hole, hole)

    p.end()
    return img


# ---------------------------------------------------------------- ICO 打包
def _dib(img: QImage) -> bytes:
    """32bpp BGRA + AND 掩码（BMP 形式，兼容老版本 Windows / 各种壳）。"""
    w, h = img.width(), img.height()
    img = img.convertToFormat(QImage.Format_ARGB32)
    rows = []
    for y in range(h - 1, -1, -1):                 # DIB 是自下而上
        row = bytearray()
        for x in range(w):
            c = img.pixelColor(x, y)
            a = c.alpha()
            row += bytes((c.blue() * a // 255, c.green() * a // 255,
                          c.red() * a // 255, a))  # 预乘，避免边缘发白
        rows.append(bytes(row))
    mask_stride = ((w + 31) // 32) * 4             # AND 掩码按 4 字节对齐
    mask = b"\x00" * (mask_stride * h)
    header = struct.pack("<IiiHHIIiiII", 40, w, h * 2, 1, 32, 0,
                         w * h * 4 + len(mask), 0, 0, 0, 0)
    return header + b"".join(rows) + mask


def _png(img: QImage) -> bytes:
    from PySide6.QtCore import QBuffer, QByteArray
    ba = QByteArray()
    buf = QBuffer(ba)
    buf.open(QBuffer.WriteOnly)
    img.save(buf, "PNG")
    buf.close()
    return bytes(ba.data())


def write_ico(images: dict[int, QImage], path: Path):
    """写 ICO：<=64 用 DIB，128/256 用 PNG（Vista 起支持）。"""
    entries = []
    for size in sorted(images):
        img = images[size]
        data = _png(img) if size >= 128 else _dib(img)
        entries.append((size, data))

    out = bytearray(struct.pack("<HHH", 0, 1, len(entries)))
    offset = 6 + 16 * len(entries)
    for size, data in entries:
        dim = 0 if size == 256 else size
        out += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    for _, data in entries:
        out += data
    path.write_bytes(bytes(out))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="assets")
    ap.add_argument("--preview", action="store_true", help="额外输出一张尺寸对照预览图")
    args = ap.parse_args()

    app = QGuiApplication.instance() or QGuiApplication(sys.argv[:1])
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    images = {size: paint(size) for size in SIZES}
    ico = out / "netdiag.ico"
    write_ico(images, ico)
    images[256].save(str(out / "netdiag_256.png"), "PNG")
    images[64].save(str(out / "netdiag_64.png"), "PNG")

    if args.preview:
        # 尺寸对照：浅色底卡上排 256/64/48/32/24/16
        pad, gap = 36, 28
        row = [(256, images[256]), (64, images[64]), (48, images[48]),
               (32, images[32]), (24, images[24]), (16, images[16])]
        W = pad * 2 + sum(s for s, _ in row) + gap * (len(row) - 1)
        H = pad * 2 + 256
        canvas = QImage(W, H, QImage.Format_ARGB32)
        canvas.fill(QColor("#EEF3F1"))
        p = QPainter(canvas)
        p.setRenderHint(QPainter.SmoothPixmapTransform, True)
        x = pad
        for size, im in row:
            p.drawImage(QRectF(x, (H - size) / 2, size, size), im)
            x += size + gap
        p.end()
        canvas.save(str(out / "icon_preview.png"), "PNG")

    print(f"ico  : {ico}  {ico.stat().st_size / 1024:.1f} KB")
    print(f"png  : {out / 'netdiag_256.png'}")
    print("sizes: " + ", ".join(str(s) for s in sorted(images)))


if __name__ == "__main__":
    main()
