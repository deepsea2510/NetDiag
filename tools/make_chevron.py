"""生成下拉框箭头图标（浅色 / 深色两版）。

QSS 一旦给 QComboBox 设了边框，Qt 就不再用 Fusion 的默认箭头，
必须自己给 `QComboBox::down-arrow` 提供 image——这里生成 48×48 的透明 PNG，
QSS 里按 12px 显示，高分屏下也不糊。

用法：python tools/make_chevron.py
"""
from __future__ import annotations

import os

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QGuiApplication, QImage, QPainter, QPainterPath, QPen

HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(os.path.dirname(HERE), "assets")
SIZE = 48

COLORS = {
    "chevron_down_light.png": "#6f8179",
    "chevron_down_dark.png": "#9fb3aa",
}


def draw(color: str) -> QImage:
    img = QImage(SIZE, SIZE, QImage.Format_ARGB32)
    img.fill(Qt.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing, True)
    pen = QPen(QColor(color), 5.0)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)
    # 一个「v」形：左 12,19 → 中 24,31 → 右 36,19
    path = QPainterPath(QPointF(12, 19))
    path.lineTo(QPointF(24, 31))
    path.lineTo(QPointF(36, 19))
    p.drawPath(path)
    p.end()
    return img


def main() -> int:
    app = QGuiApplication.instance() or QGuiApplication([])   # noqa: F841  QPainter 需要
    os.makedirs(ASSETS, exist_ok=True)
    for name, color in COLORS.items():
        path = os.path.join(ASSETS, name)
        ok = draw(color).save(path)
        print(("ok  " if ok else "fail") + f" {path} ({color})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
