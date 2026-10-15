"""Rebuild the maintained Windows icon from the small canonical SVG subset.

Only rect and polygon geometry is accepted. No network, fonts or graphics runtime.
The SVG stays the editing source; ICO is a required native resource, not a cache.
"""
from __future__ import annotations

import argparse
import math
from pathlib import Path
import struct
import xml.etree.ElementTree as xml
import zlib


def rgba(value: str) -> tuple[int, int, int, int]:
    if len(value) != 7 or not value.startswith("#"):
        raise ValueError("icon_color_invalid: " + value)
    return tuple(int(value[index:index + 2], 16) for index in (1, 3, 5)) + (255,)


def geometry(source: Path) -> list[tuple]:
    tree = xml.fromstring(source.read_text(encoding="utf-8-sig"))
    if tree.get("viewBox") != "0 0 128 128":
        raise ValueError("icon_viewbox_invalid")
    shapes = []
    for child in tree:
        name = child.tag.split("}")[-1]
        if name == "rect":
            values = tuple(float(child.get(key, "0")) for key in ("x", "y", "width", "height", "rx"))
            shapes.append((name, values, rgba(child.attrib["fill"])))
        elif name == "polygon":
            points = [tuple(map(float, item.split(","))) for item in child.attrib["points"].split()]
            if len(points) < 3 or any(len(point) != 2 for point in points):
                raise ValueError("icon_polygon_invalid")
            shapes.append((name, points, rgba(child.attrib["fill"])))
        else:
            raise ValueError("icon_element_unsupported: " + name)
    return shapes


def contains(shape: tuple, x: float, y: float) -> bool:
    name, values, _ = shape
    if name == "rect":
        left, top, width, height, radius = values
        if not (left <= x < left + width and top <= y < top + height):
            return False
        radius = min(radius, width / 2, height / 2)
        cx = max(left + radius, min(x, left + width - radius))
        cy = max(top + radius, min(y, top + height - radius))
        return (x - cx) ** 2 + (y - cy) ** 2 <= radius ** 2
    inside = False
    previous = values[-1]
    for current in values:
        ax, ay = current
        bx, by = previous
        if (ay > y) != (by > y) and x < (bx - ax) * (y - ay) / (by - ay) + ax:
            inside = not inside
        previous = current
    return inside


def png(shapes: list[tuple], size: int) -> bytes:
    rows = bytearray()
    samples = 4
    for row in range(size):
        rows.append(0)
        for column in range(size):
            accum = [0, 0, 0, 0]
            for sy in range(samples):
                for sx in range(samples):
                    x = (column + (sx + 0.5) / samples) * 128 / size
                    y = (row + (sy + 0.5) / samples) * 128 / size
                    color = (0, 0, 0, 0)
                    for shape in shapes:
                        if contains(shape, x, y):
                            color = shape[2]
                    for channel in range(4):
                        accum[channel] += color[channel]
            rows.extend(round(value / samples ** 2) for value in accum)
    def chunk(name: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + name + data + struct.pack(">I", zlib.crc32(name + data))
    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b"")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output or root / "assets/app_icon.ico"
    shapes = geometry(root / "assets/logo.svg")
    sizes = (16, 32, 48, 256)
    images = [png(shapes, size) for size in sizes]
    offset = 6 + 16 * len(sizes)
    data = bytearray(struct.pack("<HHH", 0, 1, len(sizes)))
    for size, image in zip(sizes, images, strict=True):
        data.extend(struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(image), offset))
        offset += len(image)
    for image in images:
        data.extend(image)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    print(f"icon_generated: {output} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
