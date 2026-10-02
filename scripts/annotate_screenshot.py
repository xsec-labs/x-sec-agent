#!/usr/bin/env python3
"""Draw slim red focus rectangles around evidence screenshot regions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from PIL import Image, ImageDraw

from xsec_paths import resolve_artifact_path, resolve_output_path


def parse_box(raw: str) -> dict:
    parts = [p.strip() for p in raw.split(",")]
    if len(parts) not in {4, 5}:
        raise argparse.ArgumentTypeError("box must be x,y,w,h or x,y,w,h,label")
    x, y, w, h = [int(float(v)) for v in parts[:4]]
    return {"x": x, "y": y, "w": w, "h": h}


def load_boxes(args) -> list[dict]:
    boxes: list[dict] = []
    for raw in args.box or []:
        boxes.append(parse_box(raw))
    if args.boxes_json:
        data = json.loads(resolve_artifact_path(args.boxes_json).read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError("boxes_json must contain a list")
        boxes.extend(data)
    if not boxes:
        raise ValueError("provide at least one --box or --boxes-json")
    return boxes


def padded_rect(box: dict, image: Image.Image, padding: int) -> list[int]:
    x = int(box["x"])
    y = int(box["y"])
    w = int(box["w"])
    h = int(box["h"])
    left = max(0, x - padding)
    top = max(0, y - padding)
    right = min(image.width - 1, x + w + padding)
    bottom = min(image.height - 1, y + h + padding)
    return [left, top, right, bottom]


def annotate(input_path: Path, output_path: Path, boxes: list[dict], width: int, padding: int) -> None:
    image = Image.open(input_path).convert("RGB")
    draw = ImageDraw.Draw(image)
    for box in boxes:
        draw.rectangle(padded_rect(box, image, padding), outline=(220, 0, 0), width=width)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(output_path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Draw slim red boxes around screenshot regions.")
    parser.add_argument("--input", required=True, help="Original screenshot path")
    parser.add_argument("--output", required=True, help="Annotated screenshot path")
    parser.add_argument("--box", action="append", help="Focus box: x,y,w,h; an optional fifth label is accepted but not rendered")
    parser.add_argument("--boxes-json", help="JSON list of boxes with x,y,w,h")
    parser.add_argument("--width", type=int, default=2, help="Rectangle stroke width")
    parser.add_argument("--padding", type=int, default=4, help="Pixels to expand each box outward")
    args = parser.parse_args()

    output_path = resolve_output_path(args.output)
    annotate(resolve_artifact_path(args.input), output_path, load_boxes(args), args.width, args.padding)
    print(json.dumps({"ok": True, "output": str(output_path)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
