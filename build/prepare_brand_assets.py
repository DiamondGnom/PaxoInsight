from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image


def alpha_crop(image: Image.Image, padding: int) -> Image.Image:
    rgba = image.convert("RGBA")
    bounds = rgba.getchannel("A").getbbox()
    if bounds is None:
        raise ValueError("The source image has no visible pixels")
    left, top, right, bottom = bounds
    return rgba.crop(
        (
            max(0, left - padding),
            max(0, top - padding),
            min(rgba.width, right + padding),
            min(rgba.height, bottom + padding),
        )
    )


def prepare_icon(source: Path, output_dir: Path) -> None:
    image = alpha_crop(Image.open(source), padding=20)
    side = max(image.size)
    canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    canvas.alpha_composite(
        image,
        ((side - image.width) // 2, (side - image.height) // 2),
    )
    icon = canvas.resize((512, 512), Image.Resampling.LANCZOS)
    icon.save(output_dir / "paxoinsight-icon.png", optimize=True)
    icon.save(
        output_dir / "paxoinsight.ico",
        format="ICO",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )


def prepare_logo(source: Path, output_dir: Path) -> None:
    image = alpha_crop(Image.open(source), padding=24)
    width = 384
    height = round(image.height * width / image.width)
    logo = image.resize((width, height), Image.Resampling.LANCZOS)
    logo.save(output_dir / "paxoinsight-logo.png", optimize=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("icon", type=Path)
    parser.add_argument("logo", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    prepare_icon(args.icon, args.output_dir)
    prepare_logo(args.logo, args.output_dir)


if __name__ == "__main__":
    main()
