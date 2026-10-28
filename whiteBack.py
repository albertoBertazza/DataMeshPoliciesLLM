from pathlib import Path
from PIL import Image
import tempfile
import os

# TODO: Replace this with the folder containing your images.
# All images in this folder and its subfolders will be searched.
ROOT_FOLDER = Path(r"C:\Users\berta\Downloads\OPARulesGeneratedByLLMWithTrino")

IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".webp", ".tif", ".tiff", ".bmp"
}

def has_transparency(image: Image.Image) -> bool:
    """Return True if the image has an alpha channel or transparent palette entries."""
    if image.mode in ("RGBA", "LA"):
        return image.getchannel("A").getextrema()[0] < 255
    if image.mode == "P" and "transparency" in image.info:
        return True
    return False

def composite_on_white(image: Image.Image) -> Image.Image:
    """Place the image over an opaque white background."""
    rgba = image.convert("RGBA")
    white = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
    return Image.alpha_composite(white, rgba).convert("RGB")

def main() -> None:
    if not ROOT_FOLDER.is_dir():
        print(f"ERROR: Folder does not exist: {ROOT_FOLDER}")
        print("Edit ROOT_FOLDER near the top of this script.")
        return

    processed = 0
    skipped = 0
    errors = 0

    for path in ROOT_FOLDER.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in IMAGE_EXTENSIONS:
            continue

        try:
            with Image.open(path) as image:
                if not has_transparency(image):
                    skipped += 1
                    continue
                result = composite_on_white(image)

            # Keep the original untouched; save a new PNG alongside it.
            output_path = path.with_name(f"{path.stem}.png")
            result.save(output_path, format="PNG")
            processed += 1
            print(f"Created: {output_path}")

        except Exception as exc:
            errors += 1
            print(f"ERROR processing {path}: {exc}")

    print("\nFinished.")
    print(f"Images converted: {processed}")
    print(f"Skipped (no transparency): {skipped}")
    print(f"Errors: {errors}")

if __name__ == "__main__":
    main()
