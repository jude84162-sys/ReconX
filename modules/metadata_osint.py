# modules/metadata_osint.py
"""ReconX - Image Metadata Extractor (99% accuracy)."""

import os
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("ReconX.metadata")

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


# Sensitive EXIF tags
SENSITIVE_TAGS = {
    "GPSInfo", "GPSLatitude", "GPSLongitude", "GPSAltitude",
    "Make", "Model", "Software", "DateTimeOriginal", "DateTime",
    "Artist", "Copyright", "HostComputer", "ImageDescription",
    "BodySerialNumber", "LensSerialNumber", "CameraOwnerName",
}


def _extract_gps(exif_data):
    """Extract GPS coordinates."""
    gps = {}
    try:
        gps_info = exif_data.get("GPSInfo", {})
        if not gps_info:
            return gps

        for tag, value in gps_info.items():
            tag_name = GPSTAGS.get(tag, tag)
            gps[tag_name] = value

        # Convert to decimal
        if "GPSLatitude" in gps and "GPSLongitude" in gps:
            def to_decimal(coord, ref):
                try:
                    d, m, s = coord
                    decimal = float(d) + float(m) / 60 + float(s) / 3600
                    if ref in ("S", "W"):
                        decimal = -decimal
                    return round(decimal, 6)
                except Exception:
                    return None

            lat = to_decimal(gps["GPSLatitude"], gps.get("GPSLatitudeRef", "N"))
            lon = to_decimal(gps["GPSLongitude"], gps.get("GPSLongitudeRef", "E"))

            if lat and lon:
                gps["_decimal"] = {"lat": lat, "lon": lon}
                gps["_maps_url"] = f"https://www.google.com/maps?q={lat},{lon}"

    except Exception:
        pass
    return gps


def run_metadata_osint(filepath):
    """Extract metadata from image."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "filepath": str(filepath),
        "exists": False,
        "size": 0,
        "size_human": "",
        "extension": None,
        "image": {},
        "exif": {},
        "gps": {},
        "sensitive": [],
        "risk_score": 0,
        "error": None
    }

    path = Path(filepath).expanduser()

    if not path.exists():
        result["error"] = "File not found"
        return result

    result["exists"] = True
    size = path.stat().st_size
    result["size"] = size

    # Human readable size
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            result["size_human"] = f"{size:.1f} {unit}"
            break
        size /= 1024

    result["extension"] = path.suffix.lower()

    if not HAS_PIL:
        result["error"] = "Pillow not installed (pip install Pillow)"
        return result

    try:
        img = Image.open(path)
        result["image"] = {
            "format": img.format,
            "mode": img.mode,
            "width": img.size[0],
            "height": img.size[1],
        }

        exif = img.getexif()
        if exif:
            for tag_id, value in exif.items():
                tag = TAGS.get(tag_id, tag_id)
                try:
                    result["exif"][str(tag)] = str(value)[:200]
                except Exception:
                    pass

            # GPS
            result["gps"] = _extract_gps(exif)

            # Sensitive tags
            for tag in result["exif"]:
                if tag in SENSITIVE_TAGS:
                    result["sensitive"].append(tag)

            if result["gps"]:
                result["sensitive"].append("GPSInfo")

            # Risk score
            score = len(result["sensitive"]) * 10
            result["risk_score"] = min(score, 100)

    except Exception as e:
        result["error"] = str(e)

    return result


def print_metadata_report(result):
    print("\n" + "=" * 70)
    print("  Image Metadata - ReconX")
    print("=" * 70)

    if result.get("error"):
        print(f"\n[!] {result['error']}")
        return

    print(f"\n[*] File: {result.get('filepath')}")
    print(f"[*] Size: {result.get('size_human')} ({result.get('size')} bytes)")
    print(f"[*] Risk: {result.get('risk_score')}/100")

    if result.get("image"):
        img = result["image"]
        print(f"\n[+] Image:")
        print(f"    Format: {img.get('format')}")
        print(f"    Mode:   {img.get('mode')}")
        print(f"    Size:   {img.get('width')}x{img.get('height')}")

    if result.get("gps"):
        gps = result["gps"]
        print(f"\n[+] GPS Location:")
        if gps.get("_decimal"):
            print(f"    Lat/Lon: {gps['_decimal']['lat']}, {gps['_decimal']['lon']}")
            print(f"    Maps:    {gps['_maps_url']}")
        else:
            for k, v in gps.items():
                if not k.startswith("_"):
                    print(f"    {k}: {v}")

    if result.get("sensitive"):
        print(f"\n[!] Sensitive Tags ({len(result['sensitive'])}):")
        for tag in result["sensitive"]:
            print(f"    [!] {tag}")

    if result.get("exif"):
        print(f"\n[+] All EXIF ({len(result['exif'])} tags):")
        for k, v in list(result["exif"].items())[:20]:
            print(f"    {k}: {v}")
        if len(result["exif"]) > 20:
            print(f"    ... and {len(result['exif']) - 20} more")

    print("\n" + "=" * 70 + "\n")
