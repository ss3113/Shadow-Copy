#!/usr/bin/env python3

"""
Shadow-Copy: Automated OSINT Metadata Stripper & Privacy Sanitizer.

This tool scans images inside /unsecured_pool/, extracts risky EXIF metadata,
reports privacy leaks such as GPS coordinates, and writes clean sanitized copies
to /sanatized_output/ while preserving the original files.
"""

from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import sys
import time


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"

BG_RED = "\033[41m"
BG_GREEN = "\033[42m"

# PROJECT CONFIGURATION

INPUT_DIR = Path("unsecured_pool")
OUTPUT_DIR = Path("sanatized_output")

SUPPORTED_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".bmp",
    ".tiff",
    ".tif",
}

# CLI DESIGN HELPERS


def clear_screen() -> None:
    """Clear the terminal screen for a cleaner tactical dashboard effect."""
    print("\033c", end="")


def slow_print(text: str, delay: float = 0.002) -> None:
    """Print text with a subtle animated effect for a cyber-tool feel."""
    for character in text:
        print(character, end="", flush=True)
        time.sleep(delay)
    print()


def print_banner() -> None:
    """Display the Shadow-Copy cyberpunk-style CLI banner."""
    clear_screen()

    banner = f"""
{CYAN}{BOLD}
   ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗      ██████╗ ██████╗ ██████╗ ██╗   ██╗
   ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║     ██╔════╝██╔═══██╗██╔══██╗╚██╗ ██╔╝
   ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║     ██║     ██║   ██║██████╔╝ ╚████╔╝
   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║     ██║     ██║   ██║██╔═══╝   ╚██╔╝
   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝     ╚██████╗╚██████╔╝██║        ██║
   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝       ╚═════╝ ╚═════╝ ╚═╝        ╚═╝
{RESET}
{MAGENTA}{BOLD}        Automated OSINT Metadata Stripper & Privacy Sanitizer{RESET}
{DIM}        Defensive security utility for removing image-based tracking intelligence.{RESET}
"""
    print(banner)


def print_section(title: str, color: str = CYAN) -> None:
    """Print a formatted dashboard section title."""
    print(f"\n{color}{BOLD}[ {title} ]{RESET}")
    print(f"{color}{'-' * (len(title) + 4)}{RESET}")


def print_status(label: str, value: str, color: str = WHITE) -> None:
    """Print a clean label/value status row."""
    print(f"{DIM}{label:<24}{RESET} {color}{value}{RESET}")


def print_threat(message: str) -> None:
    """Print a high-visibility threat finding."""
    print(f"{RED}{BOLD}[THREAT FOUND]{RESET} {YELLOW}{message}{RESET}")


def print_success(message: str) -> None:
    """Print a green success message."""
    print(f"{GREEN}{BOLD}[CLEAN]{RESET} {message}")


def print_warning(message: str) -> None:
    """Print a yellow warning message."""
    print(f"{YELLOW}{BOLD}[WARN]{RESET} {message}")


def print_error(message: str) -> None:
    """Print a red error message."""
    print(f"{RED}{BOLD}[ERROR]{RESET} {message}")


# FILESYSTEM AUTOMATION

def ensure_project_folders() -> None:
    """Create required input and output folders if they do not already exist."""
    INPUT_DIR.mkdir(exist_ok=True)
    OUTPUT_DIR.mkdir(exist_ok=True)


def discover_images() -> list[Path]:
    """Find supported image files inside the unsecured input pool."""
    image_files = []

    for file_path in INPUT_DIR.iterdir():
        if file_path.is_file() and file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
            image_files.append(file_path)

    return sorted(image_files)

# EXIF EXTRACTION HELPERS

def decode_exif(image: Image.Image) -> Dict[str, Any]:
    """
    Extract and decode EXIF metadata from an image.

    Pillow stores EXIF data using numeric tag IDs. This function converts those
    numeric IDs into human-readable tag names such as DateTimeOriginal or Model.
    """
    metadata: Dict[str, Any] = {}

    raw_exif = image.getexif()

    if not raw_exif:
        return metadata

    for tag_id, value in raw_exif.items():
        tag_name = TAGS.get(tag_id, tag_id)

        if tag_name == "GPSInfo":
            gps_data = {}

            for gps_tag_id, gps_value in value.items():
                gps_tag_name = GPSTAGS.get(gps_tag_id, gps_tag_id)
                gps_data[gps_tag_name] = gps_value

            metadata["GPSInfo"] = gps_data
        else:
            metadata[str(tag_name)] = value

    return metadata


def rational_to_float(value: Any) -> float:
    """
    Convert EXIF rational number values into normal floating-point numbers.

    GPS coordinates in EXIF are often stored as fractions, not plain decimals.
    """
    try:
        return float(value)
    except TypeError:
        return value.numerator / value.denominator


def dms_to_decimal(dms: Any, reference: str) -> float:
    """
    Convert GPS degrees/minutes/seconds format into decimal degrees.

    EXIF GPS coordinates usually store latitude and longitude as:
    degrees, minutes, seconds.
    """
    degrees = rational_to_float(dms[0])
    minutes = rational_to_float(dms[1])
    seconds = rational_to_float(dms[2])

    decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)

    if reference in ["S", "W"]:
        decimal *= -1

    return decimal


def extract_gps_coordinates(metadata: Dict[str, Any]) -> Optional[Tuple[float, float]]:
    """Extract decimal GPS latitude and longitude from decoded EXIF metadata."""
    gps_info = metadata.get("GPSInfo")

    if not gps_info:
        return None

    latitude = gps_info.get("GPSLatitude")
    latitude_ref = gps_info.get("GPSLatitudeRef")
    longitude = gps_info.get("GPSLongitude")
    longitude_ref = gps_info.get("GPSLongitudeRef")

    if not latitude or not latitude_ref or not longitude or not longitude_ref:
        return None

    lat_decimal = dms_to_decimal(latitude, latitude_ref)
    lon_decimal = dms_to_decimal(longitude, longitude_ref)

    return lat_decimal, lon_decimal


def build_google_maps_url(latitude: float, longitude: float) -> str:
    """Create a clickable Google Maps URL from decimal GPS coordinates."""
    return f"https://www.google.com/maps?q={latitude},{longitude}"

# OSINT SCAN MODE


def extract_interesting_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pull recruiter-friendly and security-relevant metadata fields from EXIF.

    These fields can reveal device identity, software stack, creation time,
    and sometimes operational patterns.
    """
    interesting_keys = [
        "Make",
        "Model",
        "DateTime",
        "DateTimeOriginal",
        "DateTimeDigitized",
        "Software",
        "LensModel",
        "Artist",
        "Copyright",
        "HostComputer",
        "ImageDescription",
    ]

    findings = {}

    for key in interesting_keys:
        if key in metadata:
            findings[key] = metadata[key]

    return findings


def scan_image_for_osint(file_path: Path) -> Dict[str, Any]:
    """
    Open an image and scan for privacy-sensitive OSINT metadata.

    Returns a dictionary containing decoded metadata, GPS coordinates,
    Google Maps link, and interesting device/timestamp findings.
    """
    with Image.open(file_path) as image:
        metadata = decode_exif(image)

    gps_coordinates = extract_gps_coordinates(metadata)
    maps_url = None

    if gps_coordinates:
        maps_url = build_google_maps_url(gps_coordinates[0], gps_coordinates[1])

    interesting_metadata = extract_interesting_metadata(metadata)

    return {
        "metadata": metadata,
        "gps_coordinates": gps_coordinates,
        "maps_url": maps_url,
        "interesting_metadata": interesting_metadata,
    }


def format_metadata_value(value: Any) -> str:
    """
    Convert raw metadata values into readable terminal text.

    EXIF values can be strings, numbers, tuples, bytes, or Pillow rational
    objects. This helper makes every value safe and clean to print.
    """
    if isinstance(value, bytes):
        preview = value[:32].hex(" ")
        suffix = " ..." if len(value) > 32 else ""
        return f"<{len(value)} bytes: {preview}{suffix}>"

    if isinstance(value, dict):
        return "{nested metadata block}"

    if isinstance(value, (list, tuple)):
        return ", ".join(format_metadata_value(item) for item in value)

    return str(value)


def display_all_metadata(metadata: Dict[str, Any]) -> None:
    """
    Print every metadata tag discovered during Scan/OSINT Mode.

    This is the detailed evidence view: it shows all EXIF fields, not only the
    high-risk fields like GPS, device model, and timestamps.
    """
    print(f"\n{CYAN}{BOLD}Full Metadata Dump{RESET}")

    if not metadata:
        print_success("No metadata fields available to display.")
        return

    for tag_name in sorted(metadata):
        value = metadata[tag_name]

        if isinstance(value, dict):
            print_status(tag_name, "{", CYAN)

            for nested_key in sorted(value):
                nested_value = format_metadata_value(value[nested_key])
                print_status(f"  {nested_key}", nested_value, YELLOW)

            print_status("", "}", CYAN)
            continue

        print_status(tag_name, format_metadata_value(value), YELLOW)


def display_scan_report(file_path: Path, report: Dict[str, Any]) -> None:
    """Print the OSINT scan results for a single image."""
    print_section(f"SCAN MODE: {file_path.name}", BLUE)

    metadata = report["metadata"]
    gps_coordinates = report["gps_coordinates"]
    maps_url = report["maps_url"]
    interesting_metadata = report["interesting_metadata"]

    print_status("File", file_path.name, CYAN)
    print_status("Metadata Tags Found", str(len(metadata)), YELLOW if metadata else GREEN)

    if gps_coordinates:
        latitude, longitude = gps_coordinates

        print_threat("GPS location metadata detected.")
        print_status("Latitude", str(latitude), RED)
        print_status("Longitude", str(longitude), RED)
        print_status("Google Maps URL", maps_url, YELLOW)
    else:
        print_success("No GPS coordinate leak detected.")

    if interesting_metadata:
        print(f"\n{YELLOW}{BOLD}Device / Timeline Intelligence{RESET}")

        for key, value in interesting_metadata.items():
            print_status(key, str(value), YELLOW)
    else:
        print_success("No obvious device or timestamp metadata found.")

    display_all_metadata(metadata)

    if metadata:
        print_warning("Metadata exists and should be sanitized before public sharing.")
    else:
        print_success("Image appears metadata-clean before sanitization.")


# SANITIZE MODE


def sanitize_image(input_path: Path, output_path: Path) -> None:
    """
    Save a clean copy of an image without EXIF metadata.

    The function creates a fresh pixel-only image object, copies the visual data,
    and saves it without passing EXIF fields to the output file.
    """
    with Image.open(input_path) as image:
        image_format = image.format

        if image.mode in ("RGBA", "LA"):
            clean_image = Image.new(image.mode, image.size)
        else:
            clean_image = Image.new(image.mode, image.size)

        if hasattr(image, "get_flattened_data"):
            clean_image.putdata(list(image.get_flattened_data()))
        else:
            clean_image.putdata(list(image.getdata()))

        save_format = image_format if image_format else "PNG"

        if save_format.upper() in ["JPEG", "JPG"] and clean_image.mode in ("RGBA", "LA", "P"):
            clean_image = clean_image.convert("RGB")

        clean_image.save(output_path, format=save_format)


def build_output_path(input_path: Path) -> Path:
    """Create the sanitized output filename for a given input image."""
    safe_name = f"{input_path.stem}_sanitized{input_path.suffix}"
    return OUTPUT_DIR / safe_name


def verify_metadata_removed(output_path: Path) -> bool:
    """Verify that the sanitized output image no longer contains EXIF metadata."""
    with Image.open(output_path) as image:
        metadata = decode_exif(image)

    return len(metadata) == 0


def run_sanitize_mode(input_path: Path) -> bool:
    """Sanitize one image and print the result."""
    output_path = build_output_path(input_path)

    print_section(f"SANITIZE MODE: {input_path.name}", MAGENTA)

    try:
        sanitize_image(input_path, output_path)
        is_clean = verify_metadata_removed(output_path)

        if is_clean:
            print_success(f"Metadata wiped successfully: {output_path}")
            print_status("Sanitization Status", "PRIVACY-COMPLIANT", GREEN)
            return True

        print_warning(f"Sanitized file created, but metadata verification found remaining tags: {output_path}")
        print_status("Sanitization Status", "REVIEW REQUIRED", YELLOW)
        return False

    except Exception as error:
        print_error(f"Failed to sanitize {input_path.name}: {error}")
        return False


# MAIN ORCHESTRATION

def process_all_images() -> None:
    """Run the full Shadow-Copy workflow across every image in the input folder."""
    ensure_project_folders()

    print_banner()

    print_section("SYSTEM INITIALIZATION", CYAN)
    print_status("Input Pool", str(INPUT_DIR.resolve()), CYAN)
    print_status("Sanitized Output", str(OUTPUT_DIR.resolve()), CYAN)
    print_status("Supported Formats", ", ".join(sorted(SUPPORTED_EXTENSIONS)), CYAN)

    images = discover_images()

    if not images:
        print_warning(f"No supported images found in {INPUT_DIR}/")
        print(f"\n{WHITE}Drop images into {CYAN}{INPUT_DIR}/{WHITE} and run the tool again.{RESET}")
        return

    print_section("BULK PROCESSING QUEUE", CYAN)
    print_status("Images Detected", str(len(images)), GREEN)

    total_processed = 0
    total_cleaned = 0
    total_gps_threats = 0

    for image_path in images:
        total_processed += 1

        try:
            report = scan_image_for_osint(image_path)

            if report["gps_coordinates"]:
                total_gps_threats += 1

            display_scan_report(image_path, report)

            if run_sanitize_mode(image_path):
                total_cleaned += 1

        except Exception as error:
            print_error(f"Could not process {image_path.name}: {error}")

    print_section("MISSION SUMMARY", GREEN)
    print_status("Files Processed", str(total_processed), WHITE)
    print_status("Files Sanitized", str(total_cleaned), GREEN)
    print_status("GPS Threats Found", str(total_gps_threats), RED if total_gps_threats else GREEN)
    print_status("Originals Preserved", "YES", GREEN)

    if total_cleaned == total_processed:
        print(f"\n{BG_GREEN}{BOLD} OPERATION COMPLETE: ALL POSSIBLE FILES SANITIZED {RESET}")
    else:
        print(f"\n{BG_RED}{BOLD} OPERATION COMPLETE WITH WARNINGS: REVIEW FAILED FILES {RESET}")


def main() -> None:
    """Entry point for the Shadow-Copy command-line program."""
    try:
        process_all_images()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}{BOLD}[INTERRUPTED]{RESET} User aborted Shadow-Copy session.")
        sys.exit(130)


if __name__ == "__main__":
    main()
