# Shadow-Copy

**Shadow-Copy** is an automated OSINT metadata stripper and privacy sanitizer built with Python. It helps users detect and remove hidden metadata from images before they are uploaded, shared, archived, or published online.

This project is designed as a defensive cybersecurity tool that demonstrates practical privacy engineering, OSINT awareness, Python automation, and secure file handling.

---

## Why Shadow-Copy Matters

Images often contain hidden EXIF metadata that can expose sensitive information such as:

- GPS latitude and longitude
- Camera manufacturer and model
- Device fingerprinting details
- Original capture timestamps
- Editing software
- Host machine or author fields
- Operational patterns useful to threat actors

Threat actors can use this metadata for location tracking, profiling, doxxing, social engineering, and reconnaissance. Shadow-Copy helps reduce that risk by detecting privacy leaks and producing clean metadata-free copies.

---

## Key Features

### Automated Folder Workflow

Shadow-Copy creates and uses two local folders:

```text
unsecured_pool/
sanatized_output/