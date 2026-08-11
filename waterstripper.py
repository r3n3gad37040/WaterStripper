#!/usr/bin/env python3
"""
WaterStripper v2 — reclaim ownership of your own documents, code, and media.

Detects and strips hidden tracking / provenance markers embedded by AI
providers (Anthropic, OpenAI, Google, etc.) and by EU AI Act Article 50
"transparency" infrastructure in generated text, code, and media files.

TEXT / CODE LAYER (zero-dependency, works on any UTF-8 text):
  1. Zero-width characters        (ZWSP U+200B, ZWNJ U+200C, ZWJ U+200D, WJ U+2060)
  2. Unicode Tag block            (U+E0000–U+E007F — invisible ASCII-smuggling tags)
  3. Invisible / exotic spaces    (U+00A0, U+202F, U+2000–U+200A, U+3000, U+205F...)
  4. Bidi / directional controls  (U+200E, U+200F, U+202A–U+202E, U+2066–U+2069)
  5. Soft hyphens                 (U+00AD)
  6. Byte order marks             (U+FEFF mid-text)
  7. Variation selectors          (U+FE00–U+FE0F, U+E0100–U+E01EF)
  8. Interlinear annotations      (U+FFF9–U+FFFB)
  9. Homoglyph confusables        (Cyrillic/Greek lookalikes of ASCII)
 10. Line/paragraph separators    (U+2028/U+2029 -> normal newlines)

HTML / SVG LAYER:
 11. <meta name="generator"> tags          (AI tool self-branding)
 12. Provenance / C2PA meta tags           (name/property containing c2pa,
                                           provenance, content-credentials,
                                           ai-generated, xmp)
 13. Embedded XMP packets                  (<x:xmpmeta>...</x:xmpmeta>)
 14. EU AI Act icon references             (external EU icon asset URLs)

BINARY / MEDIA LAYER (pure Python, no external tools):
 15. JPEG: C2PA manifests (APP11 JUMBF "c2pa"), XMP APP1 segments,
     Exif Software/Creator provenance fields, COM provenance comments
 16. PNG:  C2PA "caBX" chunk, XMP iTXt ("XML:com.adobe.xmp"),
     text chunks carrying provenance/generator keywords
 17. PDF:  /Metadata XMP streams and C2PA references (detected; stripped
     when rewriting is safe, otherwise reported with guidance)

Regulatory counter-coverage:
  - EU AI Act (Regulation 2024/1689) Article 50 machine-readable marking
  - EU Code of Practice on Transparency of AI-Generated Content (2026):
    digitally-signed C2PA metadata, imperceptible watermarking
  - C2PA / Content Credentials manifests
  - IPTC/XMP DigitalSourceType provenance fields
    (e.g. trainedAlgorithmicMedia / algorithmicMedia)

Fingerprint registries (Code of Practice optional third mechanism) are
server-side hash databases; they carry no marker in your file, so there is
nothing to strip — but stripping the metadata and watermark layers removes
everything that travels with your work.

Usage:
  waterstripper.py FILE...          strip in place (writes .bak backups)
  waterstripper.py -o OUT FILE      strip to a new file
  waterstripper.py --scan FILE...   report markers only, change nothing
  waterstripper.py --stdin          read stdin, write stripped stdout
  waterstripper.py --scan --stdin   analyze stdin

Exit codes: 0 = clean / stripped ok, 1 = markers found (scan mode), 2 = error.
"""

import argparse
import re
import shutil
import struct
import sys
from collections import Counter

# ---------------------------------------------------------------------------
# TEXT LAYER
# ---------------------------------------------------------------------------

ZERO_WIDTH = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
}

EXOTIC_SPACES = {
    0x00A0: "NO-BREAK SPACE",
    0x2000: "EN QUAD", 0x2001: "EM QUAD", 0x2002: "EN SPACE",
    0x2003: "EM SPACE", 0x2004: "THREE-PER-EM SPACE",
    0x2005: "FOUR-PER-EM SPACE", 0x2006: "SIX-PER-EM SPACE",
    0x2007: "FIGURE SPACE", 0x2008: "PUNCTUATION SPACE",
    0x2009: "THIN SPACE", 0x200A: "HAIR SPACE",
    0x202F: "NARROW NO-BREAK SPACE",
    0x205F: "MEDIUM MATHEMATICAL SPACE",
    0x3000: "IDEOGRAPHIC SPACE",
}

BIDI_CONTROLS = {
    0x200E: "LEFT-TO-RIGHT MARK", 0x200F: "RIGHT-TO-LEFT MARK",
    0x202A: "LEFT-TO-RIGHT EMBEDDING", 0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE", 0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE", 0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE", 0x2069: "POP DIRECTIONAL ISOLATE",
    0x061C: "ARABIC LETTER MARK",
}

OTHER_INVISIBLES = {
    0x00AD: "SOFT HYPHEN",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE (BOM)",
    0xFFF9: "INTERLINEAR ANNOTATION ANCHOR",
    0xFFFA: "INTERLINEAR ANNOTATION SEPARATOR",
    0xFFFB: "INTERLINEAR ANNOTATION TERMINATOR",
    0x034F: "COMBINING GRAPHEME JOINER",
    0x115F: "HANGUL CHOSEONG FILLER",
    0x1160: "HANGUL JUNGSEONG FILLER",
    0x17B4: "KHMER VOWEL INHERENT AQ",
    0x17B5: "KHMER VOWEL INHERENT AA",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
}

LINE_SEPS = {0x2028: "LINE SEPARATOR", 0x2029: "PARAGRAPH SEPARATOR"}

TAG_START, TAG_END = 0xE0000, 0xE007F
VS1_START, VS1_END = 0xFE00, 0xFE0F
VS2_START, VS2_END = 0xE0100, 0xE01EF

# Common Cyrillic/Greek homoglyphs abused for confusable watermarks -> ASCII.
HOMOGLYPHS = {
    0x0410: "A", 0x0430: "a",   # Cyrillic A
    0x0412: "B",                 # Cyrillic Ve
    0x0421: "C", 0x0441: "c",   # Cyrillic Es
    0x0415: "E", 0x0435: "e",   # Cyrillic Ie
    0x0395: "E", 0x03B5: "e",   # Greek Epsilon
    0x0397: "H", 0x03B7: "n",   # Greek Eta
    0x0406: "I", 0x0456: "i",   # Cyrillic Byelorussian I
    0x0399: "I", 0x03B9: "i",   # Greek Iota
    0x0408: "J", 0x0458: "j",   # Cyrillic Je
    0x039A: "K", 0x03BA: "k",   # Greek Kappa
    0x041C: "M",                 # Cyrillic Em
    0x039D: "N",                 # Greek Nu
    0x041E: "O", 0x043E: "o",   # Cyrillic O
    0x039F: "O", 0x03BF: "o",   # Greek Omicron
    0x0420: "P", 0x0440: "p",   # Cyrillic Er
    0x03A1: "P", 0x03C1: "p",   # Greek Rho
    0x0405: "S",                 # Cyrillic Dze
    0x0422: "T",                 # Cyrillic Te
    0x03A4: "T",                 # Greek Tau
    0x0425: "X", 0x0445: "x",   # Cyrillic Kha
    0x03A7: "X", 0x03C7: "x",   # Greek Chi
    0x04AE: "Y", 0x0443: "y",   # Cyrillic U
    0x0396: "Z",                 # Greek Zeta
}

CATEGORIES = [
    ("zero_width", ZERO_WIDTH),
    ("exotic_space", EXOTIC_SPACES),
    ("bidi_control", BIDI_CONTROLS),
    ("invisible", OTHER_INVISIBLES),
    ("line_separator", LINE_SEPS),
]

# ---------------------------------------------------------------------------
# HTML / SVG LAYER
# ---------------------------------------------------------------------------

META_GENERATOR_RE = re.compile(
    r'<meta\s+[^>]*name\s*=\s*["\']generator["\'][^>]*>/?\s*',
    re.IGNORECASE)
META_PROVENANCE_RE = re.compile(
    r'<meta\s+[^>]*(?:name|property)\s*=\s*["\'][^"\']*'
    r'(?:c2pa|provenance|content-credentials?|ai[-_ ]?generated|'
    r'iptc|digitalSourceType)[^"\']*["\'][^>]*>/?\s*',
    re.IGNORECASE)
XMP_PACKET_RE = re.compile(
    r'<x:xmpmeta\b.*?</x:xmpmeta\s*>|<\?xpacket\b.*?\?>\s*',
    re.IGNORECASE | re.DOTALL)
EU_ICON_URL_RE = re.compile(
    r'(?:src|href)\s*=\s*["\'][^"\']*digital-strategy\.ec\.europa\.eu[^"\']*'
    r'(?:icon|ai)[^"\']*["\']',
    re.IGNORECASE)

# ---------------------------------------------------------------------------
# BINARY LAYER CONSTANTS
# ---------------------------------------------------------------------------

JPEG_SOI = b"\xff\xd8"
JPEG_APP1 = 0xE1
JPEG_APP11 = 0xEB
JPEG_COM = 0xFE
JPEG_SOS = 0xDA

PNG_C2PA_CHUNK = b"caBX"
PNG_TEXT_CHUNKS = (b"tEXt", b"zTXt", b"iTXt")

PROVENANCE_KEYWORDS = (
    b"c2pa", b"jumbf", b"content credentials", b"contentcredentials",
    b"xml:com.adobe.xmp", b"digitalsourcetype", b"trainedalgorithmicmedia",
    b"algorithmicmedia", b"compositeSynthetic", b"generative",
    b"ai-generated", b"ai generated",
)

XMP_NS_MARKERS = (b"adobe:ns:meta/", b"<x:xmpmeta", b"<?xpacket")


def classify(cp):
    """Return (category, description) for a suspicious codepoint, else None."""
    for name, table in CATEGORIES:
        if cp in table:
            return name, table[cp]
    if TAG_START <= cp <= TAG_END:
        return "unicode_tag", "UNICODE TAG BLOCK (invisible payload char)"
    if VS1_START <= cp <= VS1_END:
        return "variation_selector", f"VARIATION SELECTOR-{cp - 0xFE00 + 1}"
    if VS2_START <= cp <= VS2_END:
        return "variation_selector", f"VARIATION SELECTOR-{cp - 0xE0100 + 17}"
    if cp in HOMOGLYPHS:
        return "homoglyph", f"CONFUSABLE (lookalike of '{HOMOGLYPHS[cp]}')"
    return None


def scan(text):
    """Return Counter of {(cat, cp, desc): count}."""
    hits = Counter()
    for ch in text:
        cp = ord(ch)
        c = classify(cp)
        if c:
            hits[(c[0], cp, c[1])] += 1
    return hits


def scan_html_layer(text):
    """Detect HTML/SVG-level provenance structures. Returns Counter."""
    hits = Counter()
    n = len(META_GENERATOR_RE.findall(text))
    if n:
        hits[("html_meta", None, "<meta name=\"generator\"> AI tool branding")] = n
    n = len(META_PROVENANCE_RE.findall(text))
    if n:
        hits[("html_meta", None, "provenance/C2PA <meta> tag")] = n
    n = len(XMP_PACKET_RE.findall(text))
    if n:
        hits[("xmp_packet", None, "embedded XMP metadata packet")] = n
    n = len(EU_ICON_URL_RE.findall(text))
    if n:
        hits[("eu_icon", None, "EU AI Act icon asset reference")] = n
    return hits


def strip_html_layer(text, stats):
    text, n = META_GENERATOR_RE.subn("", text)
    if n:
        stats["html_meta"] += n
    text, n = META_PROVENANCE_RE.subn("", text)
    if n:
        stats["html_meta"] += n
    text, n = XMP_PACKET_RE.subn("", text)
    if n:
        stats["xmp_packet"] += n
    text, n = EU_ICON_URL_RE.subn('src=""', text)
    if n:
        stats["eu_icon"] += n
    return text


def strip_text(text, keep_homoglyphs=False, html_layer=True):
    """Remove / normalize all marker classes. Returns (clean_text, stats Counter)."""
    stats = Counter()
    if html_layer:
        text = strip_html_layer(text, stats)
    out = []
    for ch in text:
        cp = ord(ch)
        c = classify(cp)
        if not c:
            out.append(ch)
            continue
        cat = c[0]
        stats[cat] += 1
        if cat == "exotic_space":
            out.append(" ")
        elif cat == "line_separator":
            out.append("\n")
        elif cat == "homoglyph":
            if keep_homoglyphs:
                out.append(ch)
            else:
                out.append(HOMOGLYPHS[cp])
        # everything else (zero-width, tags, bidi, variation selectors,
        # soft hyphen, BOM, annotations) is deleted outright.
    return "".join(out), stats


# ---------------------------------------------------------------------------
# BINARY LAYER: JPEG
# ---------------------------------------------------------------------------

def _jpeg_segments(data):
    """Yield (marker, payload, start, end) for every pre-SOS segment."""
    if not data.startswith(JPEG_SOI):
        return
    pos = 2
    end_of_scan = len(data)
    while pos + 4 <= len(data):
        if data[pos] != 0xFF:
            break
        marker = data[pos + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        seg_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        seg_end = pos + 2 + seg_len
        yield marker, data[pos + 4:seg_end], pos, seg_end
        if marker == JPEG_SOS:
            end_of_scan = seg_end
            break
        pos = seg_end
    return end_of_scan


def _jpeg_segment_is_provenance(marker, payload):
    low = payload[:4096].lower()
    if marker == JPEG_APP11 and (b"jumbf" in low or b"c2pa" in low):
        return "C2PA manifest (JPEG APP11 JUMBF)"
    if marker == JPEG_APP1:
        if any(m in payload[:64] for m in XMP_NS_MARKERS) or \
           any(m in low for m in XMP_NS_MARKERS):
            return "XMP metadata (JPEG APP1)"
        if payload.startswith(b"Exif\x00\x00"):
            if any(k in low for k in PROVENANCE_KEYWORDS):
                return "Exif block with provenance fields (JPEG APP1)"
    if marker == JPEG_COM:
        if any(k in low for k in PROVENANCE_KEYWORDS):
            return "JPEG COM provenance comment"
    return None


def process_jpeg(data):
    """Return (new_data, hits Counter)."""
    hits = Counter()
    if not data.startswith(JPEG_SOI):
        return data, hits
    out = bytearray(JPEG_SOI)
    segments = list(_jpeg_segments(data) or [])
    if not segments:
        return data, hits
    scan_end = None
    for item in segments:
        if isinstance(item, int):
            scan_end = item
            continue
        marker, payload, start, end = item
        reason = _jpeg_segment_is_provenance(marker, payload)
        if reason:
            hits[("binary_metadata", None, reason)] += 1
            continue  # drop the segment entirely
        out += data[start:end]
        if marker == JPEG_SOS:
            scan_end = end
    if scan_end is None or scan_end > len(data):
        return data, hits
    out += data[scan_end:]
    return bytes(out), hits


# ---------------------------------------------------------------------------
# BINARY LAYER: PNG
# ---------------------------------------------------------------------------

PNG_SIG = b"\x89PNG\r\n\x1a\n"


def process_png(data):
    """Return (new_data, hits Counter)."""
    hits = Counter()
    if not data.startswith(PNG_SIG):
        return data, hits
    out = bytearray(PNG_SIG)
    pos = len(PNG_SIG)
    while pos + 12 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        ctype = data[pos + 4:pos + 8]
        chunk = data[pos:pos + 12 + length]
        payload = data[pos + 8:pos + 8 + length]
        drop_reason = None
        if ctype == PNG_C2PA_CHUNK:
            drop_reason = "C2PA manifest (PNG caBX chunk)"
        elif ctype in PNG_TEXT_CHUNKS:
            low = payload[:2048].lower()
            if any(k in low for k in PROVENANCE_KEYWORDS):
                drop_reason = f"provenance text chunk (PNG {ctype.decode()})"
        if drop_reason:
            hits[("binary_metadata", None, drop_reason)] += 1
        else:
            out += chunk
        pos += 12 + length
        if ctype == b"IEND":
            break
    out += data[pos:]
    return bytes(out), hits


# ---------------------------------------------------------------------------
# BINARY LAYER: PDF (detection + XMP stream stripping)
# ---------------------------------------------------------------------------

def process_pdf(data):
    """Return (new_data, hits Counter). Strips XMP metadata streams in place."""
    hits = Counter()
    if not data.startswith(b"%PDF"):
        return data, hits
    low = data.lower()
    for kw in PROVENANCE_KEYWORDS:
        n = low.count(kw)
        if n:
            hits[("binary_metadata", None,
                  f"C2PA/provenance reference in PDF ('{kw.decode()}')")] = n
    # Remove XMP metadata streams (they are self-contained stream objects).
    xmp_re = re.compile(
        rb"<<[^>]*?/Subtype\s*/XML[^>]*?>>\s*stream\r?\n.*?\r?\nendstream",
        re.DOTALL)
    new_data, n = xmp_re.subn(b"", data)
    if n:
        hits[("xmp_packet", None, "PDF /Metadata XMP stream (removed)")] = n
        return new_data, hits
    return data, hits


BINARY_PROCESSORS = [
    (JPEG_SOI, process_jpeg, "JPEG"),
    (PNG_SIG, process_png, "PNG"),
    (b"%PDF", process_pdf, "PDF"),
]

TEXT_EXTS = {
    ".txt", ".md", ".markdown", ".py", ".js", ".ts", ".jsx", ".tsx",
    ".json", ".yaml", ".yml", ".toml", ".html", ".htm", ".css",
    ".svg", ".xml", ".csv", ".sh", ".bash", ".c", ".h", ".cpp",
    ".rs", ".go", ".java", ".rb", ".php", ".sql", ".cfg", ".ini",
}


def is_probably_text(path):
    import os
    ext = os.path.splitext(path)[1].lower()
    return ext in TEXT_EXTS


def process_binary(path, data):
    """Dispatch binary handler by magic bytes. Returns (new_data, hits)."""
    for magic, fn, _name in BINARY_PROCESSORS:
        if data.startswith(magic):
            return fn(data)
    return data, Counter()


# ---------------------------------------------------------------------------
# REPORTING / IO
# ---------------------------------------------------------------------------

def format_report(name, hits, stripped_stats=None):
    lines = [f"== {name} =="]
    if not hits and not stripped_stats:
        lines.append("  CLEAN — no hidden markers found.")
        return "\n".join(lines)
    total = 0
    for (cat, cp, desc), n in sorted(hits.items(), key=str):
        total += n
        loc = f"U+{cp:04X} " if cp is not None else ""
        lines.append(f"  [{cat}] {loc}{desc}: x{n}")
    lines.append(f"  TOTAL hidden marker elements: {total}")
    if stripped_stats is not None:
        lines.append("  ACTION: stripped/normalized "
                     + ", ".join(f"{k} x{v}" for k, v in sorted(stripped_stats.items())))
    return "\n".join(lines)


def process_file(path, args):
    import os
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        print(f"ERROR reading {path}: {e}", file=sys.stderr)
        return 2

    is_text = is_probably_text(path) or _looks_like_text(raw)

    if is_text:
        try:
            text = raw.decode("utf-8", errors="surrogateescape")
        except Exception as e:
            print(f"ERROR decoding {path}: {e}", file=sys.stderr)
            return 2
        hits = scan(text) + scan_html_layer(text)
        if args.scan:
            print(format_report(path, hits))
            return 1 if hits else 0
        clean, stats = strip_text(text, keep_homoglyphs=args.keep_homoglyphs)
        print(format_report(path, hits, stripped_stats=stats))
        out_bytes = clean.encode("utf-8", errors="surrogateescape")
    else:
        new_raw, hits = process_binary(path, raw)
        if args.scan:
            print(format_report(path, hits))
            return 1 if hits else 0
        stats = Counter()
        for (_cat, _cp, desc), n in hits.items():
            stats[f"binary: {desc}"] += n
        print(format_report(path, hits, stripped_stats=stats if hits else None))
        out_bytes = new_raw

    if args.output:
        out_path = args.output
    else:
        shutil.copy2(path, path + ".bak")
        out_path = path
    try:
        with open(out_path, "wb") as f:
            f.write(out_bytes)
    except OSError as e:
        print(f"ERROR writing {out_path}: {e}", file=sys.stderr)
        return 2
    return 0


def _looks_like_text(raw):
    """Heuristic: no NUL bytes in the first 8KB means treat as text."""
    return b"\x00" not in raw[:8192] and not any(
        raw.startswith(m) for m, _f, _n in BINARY_PROCESSORS)


def main():
    p = argparse.ArgumentParser(
        prog="waterstripper",
        description="Strip AI-provider and EU AI Act Article 50 "
                    "watermark/tracking markers from text, code, and media.")
    p.add_argument("files", nargs="*", help="Files to process")
    p.add_argument("--scan", action="store_true",
                   help="Report only; do not modify anything")
    p.add_argument("-o", "--output", help="Write stripped output to this file "
                                          "(single input only)")
    p.add_argument("--stdin", action="store_true",
                   help="Read from stdin, write stripped text to stdout")
    p.add_argument("--keep-homoglyphs", action="store_true",
                   help="Leave Cyrillic/Greek lookalikes untouched "
                        "(useful for documents in those scripts)")
    args = p.parse_args()

    if args.stdin:
        text = sys.stdin.read()
        hits = scan(text) + scan_html_layer(text)
        if args.scan:
            print(format_report("<stdin>", hits), file=sys.stderr)
            return 1 if hits else 0
        clean, stats = strip_text(text, keep_homoglyphs=args.keep_homoglyphs)
        sys.stdout.write(clean)
        if hits:
            print(format_report("<stdin>", hits, stats), file=sys.stderr)
        return 0

    if not args.files:
        p.print_help()
        return 2
    if args.output and len(args.files) != 1:
        print("ERROR: -o/--output works with exactly one input file", file=sys.stderr)
        return 2

    rc = 0
    for path in args.files:
        r = process_file(path, args)
        if r == 2:
            return 2
        rc = max(rc, r)
    return rc


if __name__ == "__main__":
    sys.exit(main())
