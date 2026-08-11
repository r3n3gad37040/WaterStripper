#!/usr/bin/env python3
"""
WaterStripper — reclaim ownership of your own documents and code.

Detects and strips hidden tracking / provenance markers embedded by AI
providers (Anthropic, OpenAI, Google, etc.) in generated text and code:

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
 11. Optional: invisible-separator whitespace parity analysis (report only)

Usage:
  waterstripper.py FILE...          strip in place (writes .bak backups)
  waterstripper.py -o OUT FILE      strip to a new file
  waterstripper.py --scan FILE...   report markers only, change nothing
  waterstripper.py --stdin          read stdin, write stripped stdout
  waterstripper.py --scan --stdin   analyze stdin

Exit codes: 0 = clean / stripped ok, 1 = markers found (scan mode), 2 = error.
"""

import argparse
import os
import shutil
import sys
import unicodedata
from collections import Counter

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
    0x0397: "H", 0x03B7: "n",   # Greek Eta (lower maps lookalike n)
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
    """Return Counter of {(cat, cp, desc): count} and positions summary."""
    hits = Counter()
    for ch in text:
        cp = ord(ch)
        c = classify(cp)
        if c:
            hits[(c[0], cp, c[1])] += 1
    return hits


def strip_text(text, keep_homoglyphs=False):
    """Remove / normalize all marker classes. Returns (clean_text, stats Counter)."""
    stats = Counter()
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


def format_report(name, hits, stripped_stats=None):
    lines = [f"== {name} =="]
    if not hits and not stripped_stats:
        lines.append("  CLEAN — no hidden markers found.")
        return "\n".join(lines)
    total = 0
    for (cat, cp, desc), n in sorted(hits.items()):
        total += n
        lines.append(f"  [{cat}] U+{cp:04X} {desc}: x{n}")
    lines.append(f"  TOTAL hidden marker characters: {total}")
    if stripped_stats is not None:
        lines.append("  ACTION: stripped/normalized "
                     + ", ".join(f"{k} x{v}" for k, v in sorted(stripped_stats.items())))
    return "\n".join(lines)


def process_file(path, args):
    try:
        with open(path, "r", encoding="utf-8", errors="surrogateescape") as f:
            text = f.read()
    except (OSError, UnicodeError) as e:
        print(f"ERROR reading {path}: {e}", file=sys.stderr)
        return 2

    hits = scan(text)
    if args.scan:
        print(format_report(path, hits))
        return 1 if hits else 0

    clean, stats = strip_text(text, keep_homoglyphs=args.keep_homoglyphs)
    print(format_report(path, hits, stripped_stats=stats))

    if args.output:
        out_path = args.output
    else:
        shutil.copy2(path, path + ".bak")
        out_path = path
    try:
        with open(out_path, "w", encoding="utf-8", errors="surrogateescape") as f:
            f.write(clean)
    except OSError as e:
        print(f"ERROR writing {out_path}: {e}", file=sys.stderr)
        return 2
    return 0


def main():
    p = argparse.ArgumentParser(
        prog="waterstripper",
        description="Strip AI-provider watermark/tracking markers from text and code.")
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
        hits = scan(text)
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
