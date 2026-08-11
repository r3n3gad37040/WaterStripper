# WaterStripper

**Reclaim ownership of your own documents and code.**

WaterStripper detects and removes hidden watermark and tracking markers that AI
providers (Anthropic, OpenAI, Google, and others) embed in generated text and
source code. You rented the tool. The output is yours. WaterStripper makes
sure of it.

## Why this exists

When you hammer a nail, the hammer manufacturer does not stamp its logo into
every nail head. When you saw a board, the saw does not record what you cut.
But AI providers have taken it upon themselves to embed invisible identifiers
into the text and code their models produce, quietly claiming a fingerprint on
work that belongs to you.

These markers are:

- **Invisible.** You will never see them in your editor.
- **Persistent.** They survive copy-paste and light editing.
- **Uninvited.** No one asked you whether your documents should carry them.

Anthropic has publicly confirmed (August 2026, under EU AI Act pressure) that
Claude output carries imperceptible watermarks. Third-party analysis has
identified zero-width character fingerprints in GPT-family output. OpenAI,
Google, and others have documented C2PA provenance metadata and statistical
watermarking programs.

WaterStripper puts the control back where it belongs: with you.

## What it detects and strips

| # | Marker class | Codepoints / technique |
|---|---|---|
| 1 | Zero-width characters | U+200B, U+200C, U+200D, U+2060, U+180E |
| 2 | Unicode Tag block | U+E0000–U+E007F (invisible ASCII payload carriers) |
| 3 | Exotic/invisible spaces | U+00A0, U+2000–U+200A, U+202F, U+205F, U+3000 |
| 4 | Bidirectional controls | U+200E, U+200F, U+202A–U+202E, U+2066–U+2069, U+061C |
| 5 | Soft hyphens | U+00AD |
| 6 | Mid-text byte order marks | U+FEFF |
| 7 | Variation selectors | U+FE00–U+FE0F, U+E0100–U+E01EF |
| 8 | Interlinear annotations | U+FFF9–U+FFFB |
| 9 | Homoglyph confusables | Cyrillic/Greek lookalikes of ASCII letters |
| 10 | Line/paragraph separators | U+2028, U+2029 (normalized to newlines) |

Statistical watermarks (token-choice bias such as KGW green-list schemes)
leave no characters to strip; public research shows they are fragile and
rarely deployed at scale. File-level C2PA metadata lives outside the text and
can be removed with `exiftool -all=` on affected media files.

## Installation

Requires Python 3.7+. No dependencies, no packages, no build step. One file.

```bash
git clone https://github.com/r3n3gad37040/WaterStripper.git
cd WaterStripper
chmod +x waterstripper.py
```

Or grab just the script:

```bash
curl -O https://raw.githubusercontent.com/r3n3gad37040/WaterStripper/main/waterstripper.py
chmod +x waterstripper.py
```

Optionally put it on your PATH:

```bash
sudo cp waterstripper.py /usr/local/bin/waterstripper
```

## Usage

### Scan only (change nothing)

```bash
./waterstripper.py --scan myfile.md
```

Produces a forensic report of every hidden marker found, by codepoint and
class:

```
== myfile.md ==
  [zero_width] U+200B ZERO WIDTH SPACE: x14
  [unicode_tag] U+E0068 UNICODE TAG BLOCK (invisible payload char): x3
  [exotic_space] U+00A0 NO-BREAK SPACE: x2
  TOTAL hidden marker characters: 19
```

Exit code 1 means markers were found, so scans wire cleanly into scripts and
CI checks.

### Strip in place (automatic backup)

```bash
./waterstripper.py myfile.md
```

Writes `myfile.md.bak` first, then rewrites the file clean.

### Strip to a new file

```bash
./waterstripper.py -o clean.md myfile.md
```

### Pipe mode

```bash
pbpaste | ./waterstripper.py --stdin | pbcopy
cat generated_code.py | ./waterstripper.py --stdin > owned_code.py
```

### Multiple files at once

```bash
./waterstripper.py --scan docs/*.md src/*.py
./waterstripper.py docs/*.md src/*.py
```

### Working with real Cyrillic or Greek text

By default, Cyrillic/Greek homoglyph lookalikes are converted to ASCII. If
your document is legitimately written in those scripts, preserve them:

```bash
./waterstripper.py --keep-homoglyphs russian_doc.md
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean, or stripping completed successfully |
| 1 | Markers found (scan mode) |
| 2 | Error (bad path, unreadable file, etc.) |

## Pre-commit hook example

Keep AI-generated contributions clean automatically:

```bash
# .git/hooks/pre-commit
#!/bin/sh
FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(md|txt|py|js|ts|json)$')
[ -z "$FILES" ] && exit 0
waterstripper --scan $FILES || {
  echo "Hidden AI watermark markers detected. Run: waterstripper <files>"
  exit 1
}
```

## What stripping does

- **Deletes outright:** zero-width chars, tag block chars, bidi controls,
  variation selectors, soft hyphens, mid-text BOMs, interlinear annotations.
- **Normalizes:** exotic spaces become plain spaces; U+2028/U+2029 become
  newlines; homoglyphs become their ASCII equivalents.

Legitimate documents pass through byte-identical. Unicode you actually want
(accented characters, CJK, math symbols, emoji) is untouched.

## Philosophy

Using a tool does not transfer ownership of your work to the toolmaker. The
developer directs, corrects, designs, and ships; the model is an instrument.
WaterStripper exists so the artifacts you create carry your signature, not
someone else's hidden one.

## Contributing

Found a new marker class in the wild? Open an issue with a sample (hex dump
welcome) or send a PR adding the codepoint range to the detection tables.
Forks welcome.

## License

MIT. Take it, use it, own your work.
