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
Claude output carries imperceptible watermarks. For Opus-class models (August
2026 onward) this is a **statistical token watermark**: the model's token
choices are biased by a secret, keyed hash of short context windows
(Kirchenbauer green-list / SynthID-tournament family). There are no hidden
characters to find — the mark lives in which words were chosen.

WaterStripper v3 answers that layer directly. See "Statistical watermarks"
below for the mechanism and the provable defeat.

WaterStripper puts the control back where it belongs: with you.

## What it detects and strips

### Text and code layer

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

### HTML / SVG layer

| # | Marker class | Form |
|---|---|---|
| 11 | Generator meta tags | `<meta name="generator" content="Claude…">` |
| 12 | Provenance meta tags | `<meta>` with c2pa / provenance / content-credentials / ai-generated / digitalSourceType names |
| 13 | Embedded XMP packets | `<x:xmpmeta>…</x:xmpmeta>` blocks |
| 14 | EU AI Act icon references | External `digital-strategy.ec.europa.eu` icon asset URLs |

### Binary / media layer (pure Python, no external tools)

| # | Format | What is removed |
|---|---|---|
| 15 | JPEG | C2PA manifests (APP11 JUMBF), XMP APP1 segments, Exif provenance fields, COM comments with provenance keywords |
| 16 | PNG | C2PA `caBX` chunk, XMP `iTXt` (`XML:com.adobe.xmp`), text chunks carrying provenance/generator keywords |
| 17 | PDF | `/Metadata` XMP streams; C2PA references detected and reported |

Legitimate structure survives: JFIF headers, quantization tables, image
data, and ordinary text chunks pass through untouched.

## Regulatory counter-coverage (v2)

Version 2 was hardened specifically against the European Union's AI content
marking regime:

- **EU AI Act (Regulation (EU) 2024/1689), Article 50** — the
  "machine-readable marking" mandate for generative AI output, binding since
  2 August 2026. WaterStripper removes the two technical mechanisms the Act's
  implementation relies on: imperceptible text watermarking (the zero-width /
  tag / exotic-space layer) and signed provenance metadata.
- **EU Code of Practice on Transparency of AI-Generated Content (June
  2026)** — the Commission-endorsed playbook for Article 50 compliance. Its
  three mechanisms are addressed as follows:
  1. *Digitally signed metadata (C2PA / Content Credentials)* — stripped from
     JPEG, PNG, and PDF at the binary level; removed from HTML/SVG as meta
     tags and XMP packets.
  2. *Imperceptible watermarking* — stripped at the character layer for
     text/code.
  3. *Fingerprinting + registry* — a server-side hash database with no marker
     in your file; there is nothing to strip, and removing layers 1 and 2
     removes everything that travels with your work.
- **C2PA Content Credentials** — manifests detected by magic bytes
  (JPEG APP11 JUMBF, PNG `caBX`) and removed whole.
- **IPTC / XMP `DigitalSourceType` provenance fields** — e.g.
  `trainedAlgorithmicMedia`, `algorithmicMedia`, `compositeSynthetic` —
  removed from Exif/XMP blocks and PDF metadata streams.
- **EU labelling icons** — the Commission's standardized AI-content icons are
  a visible-label scheme; any external references to those assets embedded in
  your HTML/SVG are detected and detached.

Whether Article 50 applies to you is between you and your lawyer. What it may
not do is ride into your files uninvited.

## What WaterStripper does NOT do

Honesty matters more than marketing. WaterStripper removes everything that
travels inside your files. It cannot touch what never was in your files.

- **Fingerprint registries.** The Code of Practice's optional third mechanism
  lets a provider hash your generated content and log that hash in a
  server-side database. Later, anyone can submit your content and ask "did
  this come from your model?" The answer comes from comparing against their
  registry — there is no marker embedded in your file, so there is nothing
  local to strip. If a provider runs such a registry and you used their
  hosted model, that record exists on their infrastructure and no client-side
  tool can erase it. The defense here is architectural: run local models, or
  edit output enough that perceptual hashes no longer match. Stripping the
  metadata and watermark layers (which WaterStripper does completely) removes
  everything that physically travels with your work.
- **Statistical token-choice watermarks** (KGW green-list schemes,
  SynthID-text style sampling bias — the Opus-class scheme, deployed by
  Anthropic from August 2026). These are baked into the probability
  distribution at generation time. There are no characters to remove; the
  "marker" is the word choice itself. v3 ships three countermeasures —
  see "Statistical watermarks (v3)" below.
- **Content already published.** If a marked file was uploaded somewhere
  before stripping, the copy on that server still carries whatever it
  carried. WaterStripper cleans your files; it cannot reach back in time or
  across the network.
- **Legal advice.** Whether any marking regime lawfully applies to your
  situation is a jurisdiction question for a lawyer, not a software question.

## Statistical watermarks (v3)

Opus-class models watermark by biasing token selection at generation time.
Both published scheme families condition the bias on a keyed hash of a short
n-gram context window (k ≈ 4–6 tokens):

- **Kirchenbauer green-list** — the context hash splits the vocabulary into
  green/red; green tokens get a logit boost. Detection is a z-test on the
  green-token rate.
- **SynthID-Text** — a keyed tournament over candidate continuations, scored
  by pseudorandom g-values derived from context hashes.

The shared weakness: the watermark is encoded in n-gram contexts. Replace
fraction p of tokens and you invalidate 1 − (1−p)^k of every window. With
k = 5:

| token churn p | contexts invalidated |
|---|---|
| 20% | 67% |
| 30% | 83% |
| 40% | 92% |
| 50% | 97% |

The residual detection z-score scales with the retained fraction (1 − p),
so at ≥50% churn the mark collapses below any reliable threshold — no key
needed, and no detector can restore windows whose tokens no longer exist.
This is why Anthropic's own Article 50 disclosure concedes that "heavily
paraphrased" text loses the mark. WaterStripper v3 operationalizes it:

- `--launder` — built-in, offline, zero-dependency paraphrase engine
  (seeded synonym ring, phrase substitutions, contraction toggles, number
  style flips). Prints measured churn and the computed context-invalidation
  percentage: an arithmetic proof of kill for every document. Use
  `--launder-rate 0.85` and `--seed N` for reproducible output. Best on
  general prose (25–35% churn); on dense technical text with many protected
  identifiers it tops out lower, so pair it with `--rewrite` when you can.
- `--rewrite CMD` — pipe through any external model or script
  (stdin→stdout) for full regeneration when you have one available. This is
  the definitive kill for technical prose: a decent local model rewrites
  60%+ of tokens while keeping code identifiers intact.
- `--oracle CMD` — wrap any detector (Anthropic's forthcoming Article 50
  detector, GPTZero, Pangram, your own) as a stdin/exit-code oracle;
  WaterStripper launders at escalating churn until the oracle reports
  clean. Empirical verification on top of the arithmetic proof.
- `--analyze-statistical` — honest heuristic scan (type-token ratio,
  trigram repetition, sentence-length burstiness) that flags machine-like
  text. It never claims key-level proof; it tells you when laundering is
  worth running.

What WaterStripper DOES guarantee: after a strip pass, your file carries zero
hidden Unicode markers, zero generator/provenance meta tags, zero XMP
packets, zero C2PA manifests, and zero EU icon references — and the scan
mode proves it byte by byte.

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
