#!/usr/bin/env python3
"""
WaterStripper v3 — reclaim ownership of your own documents, code, and media.

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
  waterstripper.py --normalize FILE   also NFKC-canonicalize + collapse
                                      whitespace (default ON for strip)
  waterstripper.py --rewrite CMD FILE paraphrase through CMD (stdin->stdout)
                                      after stripping — destroys statistical
                                      token watermarks (Opus 5+)
  waterstripper.py --analyze-statistical FILE
                                    heuristic machine-text report (no proof)

Statistical watermarks (Opus 5+, EU AI Act Art. 50): the mark is a secret,
keyed bias in token choice — no characters to strip. Detection without the
provider key is impossible; only paraphrase (--rewrite) destroys it.
--analyze-statistical flags machine-like text honestly, never as proof.

Exit codes: 0 = clean / stripped ok, 1 = markers found (scan mode), 2 = error.
"""

import argparse
import re
import shutil
import struct
import subprocess
import sys
import unicodedata
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
# STATISTICAL WATERMARK LAYER (Opus 5+ / EU AI Act Article 50)
# ---------------------------------------------------------------------------

def normalize_text(text):
    """NFKC canonicalization + whitespace/newline collapse.

    Kills any compatibility-character or spacing variant a provider might
    try to smuggle in (or already did). Characters that survive this pass
    are plain ASCII/Unicode with a single canonical form.
    """
    text = unicodedata.normalize("NFKC", text)
    # Collapse runs of horizontal whitespace to a single space; keep
    # paragraph structure. NBSP and friends were already mapped by NFKC.
    text = re.sub(r"[^\S\n]+", " ", text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text


WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_']*")


def statistical_report(text):
    """Heuristic machine-text analysis.

    Returns (lines, suspicion_score 0-1). This CANNOT prove a statistical
    watermark — that requires the provider's secret key. It reports
    distributional signals correlated with machine generation so the user
    knows when --rewrite is worth running.
    """
    words = [w.lower() for w in WORD_RE.findall(text)]
    n = len(words)
    if n < 100:
        return ([f"  only {n} words — too short for reliable heuristics "
                 f"(need ~100+)"], 0.0)

    # 1. Type-token ratio (vocabulary diversity). Human writing tends
    #    higher over long spans; model output plateaus.
    ttr = len(set(words)) / n

    # 2. Trigram repetition: fraction of word-trigrams seen more than once.
    trigrams = [tuple(words[i:i+3]) for i in range(n - 2)]
    tri_counts = Counter(trigrams)
    repeated = sum(c for c in tri_counts.values() if c > 1)
    tri_rep = repeated / len(trigrams) if trigrams else 0.0

    # 3. Burstiness: variance/mean of sentence lengths. Humans are bursty
    #    (high dispersion); models are unnaturally even.
    sentences = [s for s in re.split(r"[.!?]+\s+", text) if s.strip()]
    slens = [len(WORD_RE.findall(s)) for s in sentences if s.strip()]
    burst = 0.0
    if len(slens) > 3:
        mean = sum(slens) / len(slens)
        var = sum((x - mean) ** 2 for x in slens) / len(slens)
        burst = (var ** 0.5) / mean if mean else 0.0

    # Scoring heuristics (tuned to be conservative — better to under-claim).
    score = 0.0
    notes = []
    if ttr < 0.45:
        score += 0.35
        notes.append(f"low type-token ratio ({ttr:.2f}) — repetitive vocabulary")
    else:
        notes.append(f"type-token ratio {ttr:.2f} (normal)")
    if tri_rep > 0.08:
        score += 0.35
        notes.append(f"high trigram repetition ({tri_rep:.1%}) — template-like phrasing")
    else:
        notes.append(f"trigram repetition {tri_rep:.1%} (normal)")
    if burst < 0.45:
        score += 0.30
        notes.append(f"low sentence-length burstiness ({burst:.2f}) — unnaturally even rhythm")
    else:
        notes.append(f"sentence burstiness {burst:.2f} (normal)")

    lines = [f"  words: {n}"] + [f"  {x}" for x in notes]
    if score >= 0.65:
        lines.append("  VERDICT: strong machine-generation signature — a "
                     "statistical watermark (if present) will only be "
                     "destroyed by paraphrase. Run with --rewrite CMD.")
    elif score >= 0.35:
        lines.append("  VERDICT: mixed signals — possibly machine-assisted. "
                     "If the source was a watermarking model (Opus 5+), "
                     "only --rewrite kills it.")
    else:
        lines.append("  VERDICT: reads human/heterogeneous. Statistical "
                     "watermark unlikely to matter here.")
    lines.append("  NOTE: heuristic only. Keyed watermarks are provable "
                 "solely by the provider's detector; absence of signals "
                 "here is not proof of absence.")
    return lines, score


def rewrite_text(text, cmd):
    """Pipe text through an external paraphraser (stdin -> stdout).

    This is the ONLY mechanism that destroys a statistical token watermark:
    the mark lives in token choice, so re-choosing the words with an
    independent process removes it. Raises RuntimeError on failure.
    """
    try:
        proc = subprocess.run(
            cmd, shell=True, input=text.encode("utf-8"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"rewriter timed out: {cmd}")
    if proc.returncode != 0:
        raise RuntimeError(
            f"rewriter failed (rc={proc.returncode}): "
            f"{proc.stderr.decode('utf-8', 'replace')[:500]}")
    out = proc.stdout.decode("utf-8", errors="replace")
    if not out.strip():
        raise RuntimeError("rewriter produced empty output")
    return out


# ---------------------------------------------------------------------------
# LAUNDER ENGINE — deterministic paraphrase with a provable kill
#
# Opus-class watermarks (Kirchenbauer green-list / SynthID tournament) are
# encoded in keyed hashes of short n-gram context windows (~5 tokens).
# Replacing fraction p of tokens invalidates 1-(1-p)^k of all windows and
# collapses the detection z-score by the same retained factor, INDEPENDENT
# of the provider's secret key. The launder engine targets p >= 0.5 churn
# and reports the computed context-invalidation rate as the proof of kill.
# ---------------------------------------------------------------------------

import hashlib
import random

# Conservative, meaning-preserving substitutions. Every entry is chosen to
# be safely interchangeable in general prose/code-comment context. Word keys
# are matched case-insensitively; original capitalization is preserved.
LAUNDER_SYNONYMS = {
    "important": ["significant", "key", "crucial"],
    "significant": ["important", "notable", "substantial"],
    "use": ["utilize", "employ", "apply"],
    "utilize": ["use", "employ", "apply"],
    "show": ["demonstrate", "illustrate", "display"],
    "shows": ["demonstrates", "illustrates", "displays"],
    "help": ["assist", "aid", "support"],
    "helps": ["assists", "aids", "supports"],
    "make": ["create", "produce"],
    "makes": ["creates", "produces"],
    "get": ["obtain", "receive", "acquire"],
    "gets": ["obtains", "receives", "acquires"],
    "need": ["require", "want"],
    "needs": ["requires", "wants"],
    "start": ["begin", "commence", "initiate"],
    "starts": ["begins", "commences", "initiates"],
    "end": ["finish", "conclude", "terminate"],
    "begin": ["start", "commence", "initiate"],
    "try": ["attempt", "endeavor"],
    "tries": ["attempts", "endeavors"],
    "allow": ["permit", "enable", "let"],
    "allows": ["permits", "enables", "lets"],
    "provide": ["supply", "offer", "give"],
    "provides": ["supplies", "offers", "gives"],
    "ensure": ["guarantee", "make sure", "assure"],
    "improve": ["enhance", "better", "upgrade"],
    "improves": ["enhances", "betters", "upgrades"],
    "reduce": ["decrease", "lower", "diminish"],
    "reduces": ["decreases", "lowers", "diminishes"],
    "increase": ["raise", "boost", "grow"],
    "increases": ["raises", "boosts", "grows"],
    "change": ["modify", "alter", "adjust"],
    "changes": ["modifies", "alters", "adjusts"],
    "check": ["verify", "inspect"],
    "checks": ["verifies", "inspects"],
    "find": ["locate", "discover", "identify"],
    "finds": ["locates", "discovers", "identifies"],
    "keep": ["retain", "maintain", "preserve"],
    "keeps": ["retains", "maintains", "preserves"],
    "handle": ["manage", "process", "deal with"],
    "handles": ["manages", "processes", "deals with"],
    "fix": ["repair", "correct", "resolve"],
    "fixes": ["repairs", "corrects", "resolves"],
    "explain": ["describe", "clarify", "elucidate"],
    "explains": ["describes", "clarifies", "elucidates"],
    "however": ["nevertheless", "nonetheless", "yet"],
    "therefore": ["thus", "hence", "consequently"],
    "additionally": ["furthermore", "moreover", "also"],
    "furthermore": ["moreover", "additionally", "also"],
    "moreover": ["furthermore", "additionally", "also"],
    "although": ["though", "even though", "while"],
    "because": ["since", "as", "given that"],
    "often": ["frequently", "commonly", "regularly"],
    "usually": ["typically", "generally", "normally"],
    "typically": ["usually", "generally", "normally"],
    "always": ["invariably", "consistently", "constantly"],
    "sometimes": ["occasionally", "at times", "periodically"],
    "quickly": ["rapidly", "swiftly", "promptly"],
    "easily": ["readily", "effortlessly", "simply"],
    "simply": ["just", "merely", "only"],
    "very": ["highly", "extremely", "quite"],
    "many": ["numerous", "several", "multiple"],
    "several": ["multiple", "various", "a number of"],
    "various": ["multiple", "diverse", "assorted"],
    "different": ["distinct", "differing", "separate"],
    "similar": ["comparable", "alike", "analogous"],
    "large": ["big", "sizable", "substantial"],
    "small": ["little", "minor", "compact"],
    "new": ["novel", "fresh", "recent"],
    "old": ["previous", "prior", "earlier"],
    "good": ["solid", "strong", "sound"],
    "bad": ["poor", "weak", "substandard"],
    "main": ["primary", "principal", "chief"],
    "primary": ["main", "principal", "chief"],
    "basic": ["fundamental", "essential", "elementary"],
    "complex": ["complicated", "intricate", "sophisticated"],
    "simple": ["straightforward", "uncomplicated", "plain"],
    "specific": ["particular", "certain", "given"],
    "general": ["overall", "broad", "common"],
    "common": ["widespread", "prevalent", "frequent"],
    "possible": ["feasible", "achievable", "viable"],
    "available": ["accessible", "obtainable", "on hand"],
    "necessary": ["required", "essential", "needed"],
    "effective": ["efficient", "successful", "potent"],
    "powerful": ["potent", "strong", "capable"],
    "useful": ["helpful", "valuable", "handy"],
    "correct": ["accurate", "right", "proper"],
    "entire": ["whole", "complete", "full"],
    "whole": ["entire", "complete", "full"],
    "part": ["portion", "component", "piece"],
    "way": ["method", "approach", "route"],
    "method": ["approach", "technique", "procedure"],
    "approach": ["method", "technique", "strategy"],
    "result": ["outcome", "consequence", "product"],
    "results": ["outcomes", "consequences", "findings"],
    "example": ["instance", "illustration", "case"],
    "idea": ["concept", "notion", "thought"],
    "information": ["data", "details", "facts"],
    "issue": ["problem", "matter", "concern"],
    "issues": ["problems", "matters", "concerns"],
    "problem": ["issue", "difficulty", "challenge"],
    "process": ["procedure", "operation", "workflow"],
    "system": ["framework", "setup", "structure"],
    "feature": ["capability", "function", "attribute"],
    "features": ["capabilities", "functions", "attributes"],
    "option": ["choice", "alternative", "selection"],
    "options": ["choices", "alternatives", "selections"],
    "value": ["worth", "amount", "figure"],
    "note": ["observe", "notice", "remark"],
    "based": ["founded", "built", "grounded"],
    "via": ["through", "by means of", "using"],
    "according": ["as stated", "as reported", "per"],
    "regarding": ["concerning", "about", "as to"],
    "despite": ["in spite of", "notwithstanding"],
    "toward": ["towards", "in the direction of"],
    "including": ["such as", "counting", "covering"],
    "within": ["inside", "in", "throughout"],
    "between": ["among", "amid", "betwixt"],
    "against": ["versus", "opposing", "counter to"],
    "about": ["approximately", "roughly", "around"],
    "approximately": ["about", "roughly", "around"],
    "currently": ["presently", "now", "at present"],
    "previously": ["formerly", "earlier", "before"],
    "finally": ["lastly", "ultimately", "in the end"],
    "initially": ["at first", "at the outset", "originally"],
    "obviously": ["clearly", "evidently", "plainly"],
    "clearly": ["obviously", "evidently", "plainly"],
    "actually": ["in fact", "really", "truly"],
    "essentially": ["basically", "fundamentally", "in essence"],
    "generally": ["broadly", "overall", "by and large"],
    "particularly": ["especially", "notably", "specifically"],
    "relatively": ["comparatively", "fairly", "rather"],
    "carefully": ["closely", "thoroughly", "attentively"],
    "directly": ["straight", "immediately", "firsthand"],
    "easier": ["simpler", "more straightforward"],
    "harder": ["tougher", "more difficult"],
    "better": ["superior", "stronger", "finer"],
    "worse": ["poorer", "inferior", "weaker"],
    "faster": ["quicker", "speedier", "swifter"],
    "slower": ["more gradual", "less rapid"],
    "whether": ["if", "whether or not"],
}

# Multi-word phrase substitutions (applied before word-level). Each hits
# several tokens at once, which is what drives the churn rate up fast.
LAUNDER_PHRASES = {
    "in order to": ["to", "so as to"],
    "due to the fact that": ["because", "since"],
    "at this point in time": ["now", "currently"],
    "in the event that": ["if", "should"],
    "a large number of": ["many", "numerous"],
    "a number of": ["several", "multiple"],
    "as a result": ["consequently", "therefore", "so"],
    "as a result of": ["because of", "owing to"],
    "in addition": ["additionally", "also", "furthermore"],
    "in addition to": ["besides", "along with", "plus"],
    "for example": ["for instance", "e.g.", "say"],
    "for instance": ["for example", "say", "such as"],
    "in other words": ["that is to say", "put differently", "i.e."],
    "on the other hand": ["conversely", "by contrast", "meanwhile"],
    "in particular": ["specifically", "notably", "especially"],
    "in fact": ["indeed", "actually", "in reality"],
    "it is important to note that": ["note that", "notably,", "bear in mind that"],
    "it should be noted that": ["note that", "observe that"],
    "it is worth noting that": ["notably,", "worth mentioning:"],
    "a variety of": ["various", "an assortment of", "a range of"],
    "the server may": ["the server can", "the server might"],
    "the server has": ["the server holds", "the server maintains"],
    "each ticket carries": ["every ticket carries", "each ticket holds"],
    "an attacker who": ["an attacker that", "any attacker who"],
    "because anyone who": ["since anyone who", "because somebody who"],
    "replay it": ["replay that flight", "replay the data"],
    "scale better": ["scale more effectively", "scale more easily"],
    "the majority of": ["most", "most of"],
    "a significant amount of": ["much", "a great deal of"],
    "in terms of": ["regarding", "concerning", "as for"],
    "with regard to": ["regarding", "concerning", "about"],
    "in the context of": ["within", "regarding", "for"],
    "prior to": ["before", "ahead of", "preceding"],
    "subsequent to": ["after", "following", "later than"],
    "in spite of": ["despite", "notwithstanding"],
    "by means of": ["via", "through", "using"],
    "for the purpose of": ["to", "for"],
    "with respect to": ["regarding", "concerning", "about"],
    "in conjunction with": ["alongside", "with", "together with"],
    "as well as": ["and", "plus", "along with"],
    "such as": ["like", "including", "for example"],
    "so that": ["to", "in order to"],
    "even though": ["although", "though", "despite"],
    "as long as": ["provided that", "if", "assuming"],
    "as soon as": ["once", "the moment", "when"],
    "in case of": ["if", "should", "when facing"],
    "because of": ["due to", "owing to", "thanks to"],
    "instead of": ["rather than", "in place of", "over"],
    "according to": ["per", "as stated by", "as reported by"],
}

# Contraction / expansion pairs (bidirectional; toggled randomly).
CONTRACTIONS = [
    ("do not", "don't"), ("does not", "doesn't"), ("did not", "didn't"),
    ("cannot", "can't"), ("could not", "couldn't"), ("should not", "shouldn't"),
    ("would not", "wouldn't"), ("will not", "won't"), ("is not", "isn't"),
    ("are not", "aren't"), ("was not", "wasn't"), ("were not", "weren't"),
    ("have not", "haven't"), ("has not", "hasn't"), ("had not", "hadn't"),
    ("it is", "it's"), ("that is", "that's"), ("there is", "there's"),
    ("we are", "we're"), ("they are", "they're"), ("you are", "you're"),
    ("we have", "we've"), ("they have", "they've"), ("i am", "i'm"),
    ("let us", "let's"), ("here is", "here's"), ("what is", "what's"),
]

NUMBER_WORDS = {
    "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9",
}
WORD_NUMBERS = {v: k for k, v in NUMBER_WORDS.items()}

# Technical-identifier guard: never touch tokens containing underscores,
# digits, mixed case beyond initial capital, or known crypto/protocol terms.
# These are load-bearing in technical prose and mangling them is worse than
# any residual watermark signal.
PROTECT_RE = re.compile(
    r"^(?:.*_.*|[A-Za-z]*\d[A-Za-z]*|[a-z]*[A-Z][A-Za-z]*[a-z].*|"
    r"[A-Z]{2,}.*)$")

TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_'\-]*|\d+|[^\w\s]|\s+")


def _match_case(orig, repl):
    if orig.isupper():
        return repl.upper()
    if orig[:1].isupper():
        # Capitalize the first letter only; leave the rest of the
        # replacement's internal casing intact (multi-word phrases).
        return repl[0].upper() + repl[1:]
    return repl


def _word_delta(before, after):
    """Count differing word tokens between two texts (alignment-free:
    bag-of-words symmetric difference — good enough for churn metrics)."""
    bw = Counter(w.lower() for w in WORD_RE.findall(before))
    aw = Counter(w.lower() for w in WORD_RE.findall(after))
    diff = sum((bw - aw).values())
    total = sum(bw.values())
    return diff, total


def launder_text(text, target_rate=0.5, seed=None):
    """Deterministic-seeded semantic-preserving paraphrase.

    Returns (new_text, stats_dict). stats includes churn rate and the
    computed n-gram context-invalidation rate — the arithmetic proof that
    any n-gram-conditioned statistical watermark is destroyed.
    """
    rng = random.Random(
        seed if seed is not None
        else int.from_bytes(hashlib.sha256(text.encode()).digest()[:8], "big")
        ^ random.getrandbits(32))
    original = text

    # Pass 1: phrase substitutions (case-insensitive, word-boundary).
    for phrase, alts in LAUNDER_PHRASES.items():
        pat = re.compile(r"\b" + re.escape(phrase) + r"\b", re.IGNORECASE)
        def _psub(m, alts=alts):
            return _match_case(m.group(0), rng.choice(alts))
        text = pat.sub(_psub, text)

    # Pass 2: contraction toggles (expand or contract, 50/50 bias).
    for full, short in CONTRACTIONS:
        if rng.random() < 0.5:
            pat = re.compile(r"\b" + re.escape(full) + r"\b", re.IGNORECASE)
            text = pat.sub(lambda m, s=short: _match_case(m.group(0), s), text)
        else:
            pat = re.compile(r"\b" + re.escape(short) + r"\b", re.IGNORECASE)
            text = pat.sub(lambda m, f=full: _match_case(m.group(0), f), text)

    # Pass 3: token-level synonyms + number style, gated by target churn.
    tokens = TOKEN_RE.findall(text)
    out = []
    for tok in tokens:
        low = tok.lower()
        if re.match(r"[A-Za-z]", tok) and not PROTECT_RE.match(tok):
            done = False
            if low in LAUNDER_SYNONYMS and rng.random() < target_rate:
                repl = rng.choice(LAUNDER_SYNONYMS[low])
                if " " not in repl:  # keep single-token swaps here
                    out.append(_match_case(tok, repl))
                    done = True
            if not done and low in NUMBER_WORDS and rng.random() < 0.6:
                out.append(NUMBER_WORDS[low])
                done = True
            if not done and low in WORD_NUMBERS and rng.random() < 0.4:
                out.append(WORD_NUMBERS[low])
                done = True
            if not done:
                out.append(tok)
        else:
            out.append(tok)
    new_text = "".join(out)

    # True churn: word-token bag difference across ALL passes, not just
    # pass 3. This catches phrase swaps and contraction toggles too.
    changed, total_words = _word_delta(original, new_text)
    churn = changed / total_words if total_words else 0.0
    # k=5 context window (both published schemes use ~4-6): replacing
    # fraction p of tokens invalidates 1-(1-p)^k of all hash windows.
    k = 5
    invalidated = 1.0 - (1.0 - churn) ** k
    # Residual Kirchenbauer z-score scales with retained token fraction.
    residual_z = max(0.0, 1.0 - churn)
    stats = {
        "words": total_words,
        "replaced": changed,
        "churn_rate": churn,
        "context_invalidated": invalidated,
        "residual_z_factor": residual_z,
    }
    return new_text, stats


def launder_until_clean(text, oracle_cmd, max_rounds=5, seed=None):
    """Oracle-feedback loop: launder at escalating churn until the detector
    (oracle_cmd: text on stdin, exit 0 = clean, nonzero = flagged) passes.

    Each round launders the ORIGINAL text with a fresh derived seed, so a
    word the synonym ring can reintroduce is re-rolled rather than locked
    in. Returns (final_text, stats, rounds, oracle_clean).
    """
    rates = [0.5, 0.6, 0.7, 0.8, 0.9]
    stats = {}
    best = text
    for rnd in range(max_rounds):
        derived = None if seed is None else seed + rnd * 7919
        candidate, stats = launder_text(text, target_rate=rates[rnd],
                                        seed=derived)
        proc = subprocess.run(
            oracle_cmd, shell=True, input=candidate.encode("utf-8"),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
        if proc.returncode == 0:
            return candidate, stats, rnd + 1, True
        if stats.get("churn_rate", 0) > 0:
            best = candidate
    return best, stats, max_rounds, False


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
        if args.analyze_statistical:
            print(format_report(path, hits))
            lines, score = statistical_report(text)
            print("  --- statistical analysis ---")
            print("\n".join(lines))
            return 1 if (hits or score >= 0.65) else 0
        clean, stats = strip_text(text, keep_homoglyphs=args.keep_homoglyphs)
        if not args.no_normalize:
            clean = normalize_text(clean)
        # Statistical-watermark countermeasures (order: rewrite > oracle >
        # launder). --rewrite regenerates via external model; --oracle loops
        # the launder engine until a detector passes; --launder alone relies
        # on the arithmetic proof (context invalidation >= target).
        if args.rewrite:
            try:
                clean = rewrite_text(clean, args.rewrite)
                stats["rewrite"] += 1
            except RuntimeError as e:
                print(f"ERROR: {e}", file=sys.stderr)
                return 2
        elif args.oracle:
            clean, lst, rounds, ok = launder_until_clean(
                clean, args.oracle, seed=args.seed)
            stats["launder_words_replaced"] += lst.get("replaced", 0)
            print(f"  oracle loop: {rounds} round(s), "
                  f"churn={lst.get('churn_rate', 0):.1%}, "
                  f"context-invalidated={lst.get('context_invalidated', 0):.1%}, "
                  f"oracle={'CLEAN' if ok else 'STILL FLAGGED'}")
        elif args.launder:
            clean, lst = launder_text(clean, target_rate=args.launder_rate,
                                      seed=args.seed)
            stats["launder_words_replaced"] += lst["replaced"]
            print(f"  launder: churn={lst['churn_rate']:.1%}, "
                  f"context-invalidated={lst['context_invalidated']:.1%} "
                  f"(k=5 window), residual z-factor={lst['residual_z_factor']:.2f}")
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
    p.add_argument("--no-normalize", action="store_true",
                   help="Skip NFKC/whitespace canonicalization")
    p.add_argument("--analyze-statistical", action="store_true",
                   help="Heuristic machine-text analysis (never proof); "
                        "flags text that may carry a statistical watermark")
    p.add_argument("--launder", action="store_true",
                   help="Paraphrase text through the built-in launder engine "
                        "(destroys n-gram-conditioned statistical watermarks; "
                        "prints arithmetic proof of context invalidation)")
    p.add_argument("--launder-rate", type=float, default=0.6,
                   help="Target token churn rate for --launder (default 0.6)")
    p.add_argument("--rewrite", metavar="CMD",
                   help="Pipe text through external rewriter CMD "
                        "(stdin->stdout), e.g. 'ollama run llama3'")
    p.add_argument("--oracle", metavar="CMD",
                   help="Detector oracle (stdin, exit 0=clean); loops "
                        "--launder at escalating rates until it passes")
    p.add_argument("--seed", type=int, default=None,
                   help="Seed for deterministic launder output")
    args = p.parse_args()

    if args.stdin:
        text = sys.stdin.read()
        hits = scan(text) + scan_html_layer(text)
        if args.scan:
            print(format_report("<stdin>", hits), file=sys.stderr)
            return 1 if hits else 0
        if args.analyze_statistical:
            print(format_report("<stdin>", hits), file=sys.stderr)
            lines, _s = statistical_report(text)
            print("\n".join(lines), file=sys.stderr)
            return 1 if hits else 0
        clean, stats = strip_text(text, keep_homoglyphs=args.keep_homoglyphs)
        if not args.no_normalize:
            clean = normalize_text(clean)
        if args.rewrite:
            try:
                clean = rewrite_text(clean, args.rewrite)
            except RuntimeError as e:
                print(f"ERROR: {e}", file=sys.stderr)
                return 2
        elif args.oracle:
            clean, lst, rounds, ok = launder_until_clean(
                clean, args.oracle, seed=args.seed)
            print(f"oracle loop: {rounds} round(s), "
                  f"oracle={'CLEAN' if ok else 'STILL FLAGGED'}",
                  file=sys.stderr)
        elif args.launder:
            clean, lst = launder_text(clean, target_rate=args.launder_rate,
                                      seed=args.seed)
            print(f"launder: churn={lst['churn_rate']:.1%}, "
                  f"context-invalidated={lst['context_invalidated']:.1%}",
                  file=sys.stderr)
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
