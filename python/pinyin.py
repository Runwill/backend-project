#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Read a JSON array of texts from stdin and output JSON array of objects
[{"full": "quan pin yin", "abbr": "qpy"}, ...] using pypinyin.

If pypinyin is not installed, falls back to a naive transliteration that
returns the original text as 'full' and empty 'abbr'.
"""

import sys
import json

def _safe_load_pypinyin():
    try:
        from pypinyin import pinyin, Style
        return pinyin, Style
    except Exception:
        return None, None

def _convert_batch(texts):
    pinyin_mod, Style = _safe_load_pypinyin()
    result = []
    if pinyin_mod is None:
        # Fallback: no conversion
        for t in texts:
            t = t if isinstance(t, str) else ("" if t is None else str(t))
            result.append({"full": t, "abbr": ""})
        return result
    for t in texts:
        s = t if isinstance(t, str) else ("" if t is None else str(t))
        # no tone, keep v for ü as 'v' default behavior; join by space
        arr = pinyin_mod(s, style=Style.NORMAL, strict=False)
        full = " ".join([ seg[0] if seg else "" for seg in arr ])
        # first-letter abbreviation
        arr_fl = pinyin_mod(s, style=Style.FIRST_LETTER, strict=False)
        abbr = "".join([ seg[0] if seg else "" for seg in arr_fl ])
        result.append({"full": full.lower().strip(), "abbr": abbr.lower().strip()})
    return result

def main():
    data = sys.stdin.read()
    try:
        texts = json.loads(data)
        if not isinstance(texts, list):
            raise ValueError("input must be a JSON array")
    except Exception:
        # fallback: treat entire stdin as one text
        texts = [data.strip()]
    out = _convert_batch(texts)
    sys.stdout.write(json.dumps(out, ensure_ascii=False))

if __name__ == "__main__":
    main()
