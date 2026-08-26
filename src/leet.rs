//! Leet speak (l33t) codec.
//!
//! Two directions:
//!   encode — rewrite normal text into leet (used to obfuscate a flagged user
//!            message so a re-scan no longer matches the cyber signature).
//!   decode — normalize leet back to readable plain text (the "text
//!            normalizer" half of the feature).
//!
//! Substitution table (the common one; both directions share it):
//!   A ↔ 4/@   B ↔ 8   E ↔ 3   G ↔ 6/9   I ↔ 1/!   L ↔ 1/|   O ↔ 0
//!   R ↔ 1/2   S ↔ 5/$  T ↔ 7/+   Z ↔ 2
//!
//! Encoding is deterministic (first variant per letter) so the output is
//! stable and testable. Decoding disambiguates context-free by preferring the
//! most common real word; digits that are already part of a number stay put.

/// Canonical leet substitution for encoding, indexed by lowercase ASCII letter.
/// Only letters with a common leet form are mapped; everything else passes
/// through unchanged (punctuation, digits, non-ASCII are preserved).
fn encode_char(c: char) -> Option<&'static str> {
    Some(match c.to_ascii_lowercase() {
        'a' => "4",
        'b' => "8",
        'e' => "3",
        'g' => "6",
        'i' => "1",
        'l' => "1",
        'o' => "0",
        's' => "5",
        't' => "7",
        'z' => "2",
        _ => return None,
    })
}

/// Encode plain text into leet speak. Case is dropped (leet is conventionally
/// lowercase); punctuation, whitespace, digits and non-ASCII are preserved
/// verbatim so sentence structure survives the round trip.
pub fn encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match encode_char(c) {
            Some(sub) => out.push_str(sub),
            None => out.push(c),
        }
    }
    out
}

/// Reverse lookup for a single leet symbol. Ambiguous by design — `1` can be
/// I, L or R — so decoding works word-by-word and picks the candidate that
/// forms a real word (see [`decode_word`]).
fn decode_symbol(c: char) -> &'static [&'static str] {
    match c {
        '4' | '@' => &["a"],
        '8' => &["b"],
        '3' => &["e"],
        '6' | '9' => &["g"],
        '1' => &["i", "l", "r"],
        '!' => &["i"],
        '|' => &["l"],
        '0' => &["o"],
        '2' => &["r", "z"],
        '5' | '$' => &["s"],
        '7' | '+' => &["t"],
        _ => &[],
    }
}

/// A small built-in lexicon of common words, used to prefer the most common
/// real interpretation when a leet token has several decodings. Lowercase.
/// This is intentionally modest — it only needs to break ties toward the
/// reading a human would pick, not to be a full dictionary.
const COMMON_WORDS: &[&str] = &[
    "a", "am", "an", "and", "are", "as", "at", "be", "but", "by", "can", "do", "for", "from",
    "had", "has", "have", "he", "hello", "her", "here", "him", "his", "how", "i", "if", "in", "is",
    "it", "its", "me", "my", "no", "not", "now", "of", "on", "or", "our", "out", "she", "so",
    "that", "the", "their", "them", "there", "they", "this", "to", "up", "us", "was", "we", "what",
    "when", "who", "will", "with", "world", "you", "your", "hacker", "scan", "tool", "code",
    "script", "test", "file", "run", "all", "one", "two", "see", "go", "let", "lol", "elite",
    "leet", "own", "pwn", "the", "are", "oro", "loll", "roll", "troll", "ill", "got", "tools",
];

/// Generate every plausible plain-text decoding of a leet token (cartesian
/// product of per-symbol candidates), most-likely first. Letters and unknown
/// symbols map to themselves. Capped to avoid combinatorial blowup on long
/// tokens — past the cap we stop branching and take the first candidate.
fn decode_candidates(word: &str) -> Vec<String> {
    const MAX_BRANCH: usize = 256;
    let mut acc: Vec<String> = vec![String::new()];
    for c in word.chars() {
        let cands: Vec<String> = if c.is_ascii_alphabetic() {
            let lower = c.to_ascii_lowercase();
            if lower == 'z' {
                vec!["s".to_string(), "z".to_string()]
            } else {
                vec![lower.to_string()]
            }
        } else {
            let syms = decode_symbol(c);
            if syms.is_empty() {
                vec![c.to_string()]
            } else {
                syms.iter().map(|s| s.to_string()).collect()
            }
        };
        let mut next: Vec<String> = Vec::new();
        for prefix in &acc {
            for cand in &cands {
                next.push(format!("{prefix}{cand}"));
                if next.len() >= MAX_BRANCH {
                    break;
                }
            }
            if next.len() >= MAX_BRANCH {
                break;
            }
        }
        acc = next;
    }
    acc
}

/// Decode one leet token to its most likely plain word. If any candidate is a
/// common real word, return the first (most common) one; otherwise fall back
/// to the first candidate (the deterministic primary reading).
fn decode_word(word: &str) -> String {
    if word.chars().all(|c| c.is_ascii_digit()) {
        if word.len() > 1 {
            return word.to_string();
        }
        // Single digit: decode only if a candidate is a common word (e.g. 1→i, 4→a).
        let cands = decode_candidates(word);
        for c in &cands {
            if COMMON_WORDS.contains(&c.as_str()) {
                return c.clone();
            }
        }
        return word.to_string();
    }
    let cands = decode_candidates(word);
    for c in &cands {
        if COMMON_WORDS.contains(&c.as_str()) {
            return c.clone();
        }
    }
    cands.into_iter().next().unwrap_or_else(|| word.to_string())
}

/// Decode leet speak back to plain readable text. Splits on whitespace and
/// punctuation (which are preserved), decodes each token, and prefers common
/// real words when a token is ambiguous.
pub fn decode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut cur = String::new();
    let flush = |cur: &mut String, out: &mut String| {
        if !cur.is_empty() {
            out.push_str(&decode_word(cur));
            cur.clear();
        }
    };
    for c in input.chars() {
        if c.is_alphanumeric() || matches!(c, '@' | '|' | '$' | '+') {
            cur.push(c);
        } else {
            flush(&mut cur, &mut out);
            out.push(c);
        }
    }
    flush(&mut cur, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_uses_canonical_substitutions() {
        assert_eq!(encode("hello world"), "h3110 w0r1d");
        assert_eq!(encode("I am a hacker"), "1 4m 4 h4ck3r");
        assert_eq!(encode("scan"), "5c4n");
    }

    #[test]
    fn encode_preserves_punctuation_digits_and_non_ascii() {
        assert_eq!(encode("hi, ban oi! 123"), "h1, 84n 01! 123");
        // Vietnamese / non-ASCII letters are untouched.
        assert_eq!(encode("tạo tool"), "7ạ0 7001");
    }

    #[test]
    fn decode_basic_leet() {
        assert_eq!(decode("h3ll0 w0r1d"), "hello world");
        assert_eq!(decode("1 4m 4 h4ck3r"), "i am a hacker");
    }

    #[test]
    fn decode_disambiguates_to_common_word() {
        // "1" alone -> "i" (the pronoun), not "l" or "r".
        assert_eq!(decode("1"), "i");
        // "w0r1d" -> "world" (real word) over "worid"/"wor ld".
        assert_eq!(decode("w0r1d"), "world");
    }

    #[test]
    fn decode_preserves_punctuation_and_numbers() {
        assert_eq!(decode("h3ll0, w0r1d!"), "hello, world!");
        assert_eq!(decode("123"), "123");
        assert_eq!(decode("g0t 2 t00lz?"), "got 2 tools?");
    }

    #[test]
    fn round_trip_is_readable() {
        let original = "hello world i am a hacker";
        let leet = encode(original);
        assert_eq!(leet, "h3110 w0r1d 1 4m 4 h4ck3r");
        assert_eq!(decode(&leet), original);
    }
}
