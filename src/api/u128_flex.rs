//! 128-bit message ids, accepted in either JSON form.
//!
//! Browsers have no 64-bit integer: a 38-digit uid read as a JSON *number* becomes
//! a float64 and loses ~4e21, so the id a client sends back is not the one it was
//! given. The client now quotes ids; this still accepts bare digits so a stale
//! cached bundle keeps working.
//!
//! Parsed through `RawValue`, which keeps the literal text. `deserialize_any`
//! cannot do this job: serde_json has no u128 in its untagged/Content path, so a
//! 38-digit bare id arrives as a float and every old client fails as invalid JSON.

use serde::de::{self, Deserializer};
use serde::Deserialize;
use serde_json::value::RawValue;

fn parse(text: &str) -> Result<u128, String> {
    let t = text.trim().trim_matches('"');
    t.parse::<u128>().map_err(|e| format!("bad message id: {e}"))
}

pub fn uid<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
    let raw = Box::<RawValue>::deserialize(d)?;
    parse(raw.get()).map_err(de::Error::custom)
}

pub fn uids<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u128>, D::Error> {
    let raw = Box::<RawValue>::deserialize(d)?;
    let text = raw.get().trim();
    let inner = text
        .strip_prefix('[')
        .and_then(|t| t.strip_suffix(']'))
        .ok_or_else(|| de::Error::custom("expected a list of message ids"))?;
    inner
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| parse(s).map_err(de::Error::custom))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct One {
        #[serde(deserialize_with = "uid")]
        uid: u128,
    }

    #[derive(Deserialize)]
    struct Many {
        #[serde(deserialize_with = "uids")]
        uids: Vec<u128>,
    }

    const ID: u128 = 60_349_880_548_505_824_788_396_477_401_486_182_124;

    #[test]
    fn a_bare_id_parses_exactly() {
        let one: One = serde_json::from_str(&format!("{{\"uid\":{ID}}}")).unwrap();
        assert_eq!(one.uid, ID);
    }

    #[test]
    fn a_quoted_id_parses_exactly() {
        let one: One = serde_json::from_str(&format!("{{\"uid\":\"{ID}\"}}")).unwrap();
        assert_eq!(one.uid, ID);
    }

    #[test]
    fn a_list_accepts_both_forms() {
        let many: Many = serde_json::from_str(&format!("{{\"uids\":[\"{ID}\",{ID}]}}")).unwrap();
        assert_eq!(many.uids, vec![ID, ID]);
    }

    #[test]
    fn nonsense_is_refused() {
        assert!(serde_json::from_str::<One>("{\"uid\":\"not-an-id\"}").is_err());
        assert!(serde_json::from_str::<One>("{\"uid\":[1]}").is_err());
    }
}
