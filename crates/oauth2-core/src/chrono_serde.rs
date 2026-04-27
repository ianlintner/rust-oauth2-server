//! Tolerant `chrono::DateTime<Utc>` (de)serialization helpers for fields that
//! round-trip through MongoDB.
//!
//! ## Why this exists
//!
//! Different code paths in `oauth2-storage-mongo` historically wrote timestamp
//! fields with different BSON types:
//!
//! - `Collection<T>::insert_one(...)` flows through chrono's default `Serialize`
//!   impl, which emits an **RFC 3339 string** — stored as BSON String.
//! - `update_*` functions that built `$set` documents with
//!   `mongodb::bson::DateTime` wrote the field as **BSON Date**.
//!
//! When a single document mixes the two encodings, reading it back through
//! chrono's default `Deserialize` (which expects only a string) panics with
//! `invalid type: map, expected an RFC 3339 formatted date and time string`,
//! surfacing as a 500 from any handler that touches the model. This was the
//! root cause of the production `/auth/callback/github` outage (PR #288).
//!
//! ## What this module provides
//!
//! Two `serde` deserializers that accept every shape a `DateTime<Utc>` can
//! take in BSON or extended JSON:
//!
//! - `deserialize` — for required `DateTime<Utc>` fields.
//! - `deserialize_opt` — for `Option<DateTime<Utc>>` fields.
//!
//! Both accept:
//!
//! 1. RFC 3339 string (chrono native form, what `insert_one` writes).
//! 2. BSON Date in binary mode (visited as `i64` millis since epoch).
//! 3. Extended-JSON v1: `{"$date": <i64 millis>}`.
//! 4. Extended-JSON v2 / canonical: `{"$date": {"$numberLong": "<ms>"}}`.
//!
//! Serialization is intentionally **not** customized here — fields keep using
//! chrono's default `Serialize` (RFC 3339 string), which preserves existing
//! HTTP/JSON output and matches the `insert_one` path.

use chrono::{DateTime, TimeZone, Utc};
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, Visitor};
use serde::Deserializer;
use std::fmt;

/// Tolerant deserializer for a required `DateTime<Utc>`.
pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
    d.deserialize_any(DtVisitor)
}

/// Tolerant deserializer for an `Option<DateTime<Utc>>`.
///
/// Accepts JSON `null`, missing/absent values, or any of the forms accepted
/// by [`deserialize`].
pub fn deserialize_opt<'de, D: Deserializer<'de>>(d: D) -> Result<Option<DateTime<Utc>>, D::Error> {
    d.deserialize_any(OptDtVisitor)
}

struct DtVisitor;

impl<'de> Visitor<'de> for DtVisitor {
    type Value = DateTime<Utc>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RFC 3339 date string, BSON Date (i64 millis), or extended-JSON {$date: …}")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        DateTime::parse_from_rfc3339(v)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(de::Error::custom)
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
        self.visit_str(&v)
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
        Utc.timestamp_millis_opt(v)
            .single()
            .ok_or_else(|| de::Error::custom("invalid millis"))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        self.visit_i64(v as i64)
    }

    fn visit_i128<E: de::Error>(self, v: i128) -> Result<Self::Value, E> {
        self.visit_i64(v as i64)
    }

    fn visit_u128<E: de::Error>(self, v: u128) -> Result<Self::Value, E> {
        self.visit_i64(v as i64)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        // Look for a `$date` key. Its value is either an i64 (extjson v1)
        // or a sub-map with `$numberLong` as a string (extjson v2).
        while let Some(key) = map.next_key::<String>()? {
            if key == "$date" {
                return map.next_value_seed(DateValueSeed);
            }
            // Skip unrelated keys (defensive — bson shouldn't produce any).
            let _: IgnoredAny = map.next_value()?;
        }
        Err(de::Error::custom("missing $date key in BSON Date object"))
    }
}

struct OptDtVisitor;

impl<'de> Visitor<'de> for OptDtVisitor {
    type Value = Option<DateTime<Utc>>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("null or a value accepted by chrono_serde::deserialize")
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        deserialize(d).map(Some)
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        DtVisitor.visit_str(v).map(Some)
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
        DtVisitor.visit_string(v).map(Some)
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
        DtVisitor.visit_i64(v).map(Some)
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        DtVisitor.visit_u64(v).map(Some)
    }
    fn visit_i128<E: de::Error>(self, v: i128) -> Result<Self::Value, E> {
        DtVisitor.visit_i128(v).map(Some)
    }
    fn visit_u128<E: de::Error>(self, v: u128) -> Result<Self::Value, E> {
        DtVisitor.visit_u128(v).map(Some)
    }
    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        DtVisitor.visit_map(map).map(Some)
    }
}

struct DateValueSeed;

impl<'de> DeserializeSeed<'de> for DateValueSeed {
    type Value = DateTime<Utc>;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(DateValueVisitor)
    }
}

struct DateValueVisitor;

impl<'de> Visitor<'de> for DateValueVisitor {
    type Value = DateTime<Utc>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BSON $date value (i64 millis or {$numberLong: \"<ms>\"})")
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
        Utc.timestamp_millis_opt(v)
            .single()
            .ok_or_else(|| de::Error::custom("invalid millis"))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        self.visit_i64(v as i64)
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        DateTime::parse_from_rfc3339(v)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(de::Error::custom)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            if key == "$numberLong" {
                let s: String = map.next_value()?;
                let ms: i64 = s.parse().map_err(de::Error::custom)?;
                return Utc
                    .timestamp_millis_opt(ms)
                    .single()
                    .ok_or_else(|| de::Error::custom("invalid millis"));
            }
            let _: IgnoredAny = map.next_value()?;
        }
        Err(de::Error::custom("missing $numberLong inside $date"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Required {
        #[serde(deserialize_with = "deserialize")]
        ts: DateTime<Utc>,
    }

    #[derive(Debug, Deserialize)]
    struct Optional {
        #[serde(default, deserialize_with = "deserialize_opt")]
        ts: Option<DateTime<Utc>>,
    }

    #[test]
    fn required_accepts_rfc3339_string() {
        let v: Required = serde_json::from_str(r#"{"ts":"2024-04-27T12:00:00Z"}"#).unwrap();
        assert_eq!(v.ts.timestamp_millis(), 1_714_219_200_000);
    }

    #[test]
    fn required_accepts_extjson_v1_millis() {
        let v: Required = serde_json::from_str(r#"{"ts":{"$date":1714219200000}}"#).unwrap();
        assert_eq!(v.ts.timestamp_millis(), 1_714_219_200_000);
    }

    #[test]
    fn required_accepts_extjson_v2_wrapped() {
        let v: Required =
            serde_json::from_str(r#"{"ts":{"$date":{"$numberLong":"1714219200000"}}}"#).unwrap();
        assert_eq!(v.ts.timestamp_millis(), 1_714_219_200_000);
    }

    #[test]
    fn optional_accepts_null_and_missing() {
        let v: Optional = serde_json::from_str(r#"{"ts":null}"#).unwrap();
        assert!(v.ts.is_none());
        let v: Optional = serde_json::from_str(r#"{}"#).unwrap();
        assert!(v.ts.is_none());
    }

    #[test]
    fn optional_accepts_string_and_bson_forms() {
        let v: Optional = serde_json::from_str(r#"{"ts":"2024-04-27T12:00:00Z"}"#).unwrap();
        assert_eq!(v.ts.unwrap().timestamp_millis(), 1_714_219_200_000);
        let v: Optional = serde_json::from_str(r#"{"ts":{"$date":1714219200000}}"#).unwrap();
        assert_eq!(v.ts.unwrap().timestamp_millis(), 1_714_219_200_000);
    }
}
