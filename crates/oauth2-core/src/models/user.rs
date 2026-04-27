#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub email: String,
    pub enabled: bool,
    /// User role: "admin" or "user" (default).
    #[serde(default = "default_role")]
    pub role: String,
    #[serde(deserialize_with = "dt_tolerant::deserialize")]
    pub created_at: DateTime<Utc>,
    #[serde(deserialize_with = "dt_tolerant::deserialize")]
    pub updated_at: DateTime<Utc>,
}

/// Tolerant deserializer for `chrono::DateTime<Utc>` that accepts every shape
/// MongoDB / BSON might present:
/// - RFC 3339 string (chrono's native form, what `Collection<User>::insert_one`
///   writes via chrono's default Serialize)
/// - BSON Date in binary mode (visited as `i64` millis since epoch)
/// - BSON Date in extended-JSON v1 (`{"$date": <millis>}`)
/// - BSON Date in extended-JSON v2 / canonical (`{"$date": {"$numberLong": "<ms>"}}`)
///
/// Why: MongoDB documents written via different code paths mix encodings —
/// fresh `insert_one` writes timestamps as BSON Strings (chrono default),
/// while historical `$set` updates that used `bson::DateTime` write BSON
/// Dates. Reading back through chrono's default deserializer fails with
/// "invalid type: map, expected an RFC 3339 formatted date and time string".
/// This module heals legacy rows transparently on read.
mod dt_tolerant {
    use chrono::{DateTime, TimeZone, Utc};
    use serde::de::{self, MapAccess, Visitor};
    use serde::Deserializer;
    use std::fmt;

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        d.deserialize_any(DtVisitor)
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
                let _: de::IgnoredAny = map.next_value()?;
            }
            Err(de::Error::custom("missing $date key in BSON Date object"))
        }
    }

    struct DateValueSeed;

    impl<'de> de::DeserializeSeed<'de> for DateValueSeed {
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
            // ISO-8601 / RFC 3339 form occasionally appears under $date too.
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
                let _: de::IgnoredAny = map.next_value()?;
            }
            Err(de::Error::custom("missing $numberLong inside $date"))
        }
    }
}

fn default_role() -> String {
    "user".to_string()
}

impl User {
    pub fn new(username: String, password_hash: String, email: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            username,
            password_hash,
            email,
            enabled: true,
            role: "user".to_string(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Check if the user has admin privileges.
    ///
    /// A user is admin if their `role` field is `"admin"` or their email appears
    /// in the `OAUTH2_ADMIN_EMAILS` environment variable (comma-separated list).
    /// Username alone never grants admin — set the role field in the database.
    pub fn is_admin(&self) -> bool {
        if self.role == "admin" {
            return true;
        }
        if let Ok(admin_emails) = std::env::var("OAUTH2_ADMIN_EMAILS") {
            let email_lower = self.email.to_lowercase();
            return admin_emails
                .split(',')
                .map(|e| e.trim().to_lowercase())
                .any(|e| e == email_lower);
        }
        false
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserCredentials {
    pub username: String,
    pub password: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_json_with_dates(created: &str, updated: &str) -> String {
        format!(
            r#"{{
                "id": "u1",
                "username": "alice",
                "password_hash": "x",
                "email": "a@b.test",
                "enabled": true,
                "role": "user",
                "created_at": {created},
                "updated_at": {updated}
            }}"#
        )
    }

    #[test]
    fn deserializes_rfc3339_string_dates() {
        let json =
            user_json_with_dates("\"2026-04-27T12:00:00Z\"", "\"2026-04-27T12:00:00+00:00\"");
        let user: User = serde_json::from_str(&json).expect("RFC 3339 strings should parse");
        assert_eq!(user.created_at.timestamp(), 1_777_291_200);
        assert_eq!(user.updated_at.timestamp(), 1_777_291_200);
    }

    #[test]
    fn deserializes_bson_extended_json_millis() {
        // BSON extended JSON v1 form: {"$date": <i64 millis>}
        let json =
            user_json_with_dates(r#"{"$date": 1714219200000}"#, r#"{"$date": 1714219200000}"#);
        let user: User = serde_json::from_str(&json).expect("BSON $date millis form should parse");
        assert_eq!(user.created_at.timestamp_millis(), 1_714_219_200_000);
        assert_eq!(user.updated_at.timestamp_millis(), 1_714_219_200_000);
    }

    #[test]
    fn deserializes_bson_extended_json_wrapped() {
        // BSON extended JSON v2 (canonical) form: {"$date": {"$numberLong": "<ms>"}}
        let json = user_json_with_dates(
            r#"{"$date": {"$numberLong": "1714219200000"}}"#,
            r#"{"$date": {"$numberLong": "1714219200000"}}"#,
        );
        let user: User =
            serde_json::from_str(&json).expect("BSON $date+$numberLong form should parse");
        assert_eq!(user.created_at.timestamp_millis(), 1_714_219_200_000);
        assert_eq!(user.updated_at.timestamp_millis(), 1_714_219_200_000);
    }

    #[test]
    fn mixed_encodings_round_trip() {
        // Real-world corrupted shape: insert_one wrote String, $set later wrote BSON Date.
        let json = user_json_with_dates("\"2026-04-27T12:00:00Z\"", r#"{"$date": 1714219200000}"#);
        let user: User = serde_json::from_str(&json).expect("mixed encodings should parse");
        assert_eq!(user.created_at.timestamp(), 1_777_291_200);
        assert_eq!(user.updated_at.timestamp_millis(), 1_714_219_200_000);
    }
}
