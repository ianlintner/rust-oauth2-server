//! RFC 8693 delegation actor (`act`) chain modelling.

use serde::{Deserialize, Serialize};

pub const SUB_PROFILE_USER: &str = "user";
pub const SUB_PROFILE_SERVICE: &str = "service";
pub const SUB_PROFILE_AI_AGENT: &str = "ai_agent";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub sub: String,
    pub iss: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<Actor>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActorChainError {
    MissingSub,
    MissingIss,
    DepthExceeded { depth: usize, max: usize },
    Malformed(String),
}

impl std::fmt::Display for ActorChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSub => write!(f, "actor chain level is missing a string `sub` claim"),
            Self::MissingIss => write!(f, "actor chain level is missing a string `iss` claim"),
            Self::DepthExceeded { depth, max } => {
                write!(f, "actor chain depth {depth} exceeds the maximum of {max}")
            }
            Self::Malformed(reason) => write!(f, "malformed actor chain: {reason}"),
        }
    }
}

impl Actor {
    pub fn new(sub: impl Into<String>, iss: impl Into<String>) -> Self {
        Self {
            sub: sub.into(),
            iss: iss.into(),
            sub_profile: None,
            act: None,
        }
    }

    pub fn with_profile(mut self, profile: &str) -> Self {
        self.sub_profile = Some(profile.to_string());
        self
    }

    /// Nest `inner` as this actor's `act`, leaving `inner` otherwise unchanged.
    pub fn with_inner(mut self, inner: Actor) -> Self {
        self.act = Some(Box::new(inner));
        self
    }

    /// Number of levels in the chain; `1` when there is no nested actor.
    pub fn depth(&self) -> usize {
        let mut depth = 1;
        let mut level = self;
        while let Some(inner) = level.act.as_deref() {
            depth += 1;
            level = inner;
        }
        depth
    }

    pub fn matches(&self, iss: &str, sub: &str) -> bool {
        self.iss == iss && self.sub == sub
    }

    /// Parse an `act` claim value into a chain. Every level must be a JSON
    /// object carrying string `sub` and `iss` members.
    pub fn from_value(v: &serde_json::Value) -> Result<Actor, ActorChainError> {
        // Walk the chain outermost-first, collecting each level, then rebuild
        // it innermost-first. Iterative on purpose: `act` nesting is attacker
        // controlled, so recursion here would be a stack-overflow risk.
        let mut levels: Vec<Actor> = Vec::new();
        let mut current = v;
        loop {
            let obj = current
                .as_object()
                .ok_or_else(|| Self::malformed("actor level is not a JSON object"))?;
            let sub = obj
                .get("sub")
                .and_then(serde_json::Value::as_str)
                .ok_or(ActorChainError::MissingSub)?;
            let iss = obj
                .get("iss")
                .and_then(serde_json::Value::as_str)
                .ok_or(ActorChainError::MissingIss)?;
            let sub_profile = match obj.get("sub_profile") {
                None | Some(serde_json::Value::Null) => None,
                Some(p) => Some(
                    p.as_str()
                        .ok_or_else(|| Self::malformed("actor sub_profile is not a string"))?
                        .to_string(),
                ),
            };
            levels.push(Actor {
                sub: sub.to_string(),
                iss: iss.to_string(),
                sub_profile,
                act: None,
            });
            match obj.get("act") {
                None | Some(serde_json::Value::Null) => break,
                Some(inner) => current = inner,
            }
        }

        let mut chain: Option<Actor> = None;
        for mut level in levels.into_iter().rev() {
            level.act = chain.map(Box::new);
            chain = Some(level);
        }
        // The loop above pushes at least one level before it can break.
        chain.ok_or_else(|| Self::malformed("actor chain is empty"))
    }

    /// Render the chain as an `act` claim value. Built by hand rather than via
    /// `serde_json::to_value` so it stays infallible.
    pub fn to_value(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "sub".to_string(),
            serde_json::Value::String(self.sub.clone()),
        );
        map.insert(
            "iss".to_string(),
            serde_json::Value::String(self.iss.clone()),
        );
        if let Some(profile) = &self.sub_profile {
            map.insert(
                "sub_profile".to_string(),
                serde_json::Value::String(profile.clone()),
            );
        }
        if let Some(inner) = &self.act {
            map.insert("act".to_string(), inner.to_value());
        }
        serde_json::Value::Object(map)
    }

    /// Reject chains deeper than `max_depth` levels.
    pub fn validate_chain(&self, max_depth: usize) -> Result<(), ActorChainError> {
        let depth = self.depth();
        if depth > max_depth {
            return Err(ActorChainError::DepthExceeded {
                depth,
                max: max_depth,
            });
        }
        Ok(())
    }

    fn malformed(reason: &str) -> ActorChainError {
        ActorChainError::Malformed(reason.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn agent_chain() -> Actor {
        // outermost = the AI agent acting for a service acting for a user
        Actor::new("agent-1", "https://agents.test")
            .with_profile(SUB_PROFILE_AI_AGENT)
            .with_inner(
                Actor::new("svc-1", "https://svc.test")
                    .with_profile(SUB_PROFILE_SERVICE)
                    .with_inner(Actor::new("alice", "https://idp.test")),
            )
    }

    #[test]
    fn depth_is_one_for_single_actor() {
        assert_eq!(Actor::new("alice", "https://idp.test").depth(), 1);
    }

    #[test]
    fn depth_counts_nested_levels() {
        assert_eq!(agent_chain().depth(), 3);
    }

    #[test]
    fn with_inner_preserves_the_nested_actor_unchanged() {
        let inner = Actor::new("svc-1", "https://svc.test").with_profile(SUB_PROFILE_SERVICE);
        let outer = Actor::new("agent-1", "https://agents.test").with_inner(inner.clone());
        assert_eq!(outer.act.as_deref(), Some(&inner));
    }

    #[test]
    fn matches_compares_both_iss_and_sub() {
        let a = Actor::new("alice", "https://idp.test");
        assert!(a.matches("https://idp.test", "alice"));
        assert!(!a.matches("https://other.test", "alice"));
        assert!(!a.matches("https://idp.test", "bob"));
    }

    #[test]
    fn from_value_rejects_non_object() {
        assert_eq!(
            Actor::from_value(&json!("not-an-object")),
            Err(ActorChainError::Malformed(
                "actor level is not a JSON object".to_string()
            ))
        );
    }

    #[test]
    fn from_value_rejects_missing_sub() {
        assert_eq!(
            Actor::from_value(&json!({ "iss": "https://idp.test" })),
            Err(ActorChainError::MissingSub)
        );
    }

    #[test]
    fn from_value_rejects_missing_iss() {
        assert_eq!(
            Actor::from_value(&json!({ "sub": "alice" })),
            Err(ActorChainError::MissingIss)
        );
    }

    #[test]
    fn from_value_rejects_non_string_sub() {
        assert_eq!(
            Actor::from_value(&json!({ "sub": 42, "iss": "https://idp.test" })),
            Err(ActorChainError::MissingSub)
        );
    }

    #[test]
    fn from_value_rejects_missing_iss_at_a_nested_level() {
        let v = json!({
            "sub": "agent-1",
            "iss": "https://agents.test",
            "act": { "sub": "alice" }
        });
        assert_eq!(Actor::from_value(&v), Err(ActorChainError::MissingIss));
    }

    #[test]
    fn from_value_rejects_non_object_nested_level() {
        let v = json!({
            "sub": "agent-1",
            "iss": "https://agents.test",
            "act": "alice"
        });
        assert_eq!(
            Actor::from_value(&v),
            Err(ActorChainError::Malformed(
                "actor level is not a JSON object".to_string()
            ))
        );
    }

    #[test]
    fn from_value_rejects_non_string_sub_profile() {
        assert_eq!(
            Actor::from_value(&json!({
                "sub": "alice",
                "iss": "https://idp.test",
                "sub_profile": 7
            })),
            Err(ActorChainError::Malformed(
                "actor sub_profile is not a string".to_string()
            ))
        );
    }

    #[test]
    fn to_value_omits_absent_optional_fields() {
        let v = Actor::new("alice", "https://idp.test").to_value();
        assert_eq!(v, json!({ "sub": "alice", "iss": "https://idp.test" }));
    }

    #[test]
    fn json_round_trip_preserves_nested_order() {
        let chain = agent_chain();
        let v = chain.to_value();
        assert_eq!(
            v,
            json!({
                "sub": "agent-1",
                "iss": "https://agents.test",
                "sub_profile": SUB_PROFILE_AI_AGENT,
                "act": {
                    "sub": "svc-1",
                    "iss": "https://svc.test",
                    "sub_profile": SUB_PROFILE_SERVICE,
                    "act": { "sub": "alice", "iss": "https://idp.test" }
                }
            })
        );
        assert_eq!(Actor::from_value(&v), Ok(chain));
    }

    #[test]
    fn serde_round_trip_matches_to_value() {
        let chain = agent_chain();
        let text = serde_json::to_string(&chain).expect("serialize");
        let back: Actor = serde_json::from_str(&text).expect("deserialize");
        assert_eq!(back, chain);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&text).expect("as value"),
            chain.to_value()
        );
    }

    #[test]
    fn validate_chain_accepts_depth_at_the_maximum() {
        assert_eq!(agent_chain().validate_chain(3), Ok(()));
        assert_eq!(agent_chain().validate_chain(4), Ok(()));
    }

    #[test]
    fn validate_chain_rejects_depth_five_when_max_is_four() {
        let mut chain = Actor::new("l0", "https://l0.test");
        for i in 1..5 {
            chain = Actor::new(format!("l{i}"), format!("https://l{i}.test")).with_inner(chain);
        }
        assert_eq!(chain.depth(), 5);
        assert_eq!(
            chain.validate_chain(4),
            Err(ActorChainError::DepthExceeded { depth: 5, max: 4 })
        );
    }

    #[test]
    fn display_renders_each_variant() {
        assert_eq!(
            ActorChainError::MissingSub.to_string(),
            "actor chain level is missing a string `sub` claim"
        );
        assert_eq!(
            ActorChainError::MissingIss.to_string(),
            "actor chain level is missing a string `iss` claim"
        );
        assert_eq!(
            ActorChainError::DepthExceeded { depth: 5, max: 4 }.to_string(),
            "actor chain depth 5 exceeds the maximum of 4"
        );
        assert_eq!(
            ActorChainError::Malformed("bad".to_string()).to_string(),
            "malformed actor chain: bad"
        );
    }
}
