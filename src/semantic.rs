use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{Action, PROTOCOL_VERSION, Rect, hash_serializable};

pub const MAX_SEMANTIC_ELEMENTS: usize = 4_096;
pub const MAX_SEMANTIC_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_SEMANTIC_OBSERVATION_AGE_MS: i64 = 30_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticBackend {
    Accessibility,
    Dom,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticProvenance {
    pub backend: SemanticBackend,
    pub backend_name: String,
    pub process_id: u32,
    pub process_generation: String,
    pub window_id: String,
    pub document_id: Option<String>,
    pub display_geometry_hash: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Actionability {
    pub visible: bool,
    pub enabled: bool,
    pub unambiguous: bool,
    pub stable: bool,
    pub receives_events: bool,
    pub invokable: bool,
    pub editable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticElement {
    pub tag: String,
    pub element_id: String,
    pub parent_id: Option<String>,
    pub fingerprint_hash: String,
    pub role: String,
    pub name: Option<String>,
    pub bounds: Option<Rect>,
    pub actionability: Actionability,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticObservation {
    pub protocol_version: u16,
    pub observation_id: String,
    pub generation: u64,
    pub provenance: SemanticProvenance,
    pub observed_at_ms: i64,
    pub expires_at_ms: i64,
    pub truncated: bool,
    pub elements: Vec<SemanticElement>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticTargetRef {
    pub observation_id: String,
    pub generation: u64,
    pub provenance_hash: String,
    pub element_id: String,
    pub fingerprint_hash: String,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SemanticError {
    #[error("invalid semantic observation")]
    InvalidObservation,
    #[error("semantic observation is stale")]
    StaleObservation,
    #[error("semantic target was not found")]
    TargetNotFound,
    #[error("semantic target is ambiguous")]
    AmbiguousTarget,
    #[error("semantic target changed")]
    StaleTarget,
    #[error("semantic target is not actionable")]
    TargetNotActionable,
    #[error("action has no semantic route")]
    UnsupportedAction,
}

impl SemanticObservation {
    pub fn validate(&self, now_ms: i64) -> Result<(), SemanticError> {
        if self.protocol_version != PROTOCOL_VERSION
            || !is_hash(&self.observation_id)
            || self.generation == 0
            || self.observed_at_ms <= 0
            || self.expires_at_ms <= self.observed_at_ms
            || self.expires_at_ms.saturating_sub(self.observed_at_ms)
                > MAX_SEMANTIC_OBSERVATION_AGE_MS
            || now_ms < self.observed_at_ms
            || self.elements.len() > MAX_SEMANTIC_ELEMENTS
            || !valid_provenance(&self.provenance)
            || serde_json::to_vec(self)
                .map_err(|_| SemanticError::InvalidObservation)?
                .len()
                > MAX_SEMANTIC_SNAPSHOT_BYTES
        {
            return Err(SemanticError::InvalidObservation);
        }
        if now_ms >= self.expires_at_ms {
            return Err(SemanticError::StaleObservation);
        }

        let mut elements = BTreeMap::new();
        let mut tags = BTreeSet::new();
        for element in &self.elements {
            if !valid_element(element) {
                return Err(SemanticError::InvalidObservation);
            }
            if !tags.insert(element.tag.as_str()) {
                return Err(SemanticError::AmbiguousTarget);
            }
            if elements
                .insert(element.element_id.as_str(), element)
                .is_some()
            {
                return Err(SemanticError::AmbiguousTarget);
            }
        }
        for element in &self.elements {
            if element.parent_id.as_deref().is_some_and(|parent| {
                parent == element.element_id || !elements.contains_key(parent)
            }) {
                return Err(SemanticError::InvalidObservation);
            }
            let mut ancestors = BTreeSet::new();
            let mut current = element.parent_id.as_deref();
            while let Some(id) = current {
                if !ancestors.insert(id) {
                    return Err(SemanticError::InvalidObservation);
                }
                current = elements
                    .get(id)
                    .and_then(|parent| parent.parent_id.as_deref());
            }
        }
        Ok(())
    }

    pub fn provenance_hash(&self) -> Result<String, SemanticError> {
        hash_value(&(
            self.protocol_version,
            &self.observation_id,
            self.generation,
            &self.provenance,
            self.observed_at_ms,
            self.expires_at_ms,
        ))
    }

    pub fn target(&self, tag: &str) -> Result<SemanticTargetRef, SemanticError> {
        let mut matches = self.elements.iter().filter(|element| element.tag == tag);
        let element = matches.next().ok_or(SemanticError::TargetNotFound)?;
        if matches.next().is_some() {
            return Err(SemanticError::AmbiguousTarget);
        }
        Ok(SemanticTargetRef {
            observation_id: self.observation_id.clone(),
            generation: self.generation,
            provenance_hash: self.provenance_hash()?,
            element_id: element.element_id.clone(),
            fingerprint_hash: element.fingerprint_hash.clone(),
        })
    }

    pub fn resolve<'a>(
        &'a self,
        target: &SemanticTargetRef,
        now_ms: i64,
    ) -> Result<&'a SemanticElement, SemanticError> {
        self.validate(now_ms)?;
        if target.observation_id != self.observation_id
            || target.generation != self.generation
            || target.provenance_hash != self.provenance_hash()?
            || !is_hash(&target.element_id)
            || !is_hash(&target.fingerprint_hash)
        {
            return Err(SemanticError::StaleTarget);
        }
        let mut matches = self
            .elements
            .iter()
            .filter(|element| element.element_id == target.element_id);
        let element = matches.next().ok_or(SemanticError::TargetNotFound)?;
        if matches.next().is_some() {
            return Err(SemanticError::AmbiguousTarget);
        }
        if element.fingerprint_hash != target.fingerprint_hash {
            return Err(SemanticError::StaleTarget);
        }
        Ok(element)
    }
}

pub fn route_action<'a>(
    action: &Action,
    observation: &'a SemanticObservation,
    target: &SemanticTargetRef,
    now_ms: i64,
) -> Result<&'a SemanticElement, SemanticError> {
    let element = observation.resolve(target, now_ms)?;
    if semantic_actionable(action, &element.actionability)? {
        return Ok(element);
    }
    Err(SemanticError::TargetNotActionable)
}

pub fn opaque_element_id(
    observation_id: &str,
    backend_element_id: &str,
) -> Result<String, SemanticError> {
    if !is_hash(observation_id) || !valid_text(backend_element_id, 1, 2_048) {
        return Err(SemanticError::InvalidObservation);
    }
    Ok(hash_bytes(
        [
            observation_id.as_bytes(),
            b"\0",
            backend_element_id.as_bytes(),
        ]
        .concat(),
    ))
}

pub fn semantic_tag(index: usize) -> Result<String, SemanticError> {
    if index >= MAX_SEMANTIC_ELEMENTS {
        return Err(SemanticError::InvalidObservation);
    }
    Ok(format!("e{index}"))
}

pub fn semantic_fingerprint<T: Serialize>(value: &T) -> Result<String, SemanticError> {
    hash_value(value)
}

fn semantic_actionable(
    action: &Action,
    actionability: &Actionability,
) -> Result<bool, SemanticError> {
    let base = actionability.visible
        && actionability.enabled
        && actionability.unambiguous
        && actionability.stable;
    match action {
        Action::Invoke => Ok(base && actionability.invokable),
        Action::SetValue { .. } => Ok(base && actionability.editable),
        _ => Err(SemanticError::UnsupportedAction),
    }
}

fn valid_provenance(provenance: &SemanticProvenance) -> bool {
    provenance.process_id > 0
        && valid_text(&provenance.backend_name, 1, 128)
        && valid_text(&provenance.process_generation, 1, 256)
        && valid_text(&provenance.window_id, 1, 512)
        && is_hash(&provenance.display_geometry_hash)
        && match provenance.backend {
            SemanticBackend::Accessibility => provenance.document_id.is_none(),
            SemanticBackend::Dom => provenance
                .document_id
                .as_deref()
                .is_some_and(|value| valid_text(value, 1, 512)),
        }
}

fn valid_element(element: &SemanticElement) -> bool {
    valid_tag(&element.tag)
        && is_hash(&element.element_id)
        && is_hash(&element.fingerprint_hash)
        && element.parent_id.as_deref().is_none_or(is_hash)
        && valid_text(&element.role, 1, 128)
        && element
            .name
            .as_deref()
            .is_none_or(|value| valid_text(value, 0, 1_024))
        && element
            .bounds
            .is_none_or(|bounds| bounds.width > 0 && bounds.height > 0)
}

fn valid_tag(value: &str) -> bool {
    value.strip_prefix('e').is_some_and(|index| {
        !index.is_empty() && index.len() <= 4 && index.bytes().all(|b| b.is_ascii_digit())
    })
}

fn valid_text(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len())
        && !value.chars().any(char::is_control)
        && !value.trim().is_empty()
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hash_value<T: Serialize>(value: &T) -> Result<String, SemanticError> {
    hash_serializable(value).map_err(|_| SemanticError::InvalidObservation)
}

fn hash_bytes(value: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(value.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation() -> SemanticObservation {
        let observation_id = "1".repeat(64);
        SemanticObservation {
            protocol_version: PROTOCOL_VERSION,
            observation_id: observation_id.clone(),
            generation: 7,
            provenance: SemanticProvenance {
                backend: SemanticBackend::Dom,
                backend_name: "chromium-cdp".to_string(),
                process_id: 42,
                process_generation: "process-1".to_string(),
                window_id: "window-1".to_string(),
                document_id: Some("document-1".to_string()),
                display_geometry_hash: "2".repeat(64),
            },
            observed_at_ms: 1_000,
            expires_at_ms: 31_000,
            truncated: false,
            elements: vec![SemanticElement {
                tag: semantic_tag(0).unwrap(),
                element_id: opaque_element_id(&observation_id, "backend-node-1").unwrap(),
                parent_id: None,
                fingerprint_hash: semantic_fingerprint(&("button", "Save", 1)).unwrap(),
                role: "button".to_string(),
                name: Some("Save".to_string()),
                bounds: Some(Rect {
                    x: 10,
                    y: 20,
                    width: 100,
                    height: 30,
                }),
                actionability: Actionability {
                    visible: true,
                    enabled: true,
                    unambiguous: true,
                    stable: true,
                    receives_events: true,
                    invokable: true,
                    editable: false,
                },
            }],
        }
    }

    #[test]
    fn semantic_target_is_generation_and_fingerprint_fenced() {
        let observation = observation();
        observation.validate(2_000).unwrap();
        let mut target = observation.target(&observation.elements[0].tag).unwrap();
        assert_eq!(
            observation.resolve(&target, 2_000).unwrap(),
            &observation.elements[0]
        );
        target.generation += 1;
        assert_eq!(
            observation.resolve(&target, 2_000),
            Err(SemanticError::StaleTarget)
        );
        target.generation = observation.generation;
        target.fingerprint_hash = "f".repeat(64);
        assert_eq!(
            observation.resolve(&target, 2_000),
            Err(SemanticError::StaleTarget)
        );
    }

    #[test]
    fn semantic_routes_require_actionable_stable_elements() {
        let action = Action::Invoke;
        for rejected_flag in 0..5 {
            let mut observation = observation();
            let actionability = &mut observation.elements[0].actionability;
            match rejected_flag {
                0 => actionability.visible = false,
                1 => actionability.enabled = false,
                2 => actionability.unambiguous = false,
                3 => actionability.stable = false,
                _ => actionability.invokable = false,
            }
            let target = observation.target(&observation.elements[0].tag).unwrap();
            assert_eq!(
                route_action(&action, &observation, &target, 2_000),
                Err(SemanticError::TargetNotActionable)
            );
        }

        let observation = observation();
        let target = observation.target(&observation.elements[0].tag).unwrap();
        assert_eq!(
            route_action(
                &Action::SetValue {
                    value: "secret".to_string(),
                },
                &observation,
                &target,
                2_000,
            ),
            Err(SemanticError::TargetNotActionable)
        );
    }

    #[test]
    fn duplicate_and_cyclic_elements_are_rejected() {
        let mut duplicate = observation();
        duplicate.elements.push(duplicate.elements[0].clone());
        assert_eq!(
            duplicate.validate(2_000),
            Err(SemanticError::AmbiguousTarget)
        );

        let mut cyclic = observation();
        let second_id = opaque_element_id(&cyclic.observation_id, "backend-node-2").unwrap();
        cyclic.elements[0].parent_id = Some(second_id.clone());
        cyclic.elements.push(SemanticElement {
            tag: semantic_tag(1).unwrap(),
            element_id: second_id,
            parent_id: Some(cyclic.elements[0].element_id.clone()),
            ..cyclic.elements[0].clone()
        });
        assert_eq!(
            cyclic.validate(2_000),
            Err(SemanticError::InvalidObservation)
        );
    }
}
