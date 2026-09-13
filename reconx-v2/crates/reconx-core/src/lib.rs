use async_trait::async_trait;
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(thiserror::Error, Debug)]
pub enum ReconError {
    #[error("network error: {0}")]
    Network(String),
    #[error("API error: {0}")]
    Api(String),
    #[error("rate limited for {0} seconds")]
    RateLimited(u64),
    #[error("invalid email: {0}")]
    InvalidEmail(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ReconError>;

#[async_trait]
pub trait ReconModule: Send + Sync {
    type Input: Send;
    type Output: Send;

    async fn scan(&self, input: Self::Input) -> Result<Self::Output>;

    fn name(&self) -> &'static str;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult<T> {
    pub data: T,
    pub confidence: f32,
    pub sources: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Authorization {
    SelfOwned,
    PentestWithConsent {
        reason: String,
        consent_file: PathBuf,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub user_id: String,
    pub authorization: Authorization,
}

impl AuthContext {
    pub fn is_self_owned(&self) -> bool {
        matches!(self.authorization, Authorization::SelfOwned)
    }

    pub fn has_written_consent(&self) -> bool {
        matches!(
            self.authorization,
            Authorization::PentestWithConsent { ref consent_file, .. } if consent_file.exists()
        )
    }

    pub fn is_authorized(&self) -> bool {
        match &self.authorization {
            Authorization::SelfOwned => true,
            Authorization::PentestWithConsent { consent_file, .. } => consent_file.exists(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub action: String,
    pub target: String,
    pub authorization: String,
    pub result: String,
}

pub fn validate_email(email: &str) -> Result<String> {
    let trimmed = email.trim();
    let lowered = trimmed.to_ascii_lowercase();
    let pattern = Regex::new(r"(?i)^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$")
        .map_err(|e| ReconError::Parse(format!("failed to compile regex: {e}")))?;

    if trimmed.is_empty() || !pattern.is_match(trimmed) {
        return Err(ReconError::InvalidEmail(email.to_string()));
    }

    Ok(lowered)
}

#[cfg(test)]
mod tests {
    use super::validate_email;

    #[test]
    fn valid_email() {
        let email = validate_email("  Test.User+Alias@Example.COM ").unwrap();
        assert_eq!(email, "test.user+alias@example.com");
    }

    #[test]
    fn invalid_email() {
        let result = validate_email("not-an-email");
        assert!(result.is_err());
    }
}
