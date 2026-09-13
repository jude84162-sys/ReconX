use async_trait::async_trait;
use chrono::Utc;
use reconx_core::{ReconError, ReconModule, Result};
use serde::{Deserialize, Serialize};

pub mod aggregator;
pub mod breachdir;
pub mod emailrep;
pub mod gravatar;
pub mod hibp;
pub mod risk;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailInput {
    pub email: String,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "Low"),
            RiskLevel::Medium => write!(f, "Medium"),
            RiskLevel::High => write!(f, "High"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachEntry {
    pub name: String,
    pub date: Option<String>,
    pub compromised_data: Vec<String>,
    pub sources: Vec<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationInfo {
    pub status: String,
    pub breach_count: u32,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GravatarInfo {
    pub found: bool,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachReport {
    pub email: String,
    pub scan_timestamp: String,
    pub risk_score: u8,
    pub risk_level: RiskLevel,
    pub total_breaches: u32,
    pub combined_confidence: f32,
    pub breaches: Vec<BreachEntry>,
    pub reputation: Option<ReputationInfo>,
    pub gravatar: Option<GravatarInfo>,
}

pub struct BreachModule;

#[async_trait]
impl ReconModule for BreachModule {
    type Input = EmailInput;
    type Output = BreachReport;

    async fn scan(&self, input: Self::Input) -> Result<Self::Output> {
        Ok(aggregator::scan_all(&input.email, input.timeout_secs).await)
    }

    fn name(&self) -> &'static str {
        "breach"
    }
}

impl BreachReport {
    pub fn as_csv_summary(&self) -> Vec<String> {
        vec![
            "email,scan_timestamp,risk_score,risk_level,total_breaches,combined_confidence".to_string(),
            format!(
                "{},{},{},{},{},{}",
                self.email,
                self.scan_timestamp,
                self.risk_score,
                self.risk_level,
                self.total_breaches,
                self.combined_confidence
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::{risk, BreachEntry, ReputationInfo, RiskLevel};

    #[test]
    fn risk_empty_is_low() {
        let (score, level) = risk::score(&[], None);
        assert_eq!(score, 0);
        assert_eq!(level, RiskLevel::Low);
    }

    #[test]
    fn risk_anchor_boundaries() {
        let entry = BreachEntry {
            name: "x".to_string(),
            date: None,
            compromised_data: vec!["password".to_string()],
            sources: vec!["hibp".to_string()],
            confidence: 1.0,
        };
        let first = risk::score(&[entry.clone()], None);
        assert!(matches!(first.1, RiskLevel::High));

        let rep = ReputationInfo {
            status: "suspicious".to_string(),
            breach_count: 5,
            sources: vec!["emailrep".to_string()],
        };
        let second = risk::score(&[entry], Some(&rep));
        assert!(matches!(second.1, RiskLevel::High));
    }
}
