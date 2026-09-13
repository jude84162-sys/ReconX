use reqwest::StatusCode;
use reconx_core::{ReconError, Result};
use serde::Deserialize;
use std::time::Duration;

use crate::{ReputationInfo, BreachEntry};

#[derive(Debug, Deserialize)]
struct EmailRepResponse {
    #[serde(rename = "reputation")]
    reputation: Option<f64>,
    #[serde(rename = "details")]
    details: Option<EmailRepDetails>,
}

#[derive(Debug, Deserialize)]
struct EmailRepDetails {
    #[serde(rename = "breaches")]
    breaches: Option<u32>,
    #[serde(rename = "suspicious")]
    suspicious: Option<bool>,
    #[serde(rename = "sources")]
    sources: Option<Vec<String>>,
}

pub async fn check(email: &str, timeout: u64) -> Result<Option<ReputationInfo>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .build()
        .map_err(|e| ReconError::Network(e.to_string()))?;

    let url = format!("https://emailrep.io/{email}");
    let response = client
        .get(&url)
        .header("User-Agent", "ReconX-v2/0.1")
        .send()
        .await
        .map_err(|e| ReconError::Network(e.to_string()))?;

    if response.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }

    if !response.status().is_success() {
        return Err(ReconError::Api(format!("EmailRep request failed: {}", response.status())));
    }

    let payload: EmailRepResponse = response
        .json()
        .await
        .map_err(|e| ReconError::Parse(format!("EmailRep parse error: {e}")))?;

    let details = payload.details.unwrap_or_default();
    let status = match details.suspicious {
        Some(true) => "suspicious".to_string(),
        _ if payload.reputation.unwrap_or(0.0) < 0.0 => "poor".to_string(),
        _ => "clean".to_string(),
    };

    Ok(Some(ReputationInfo {
        status,
        breach_count: details.breaches.unwrap_or(0),
        sources: details.sources.unwrap_or_default(),
    }))
}
