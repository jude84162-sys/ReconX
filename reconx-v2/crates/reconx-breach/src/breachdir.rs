#![allow(unused_variables)]
#![allow(dead_code)]
use reconx_core::{ReconError, Result};
use reqwest::StatusCode;
use serde::Deserialize;
use std::time::Duration;

use crate::BreachEntry;

#[derive(Debug, Deserialize)]
struct BreachDirRecord {
    #[serde(rename = "name")]
    name: String,
    #[serde(rename = "date")]
    date: Option<String>,
    #[serde(rename = "description")]
    description: Option<String>,
    #[serde(rename = "data_classes")]
    data_classes: Vec<String>,
}

pub async fn check(email: &str, timeout: u64) -> Result<Vec<BreachEntry>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .build()
        .map_err(|e| ReconError::Network(e.to_string()))?;

    let url = format!("https://breachdirectory.org/api/search?email={email}");
    let response = client
        .get(&url)
        .header("Accept", "application/json")
        .header("User-Agent", "ReconX-v2/0.1")
        .send()
        .await
        .map_err(|e| ReconError::Network(e.to_string()))?;

    if response.status() == StatusCode::NOT_FOUND {
        return Ok(vec![]);
    }

    if !response.status().is_success() {
        return Err(ReconError::Api(format!(
            "BreachDirectory request failed: {}",
            response.status()
        )));
    }

    let payload: Vec<BreachDirRecord> = response
        .json()
        .await
        .map_err(|e| ReconError::Parse(format!("BreachDirectory parse error: {e}")))?;

    Ok(payload
        .into_iter()
        .map(|entry| BreachEntry {
            name: entry.name,
            date: entry.date,
            compromised_data: entry.data_classes,
            sources: vec!["BreachDirectory".to_string()],
            confidence: 0.82,
        })
        .collect())
}
