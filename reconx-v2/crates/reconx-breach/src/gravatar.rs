use reqwest::StatusCode;
use reconx_core::{ReconError, Result};
use serde::Deserialize;
use std::time::Duration;

use crate::GravatarInfo;

#[derive(Debug, Deserialize)]
struct GravatarResponse {
    #[serde(rename = "entry")]
    entry: Vec<GravatarEntry>,
}

#[derive(Debug, Deserialize)]
struct GravatarEntry {
    #[serde(rename = "displayName")]
    display_name: Option<String>,
}

pub async fn check(email: &str, timeout: u64) -> Result<Option<GravatarInfo>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .build()
        .map_err(|e| ReconError::Network(e.to_string()))?;

    let hash = md5::compute(email.trim().to_ascii_lowercase());
    let url = format!("https://en.gravatar.com/{:x}.json", hash);
    let response = client
        .get(&url)
        .header("User-Agent", "ReconX-v2/0.1")
        .send()
        .await
        .map_err(|e| ReconError::Network(e.to_string()))?;

    if response.status() == StatusCode::NOT_FOUND {
        return Ok(Some(GravatarInfo {
            found: false,
            display_name: None,
        }));
    }

    if !response.status().is_success() {
        return Err(ReconError::Api(format!("Gravatar request failed: {}", response.status())));
    }

    let payload: GravatarResponse = response
        .json()
        .await
        .map_err(|e| ReconError::Parse(format!("Gravatar parse error: {e}")))?;

    let display_name = payload.entry.into_iter().next().and_then(|entry| entry.display_name);
    Ok(Some(GravatarInfo {
        found: display_name.is_some(),
        display_name,
    }))
}
