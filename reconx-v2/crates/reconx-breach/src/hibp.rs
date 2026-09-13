#![allow(unused_variables)]
#![allow(dead_code)]
use reconx_core::{ReconError, Result};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, USER_AGENT};
use reqwest::StatusCode;
use serde::Deserialize;
use std::time::Duration;

use crate::BreachEntry;

#[derive(Debug, Deserialize)]
struct HibpBreach {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Title")]
    title: Option<String>,
    #[serde(rename = "BreachDate")]
    breach_date: Option<String>,
    #[serde(rename = "DataClasses")]
    data_classes: Vec<String>,
}

pub async fn check(email: &str, timeout: u64) -> Result<Vec<BreachEntry>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .build()
        .map_err(|e| ReconError::Network(e.to_string()))?;

    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static("ReconX-v2/0.1 (+https://github.com/jude84162-sys/ReconX)"),
    );
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

    if let Ok(api_key) = std::env::var("HIBP_API_KEY") {
        if !api_key.trim().is_empty() {
            let header_value = HeaderValue::from_str(&api_key)
                .map_err(|e| ReconError::Parse(format!("invalid HIBP API key: {e}")))?;
            headers.insert("hibp-api-key", header_value);
        }
    }

    let url = format!("https://haveibeenpwned.com/api/v3/breachedaccount/{email}");
    let response = client
        .get(&url)
        .headers(headers)
        .send()
        .await
        .map_err(|e| ReconError::Network(e.to_string()))?;

    match response.status() {
        StatusCode::NOT_FOUND => Ok(vec![]),
        StatusCode::TOO_MANY_REQUESTS => Err(ReconError::RateLimited(60)),
        code if code.is_server_error() => {
            Err(ReconError::Api(format!("HIBP server error: {code}")))
        }
        code if !code.is_success() => Err(ReconError::Api(format!("HIBP request failed: {code}"))),
        _ => {
            let items: Vec<HibpBreach> = response
                .json()
                .await
                .map_err(|e| ReconError::Parse(format!("HIBP parse error: {e}")))?;

            Ok(items
                .into_iter()
                .map(|item| BreachEntry {
                    name: item.title.clone().unwrap_or_else(|| item.name.clone()),
                    date: item.breach_date,
                    compromised_data: item.data_classes,
                    sources: vec!["HIBP".to_string()],
                    confidence: 0.95,
                })
                .collect())
        }
    }
}
