use chrono::Utc;
use reconx_core::{ReconError, Result};

use crate::{
    breachdir, emailrep, gravatar, hibp, risk, BreachEntry, BreachReport, EmailInput, GravatarInfo,
    ReputationInfo, RiskLevel,
};

pub async fn scan_all(email: &str, timeout_secs: u64) -> BreachReport {
    let mut merged = Vec::new();
    let reputation = match emailrep::check(email, timeout_secs).await {
        Ok(rep) => rep,
        Err(_) => None,
    };

    let gravatar = match gravatar::check(email, timeout_secs).await {
        Ok(info) => info,
        Err(_) => Some(GravatarInfo {
            found: false,
            display_name: None,
        }),
    };

    match hibp::check(email, timeout_secs).await {
        Ok(items) => merged.extend(items),
        Err(_) => {}
    }

    match breachdir::check(email, timeout_secs).await {
        Ok(items) => merged.extend(items),
        Err(_) => {}
    }

    let total_breaches = merged.len() as u32;
    let combined_confidence = merged.iter().map(|entry| entry.confidence).sum::<f32>() / merged.len().max(1) as f32;
    let (risk_score, risk_level) = risk::score(&merged, reputation.as_ref());
    let adjusted = if !merged.is_empty() {
        risk_score.saturating_add((combined_confidence * 10.0) as u8)
    } else {
        risk_score
    };

    BreachReport {
        email: email.to_string(),
        scan_timestamp: Utc::now().to_rfc3339(),
        risk_score: adjusted.min(100),
        risk_level: if adjusted >= 80 { RiskLevel::High } else if adjusted >= 35 { RiskLevel::Medium } else { RiskLevel::Low },
        total_breaches,
        combined_confidence,
        breaches: merged,
        reputation,
        gravatar,
    }
}
