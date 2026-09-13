#![allow(unused_variables)]
#![allow(dead_code)]
use crate::{BreachEntry, GravatarInfo, ReputationInfo, RiskLevel};

pub fn score(breaches: &[BreachEntry], reputation: Option<&ReputationInfo>) -> (u8, RiskLevel) {
    let mut score = breaches.iter().fold(0u8, |acc, item| {
        let mut item_score = 10u8;
        if item
            .compromised_data
            .iter()
            .any(|value| value.to_ascii_lowercase().contains("password"))
        {
            item_score += 25;
        }
        if item
            .compromised_data
            .iter()
            .any(|value| value.to_ascii_lowercase().contains("email"))
        {
            item_score += 10;
        }
        if item
            .sources
            .iter()
            .any(|source| source.to_ascii_lowercase().contains("hibp"))
        {
            item_score += 12;
        }
        acc.saturating_add(item_score.min(45))
    });

    if let Some(rep) = reputation {
        if rep.status == "suspicious" {
            score = score.saturating_add(20);
        }
        if rep.breach_count >= 3 {
            score = score.saturating_add(15);
        }
    }

    if score >= 80 {
        (score.min(100), RiskLevel::High)
    } else if score >= 35 {
        (score.min(100), RiskLevel::Medium)
    } else {
        (score.min(100), RiskLevel::Low)
    }
}

pub fn with_gravatar(_gravatar: Option<&GravatarInfo>) -> u8 {
    0
}
