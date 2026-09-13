use chrono::Utc;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

pub fn init_tracing(verbose: bool) {
    let log_level = if verbose { "debug" } else { "info" };
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(log_level))
        .unwrap_or_else(|_| EnvFilter::new(log_level));
    let subscriber = fmt().with_env_filter(filter).with_target(false).without_time().finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

pub mod audit {
    use super::*;
    use reconx_core::AuditEntry;

    pub fn log_path() -> PathBuf {
        let mut path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push(".reconx");
        path.push("audit.log");
        path
    }

    pub fn record(entry: &AuditEntry) -> anyhow::Result<()> {
        let path = log_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let line = serde_json::to_string(entry)?;
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(file, "{line}")?;
        Ok(())
    }
}

pub mod retry {
    use reconx_core::Result;
    use tokio::time::{sleep, Duration};

    pub async fn with_retry<F, Fut, T>(max: u32, mut f: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut attempts = 0u32;
        let mut delay = Duration::from_millis(500);

        loop {
            match f().await {
                Ok(value) => return Ok(value),
                Err(err) => {
                    if attempts >= max {
                        return Err(err);
                    }
                    attempts += 1;
                    sleep(delay).await;
                    delay = match delay {
                        d if d == Duration::from_millis(500) => Duration::from_secs(1),
                        d if d == Duration::from_secs(1) => Duration::from_secs(2),
                        _ => Duration::from_secs(2),
                    };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::audit;
    use chrono::Utc;
    use reconx_core::{AuditEntry, Authorization};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn audit_entry_round_trip() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = audit::log_path();
        let entry = AuditEntry {
            timestamp: Utc::now(),
            user_id: format!("test-{unique}"),
            action: "scan".to_string(),
            target: "example.com".to_string(),
            authorization: Authorization::SelfOwned,
            result: "ok".to_string(),
        };

        audit::record(&entry).unwrap();
        let data = fs::read_to_string(path).unwrap();
        let last = data.lines().last().unwrap();
        assert!(last.contains("\"user_id\":\""));
    }
}
