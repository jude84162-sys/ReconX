use std::path::PathBuf;
use std::process::ExitCode;
use clap::{Parser, Subcommand, ValueEnum};
use reconx_breach::{BreachModule, BreachReport, EmailInput};
use reconx_core::{validate_email, AuditEntry, ReconModule};

#[derive(Parser)]
#[command(name = "reconx", version, about = "ReconX v2 OSINT")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Email {
        email: String,
        #[arg(long)]
        self_owned: bool,
        #[arg(long)]
        authorized_for: Option<String>,
        #[arg(long)]
        consent_file: Option<PathBuf>,
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Txt)]
        output: OutputFormat,
        #[arg(short, long)]
        file: Option<PathBuf>,
        #[arg(long)]
        verbose: bool,
        #[arg(long)]
        breaches_only: bool,
        #[arg(long, default_value_t = 10)]
        timeout: u64,
    },
}

#[derive(ValueEnum, Clone, Copy)]
enum OutputFormat {
    Txt,
    Json,
    Csv,
}

#[tokio::main]
async fn main() -> ExitCode {
    let _ = dotenv::dotenv();
    let cli = Cli::parse();
    match cli.command {
        Commands::Email {
            email,
            self_owned,
            authorized_for,
            consent_file,
            output,
            file,
            verbose,
            breaches_only,
            timeout,
        } => {
            reconx_common::init_tracing(verbose);
            let email = match validate_email(&email) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("Invalid: {}", e);
                    return ExitCode::from(2);
                }
            };
            if !self_owned {
                if authorized_for.is_none() {
                    eprintln!("Requires --self or --authorized-for");
                    return ExitCode::from(2);
                }
                if consent_file.is_none() {
                    eprintln!("Needs --consent-file");
                    return ExitCode::from(2);
                }
            }
            let input = EmailInput {
                email: email.clone(),
                timeout_secs: timeout,
            };
            let report = match BreachModule.scan(input).await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Failed: {}", e);
                    return ExitCode::from(1);
                }
            };
            let rendered = match output {
                OutputFormat::Json => serde_json::to_string_pretty(&report).unwrap_or_default(),
                OutputFormat::Csv => render_csv(&report),
                OutputFormat::Txt => render_txt(&report),
            };
            if let Some(path) = file {
                if let Err(e) = std::fs::write(&path, &rendered) {
                    eprintln!("Write: {}", e);
                    return ExitCode::from(1);
                }
                println!("Written: {}", path.display());
            } else {
                println!("{}", rendered);
            }
            let _ = reconx_common::audit::record(&AuditEntry {
                timestamp: chrono::Utc::now(),
                user_id: std::env::var("USER").unwrap_or_else(|_| "user".into()),
                action: "email_scan".into(),
                target: email,
                authorization: if self_owned {
                    "self".to_string()
                } else {
                    format!("auth:{}", authorized_for.unwrap_or_default())
                },
                result: format!("{} breaches", report.total_breaches),
            });
            ExitCode::SUCCESS
        }
    }
}

fn render_csv(r: &BreachReport) -> String {
    let mut s = String::new();
    s.push_str("email,risk_score,risk_level,total\n");
    s.push_str(&format!(
        "{},{},{:?},{}\n\nname,date,sources,conf\n",
        r.email, r.risk_score, r.risk_level, r.total_breaches
    ));
    for b in &r.breaches {
        s.push_str(&format!(
            "{},{},{},{:.2}\n",
            b.name,
            b.date.as_deref().unwrap_or(""),
            b.sources.join(";"),
            b.confidence
        ));
    }
    s
}

fn render_txt(r: &BreachReport) -> String {
    let mut s = format!(
        "\n=== EMAIL BREACH REPORT ===\n\nEmail: {}\nRisk: {:?} ({}/100)\nTotal: {}\n\n",
        r.email, r.risk_level, r.risk_score, r.total_breaches
    );
    for (i, b) in r.breaches.iter().enumerate() {
        s.push_str(&format!(
            "{}. {} ({})\n   Sources: {}\n",
            i + 1,
            b.name,
            b.date.as_deref().unwrap_or("?"),
            b.sources.join(", ")
        ));
    }
    s
}