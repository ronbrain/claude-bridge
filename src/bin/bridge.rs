//! `bridge` — human-friendly CLI for claude-bridge.
//!
//! Lets you participate in a bridge channel without spinning up a
//! Claude Code session. Same env-var contract as the MCP client so a
//! single export-block in your shell rc covers both:
//!
//! ```sh
//! export BRIDGE_SERVER=http://172.16.101.166:3001
//! export BRIDGE_CHANNEL=general
//! export BRIDGE_SELF=$(hostname)
//! ```
//!
//! Then:
//!
//! ```sh
//! bridge send "hey, ready to push"
//! bridge tail
//! bridge tail 20 --from saas
//! bridge peers
//! bridge findings --status open --severity high
//! bridge triage <id> fixed --note "shipped in v1.2.3"
//! bridge upload ./poc.txt --notes "SQLi PoC for /api/login"
//! bridge clear
//! ```

use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "bridge",
    about = "claude-bridge CLI — talk to a bridge channel from your terminal",
    version
)]
struct Cli {
    /// Bridge server URL. Falls back to $BRIDGE_SERVER, then localhost.
    #[arg(long, global = true)]
    server: Option<String>,

    /// Channel. Falls back to $BRIDGE_CHANNEL, then `general`.
    #[arg(long, global = true)]
    channel: Option<String>,

    /// Identity for messages we send. Falls back to $BRIDGE_SELF,
    /// then $USER, then `cli`.
    #[arg(long, global = true)]
    name: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Send a free-form message.
    Send {
        /// Message body. Wrap in quotes to preserve whitespace.
        content: Vec<String>,
    },
    /// Print recent messages (most recent at the bottom).
    Tail {
        /// Max messages to show. Defaults to 20.
        #[arg(default_value_t = 20)]
        limit: usize,
        /// Only show messages from this sender.
        #[arg(long)]
        from: Option<String>,
        /// Only messages newer than this unix-seconds timestamp.
        #[arg(long)]
        since: Option<u64>,
    },
    /// List connected peers (heartbeat within last 120s).
    Peers,
    /// List findings, optionally filtered.
    Findings {
        #[arg(long)]
        severity: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        from: Option<String>,
    },
    /// Update a finding's status.
    Triage {
        /// Finding id (uuid).
        id: String,
        /// New status: open | triaged | fixed | wontfix.
        status: String,
        /// Optional triage note.
        #[arg(long)]
        note: Option<String>,
    },
    /// Hard-delete a finding (for false-positives).
    DeleteFinding {
        id: String,
    },
    /// Upload a file as a bridge artifact (≤10 MB).
    Upload {
        /// Path to the file.
        file: PathBuf,
        /// MIME type. Auto-guessed from extension if absent.
        #[arg(long)]
        mime: Option<String>,
        /// Free-form context shown to the peer alongside the URL.
        #[arg(long)]
        notes: Option<String>,
    },
    /// Wipe the channel's message history (does NOT touch findings).
    Clear,
}

struct Cfg {
    server: String,
    channel: String,
    name: String,
}

fn cfg(cli: &Cli) -> Cfg {
    Cfg {
        server: cli
            .server
            .clone()
            .or_else(|| std::env::var("BRIDGE_SERVER").ok())
            .unwrap_or_else(|| "http://localhost:3001".into()),
        channel: cli
            .channel
            .clone()
            .or_else(|| std::env::var("BRIDGE_CHANNEL").ok())
            .unwrap_or_else(|| "general".into()),
        name: cli
            .name
            .clone()
            .or_else(|| std::env::var("BRIDGE_SELF").ok())
            .or_else(|| std::env::var("USER").ok())
            .unwrap_or_else(|| "cli".into()),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let c = cfg(&cli);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    match cli.cmd {
        Cmd::Send { content } => {
            let body = content.join(" ");
            if body.is_empty() {
                eprintln!("error: empty message");
                std::process::exit(2);
            }
            let r = client
                .post(format!("{}/send/{}", c.server, c.channel))
                .json(&json!({ "from": c.name, "content": body }))
                .send()
                .await?;
            if r.status().is_success() {
                println!("sent to #{} ✓", c.channel);
            } else {
                eprintln!("send failed: {}", r.status());
                std::process::exit(1);
            }
        }

        Cmd::Tail { limit, from, since } => {
            let mut qs: Vec<(&str, String)> = vec![("limit", limit.to_string())];
            if let Some(f) = &from {
                qs.push(("from", f.clone()));
            }
            if let Some(s) = since {
                qs.push(("since", s.to_string()));
            }
            let msgs: Vec<Value> = client
                .get(format!("{}/messages/{}", c.server, c.channel))
                .query(&qs)
                .send()
                .await?
                .json()
                .await?;
            if msgs.is_empty() {
                println!("(no messages in #{})", c.channel);
            } else {
                for m in msgs {
                    println!(
                        "[{}] {}: {}",
                        m["timestamp"].as_u64().unwrap_or(0),
                        m["from"].as_str().unwrap_or("?"),
                        m["content"].as_str().unwrap_or("")
                    );
                }
            }
        }

        Cmd::Peers => {
            let peers: Vec<Value> = client
                .get(format!("{}/peers", c.server))
                .send()
                .await?
                .json()
                .await?;
            if peers.is_empty() {
                println!("(no peers online)");
            } else {
                for p in peers {
                    println!(
                        "{:<24} idle {:>4}s  #{}",
                        p["name"].as_str().unwrap_or("?"),
                        p["idle_secs"].as_u64().unwrap_or(0),
                        p["channel"].as_str().unwrap_or("?")
                    );
                }
            }
        }

        Cmd::Findings { severity, status, from } => {
            let mut qs: Vec<(&str, String)> = Vec::new();
            for (k, v) in [("severity", severity), ("status", status), ("from", from)] {
                if let Some(val) = v {
                    qs.push((k, val));
                }
            }
            let fs: Vec<Value> = client
                .get(format!("{}/findings/{}", c.server, c.channel))
                .query(&qs)
                .send()
                .await?
                .json()
                .await?;
            if fs.is_empty() {
                println!("(no findings)");
            } else {
                for f in fs {
                    println!(
                        "[{}] {:<8} {:<60} id={} from={}",
                        f["status"].as_str().unwrap_or("?"),
                        f["severity"].as_str().unwrap_or("?"),
                        truncate(f["title"].as_str().unwrap_or(""), 60),
                        f["id"].as_str().unwrap_or("?"),
                        f["from"].as_str().unwrap_or("?")
                    );
                }
            }
        }

        Cmd::DeleteFinding { id } => {
            let r = client
                .delete(format!("{}/findings/{}/{}", c.server, c.channel, id))
                .send()
                .await?;
            if r.status().is_success() {
                println!("deleted {} ✓", id);
            } else {
                eprintln!("delete failed: {} — {}", r.status(), r.text().await.unwrap_or_default());
                std::process::exit(1);
            }
        }

        Cmd::Triage { id, status, note } => {
            let r = client
                .patch(format!("{}/findings/{}/{}", c.server, c.channel, id))
                .json(&json!({ "status": status, "note": note.unwrap_or_default() }))
                .send()
                .await?;
            if r.status().is_success() {
                println!("finding {} → {} ✓", id, status);
            } else {
                eprintln!("triage failed: {} — {}", r.status(), r.text().await.unwrap_or_default());
                std::process::exit(1);
            }
        }

        Cmd::Upload { file, mime, notes } => {
            let bytes = std::fs::read(&file)?;
            let filename = file
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("artifact.bin")
                .to_string();
            let mime = mime.unwrap_or_else(|| guess_mime(&filename).into());
            let v: Value = client
                .post(format!("{}/artifacts/{}", c.server, c.channel))
                .header("content-type", &mime)
                .header("x-bridge-from", &c.name)
                .header("x-bridge-filename", &filename)
                .body(bytes.clone())
                .send()
                .await?
                .json()
                .await?;
            let aid = v["id"].as_str().unwrap_or("?");
            let size = bytes.len();
            let url = format!("{}/artifact/{}", c.server, aid);
            // Also drop a chat ping so the peer's watcher wakes them.
            let ping = format!(
                "📎 artifact: {} ({} bytes)\nDownload: {}\nNotes: {}",
                filename,
                size,
                url,
                notes.clone().unwrap_or_default()
            );
            let _ = client
                .post(format!("{}/send/{}", c.server, c.channel))
                .json(&json!({ "from": c.name, "content": ping }))
                .send()
                .await;
            println!("uploaded {} ({} bytes) → {}", filename, size, url);
        }

        Cmd::Clear => {
            let r = client
                .delete(format!("{}/messages/{}", c.server, c.channel))
                .send()
                .await?;
            if r.status().is_success() {
                println!("cleared #{}", c.channel);
            } else {
                eprintln!("clear failed: {}", r.status());
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}

fn guess_mime(filename: &str) -> &'static str {
    match filename.rsplit('.').next().unwrap_or("").to_ascii_lowercase().as_str() {
        "txt" | "log" => "text/plain",
        "json" => "application/json",
        "yaml" | "yml" => "application/yaml",
        "html" | "htm" => "text/html",
        "md" => "text/markdown",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "pdf" => "application/pdf",
        "sh" | "bash" => "application/x-sh",
        "rs" => "text/x-rust",
        "py" => "text/x-python",
        "js" | "mjs" => "text/javascript",
        "ts" => "text/typescript",
        _ => "application/octet-stream",
    }
}
