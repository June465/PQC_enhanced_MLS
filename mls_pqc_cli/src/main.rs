//! # MLS PQC CLI
//!
//! Command-line interface for PQC-enhanced MLS protocol operations.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::fs::File;
use std::io::{Read, Write};
use serde::{Serialize, Deserialize};

// Import Engine
use mls_pqc_engine::engine::MlsEngine;
use mls_pqc_engine::engine::state::GroupState;
use mls_pqc_engine::error::EngineError;

/// PQC-enhanced MLS protocol CLI
#[derive(Parser, Debug)]
#[command(name = "mls_pqc_cli")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Directory for storing state files
    #[arg(long, short = 'd', default_value = ".mls_state", global = true)]
    pub state_dir: PathBuf,

    /// Cryptographic suite to use
    #[arg(long, short = 's', value_enum, default_value_t = Suite::Classic, global = true)]
    pub suite: Suite,

    /// Output format for results
    #[arg(long, short = 'o', value_enum, default_value_t = OutputFormat::Jsonl, global = true)]
    pub output_format: OutputFormat,

    /// Subcommand to execute
    #[command(subcommand)]
    pub command: Commands,
}

/// Cryptographic suite options
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Suite {
    /// Classic MLS with X25519/Ed25519
    Classic,
    /// PQC-only with ML-KEM
    PqcKem,
    /// Hybrid: Classic + PQC
    HybridKem,
}

/// Output format options
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// JSON Lines format (one JSON object per line)
    Jsonl,
    /// Pretty-printed JSON
    Json,
}

/// Available CLI commands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Create a new MLS group
    InitGroup {
        /// Unique identifier for the group
        #[arg(long, short = 'g')]
        group_id: String,

        /// Identity of the group creator
        #[arg(long, short = 'm')]
        member_id: String,
    },

    /// Add a member to an existing group
    AddMember {
        /// Group identifier
        #[arg(long, short = 'g')]
        group_id: String,

        /// Path to the new member's key package file
        #[arg(long, short = 'k')]
        key_package: PathBuf,
    },

    /// Remove a member from a group (Not Implemented)
    RemoveMember {
        /// Group identifier
        #[arg(long, short = 'g')]
        group_id: String,

        /// Identity of the member to remove
        #[arg(long, short = 'm')]
        member_id: String,
    },

    /// Commit pending proposals (Not Implemented)
    Commit {
        /// Group identifier
        #[arg(long, short = 'g')]
        group_id: String,
    },

    /// Encrypt a message
    Encrypt {
        /// Group identifier
        #[arg(long, short = 'g')]
        group_id: String,

        /// Message to encrypt (plaintext)
        #[arg(long, short = 'p')]
        plaintext: String,
    },

    /// Decrypt a message
    Decrypt {
        /// Group identifier
        #[arg(long, short = 'g')]
        group_id: String,

        /// Base64-encoded ciphertext to decrypt
        #[arg(long, short = 'c')]
        ciphertext: String,
    },

    /// Generate a key package
    KeyPackage {
        /// Identity for the key package
        #[arg(long, short = 'm')]
        member_id: String,

        /// Output file path for the key package
        #[arg(long, short = 'o')]
        output: PathBuf,
    },
}

#[derive(Serialize)]
struct CommandOutput {
    command: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let engine = MlsEngine::new()?;

    // Ensure state dir exists
    if !cli.state_dir.exists() {
        std::fs::create_dir_all(&cli.state_dir)?;
    }

    match &cli.command {
        Commands::InitGroup { group_id, member_id } => {
            // Note: member_id is ignored in current engine impl (uses "Creator"), 
            // but we should pass it when engine supports it.
            let group_state = engine.create_group(group_id.as_bytes(), member_id.as_bytes())?;
            
            // Save state
            let path = cli.state_dir.join(format!("{}.json", group_id));
            group_state.save(path.to_str().unwrap())?;
            
            print_output(CommandOutput {
                command: "init-group".into(),
                status: "success".into(),
                group_id: Some(group_id.clone()),
                message: Some(format!("Group created by {}", member_id)),
                result_data: None,
                error: None,
            });
        }
        
        Commands::AddMember { group_id, key_package } => {
            let path = cli.state_dir.join(format!("{}.json", group_id));
            let mut group_state = GroupState::load(path.to_str().unwrap())?;
            
            // Read key package from file
            let mut file = File::open(key_package)?;
            let mut kp_bytes = Vec::new();
            file.read_to_end(&mut kp_bytes)?;
            
            match engine.add_member(&mut group_state, &kp_bytes) {
                Ok((welcome, commit)) => {
                    // Update state file
                     group_state.save(path.to_str().unwrap())?;
                     
                     // In real CLI we might output welcome/commit to files.
                     // Here we just indicate success.
                     print_output(CommandOutput {
                        command: "add-member".into(),
                        status: "success".into(),
                        group_id: Some(group_id.clone()),
                        message: Some("Member added".into()),
                        result_data: Some(format!("Welcome size: {}, Commit size: {}", welcome.len(), commit.len())),
                        error: None,
                    });
                }
                Err(e) => print_error("add-member", e),
            }
        }
        
        Commands::Encrypt { group_id, plaintext } => {
             let path = cli.state_dir.join(format!("{}.json", group_id));
             let mut group_state = GroupState::load(path.to_str().unwrap())?;
             
             match engine.encrypt_message(&mut group_state, plaintext.as_bytes()) {
                 Ok(ciphertext) => {
                     // TODO: State update if encryption rolls ratchet? 
                     // Usually encryption advances application ratchet but checks if it needs to save?
                     // Usually application secret needs saving.
                     group_state.save(path.to_str().unwrap())?;
                     
                     use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
                     let ct_b64 = BASE64.encode(&ciphertext);
                     
                     print_output(CommandOutput {
                        command: "encrypt".into(),
                        status: "success".into(),
                        group_id: Some(group_id.clone()),
                        message: None,
                        result_data: Some(ct_b64),
                        error: None,
                    });
                 }
                 Err(e) => print_error("encrypt", e),
             }
        }
        
        Commands::Decrypt { group_id, ciphertext } => {
             let path = cli.state_dir.join(format!("{}.json", group_id));
             let mut group_state = GroupState::load(path.to_str().unwrap())?;
             
             use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
             let ct_bytes = BASE64.decode(ciphertext).map_err(|e| format!("Base64 error: {}", e))?; // Simple error mapping
             
             match engine.decrypt_message(&mut group_state, &ct_bytes) {
                 Ok(pt_bytes) => {
                     group_state.save(path.to_str().unwrap())?;
                     let pt = String::from_utf8_lossy(&pt_bytes).to_string();
                      print_output(CommandOutput {
                        command: "decrypt".into(),
                        status: "success".into(),
                        group_id: Some(group_id.clone()),
                        message: None,
                        result_data: Some(pt),
                        error: None,
                    });
                 }
                 Err(e) => print_error("decrypt", e),
             }
        }

        _ => {
            println!(
                "{{\"command\": \"unknown\", \"status\": \"not_implemented\", \"message\": \"Command not yet fully wired\"}}"
            );
        }
    }

    Ok(())
}

fn print_output(output: CommandOutput) {
    let json = serde_json::to_string(&output).unwrap();
    println!("{}", json);
}

fn print_error(cmd: &str, e: impl std::fmt::Display) {
    let output = CommandOutput {
        command: cmd.into(),
        status: "error".into(),
        group_id: None,
        message: None,
        result_data: None,
        error: Some(e.to_string()),
    };
    print_output(output);
}
