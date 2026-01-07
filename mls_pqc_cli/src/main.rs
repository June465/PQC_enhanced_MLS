//! # MLS PQC CLI
//!
//! Command-line interface for PQC-enhanced MLS protocol operations.
//!
//! ## Usage
//!
//! ```bash
//! mls_pqc_cli [OPTIONS] <COMMAND>
//! ```
//!
//! ## Commands
//!
//! - `init-group` - Create a new MLS group
//! - `add-member` - Add a member to an existing group
//! - `remove-member` - Remove a member from a group
//! - `commit` - Commit pending proposals
//! - `encrypt` - Encrypt a message for the group
//! - `decrypt` - Decrypt a message from the group
//! - `key-package` - Generate a key package for joining groups

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

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

    /// Remove a member from a group
    RemoveMember {
        /// Group identifier
        #[arg(long, short = 'g')]
        group_id: String,

        /// Identity of the member to remove
        #[arg(long, short = 'm')]
        member_id: String,
    },

    /// Commit pending proposals to the group
    Commit {
        /// Group identifier
        #[arg(long, short = 'g')]
        group_id: String,
    },

    /// Encrypt a message for the group
    Encrypt {
        /// Group identifier
        #[arg(long, short = 'g')]
        group_id: String,

        /// Message to encrypt (plaintext)
        #[arg(long, short = 'p')]
        plaintext: String,
    },

    /// Decrypt a message from the group
    Decrypt {
        /// Group identifier
        #[arg(long, short = 'g')]
        group_id: String,

        /// Base64-encoded ciphertext to decrypt
        #[arg(long, short = 'c')]
        ciphertext: String,
    },

    /// Generate a key package for joining groups
    KeyPackage {
        /// Identity for the key package
        #[arg(long, short = 'm')]
        member_id: String,

        /// Output file path for the key package
        #[arg(long, short = 'o')]
        output: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    // For Phase 0, we just print confirmation that the CLI parsed correctly
    // Full command implementation will be added in Phase 1
    match &cli.command {
        Commands::InitGroup { group_id, member_id } => {
            println!(
                "{{\"command\": \"init-group\", \"group_id\": \"{}\", \"member_id\": \"{}\", \"status\": \"not_implemented\"}}",
                group_id, member_id
            );
        }
        Commands::AddMember { group_id, key_package } => {
            println!(
                "{{\"command\": \"add-member\", \"group_id\": \"{}\", \"key_package\": \"{}\", \"status\": \"not_implemented\"}}",
                group_id, key_package.display()
            );
        }
        Commands::RemoveMember { group_id, member_id } => {
            println!(
                "{{\"command\": \"remove-member\", \"group_id\": \"{}\", \"member_id\": \"{}\", \"status\": \"not_implemented\"}}",
                group_id, member_id
            );
        }
        Commands::Commit { group_id } => {
            println!(
                "{{\"command\": \"commit\", \"group_id\": \"{}\", \"status\": \"not_implemented\"}}",
                group_id
            );
        }
        Commands::Encrypt { group_id, plaintext } => {
            println!(
                "{{\"command\": \"encrypt\", \"group_id\": \"{}\", \"plaintext_len\": {}, \"status\": \"not_implemented\"}}",
                group_id, plaintext.len()
            );
        }
        Commands::Decrypt { group_id, ciphertext } => {
            println!(
                "{{\"command\": \"decrypt\", \"group_id\": \"{}\", \"ciphertext_len\": {}, \"status\": \"not_implemented\"}}",
                group_id, ciphertext.len()
            );
        }
        Commands::KeyPackage { member_id, output } => {
            println!(
                "{{\"command\": \"key-package\", \"member_id\": \"{}\", \"output\": \"{}\", \"status\": \"not_implemented\"}}",
                member_id, output.display()
            );
        }
    }
}
