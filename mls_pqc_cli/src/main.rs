//! # MLS PQC CLI
//!
//! Command-line interface for PQC-enhanced MLS protocol operations.
//! Outputs benchmark-ready JSONL metrics for all operations.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::fs::File;
use std::io::Read;
use std::time::Instant;

mod output;
mod artifacts;
use output::{BenchmarkOutput, ArtifactBytes, ArtifactPaths};
use artifacts::ArtifactManager;

// Import Engine and types
use mls_pqc_engine::engine::{MlsEngine, CryptoSuite, KeyPackageData, SerializedKeyPackageData};
use mls_pqc_engine::engine::state::GroupState;

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

    /// Optional run identifier for experiment grouping
    #[arg(long, global = true)]
    pub run_id: Option<String>,

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

impl From<Suite> for CryptoSuite {
    fn from(suite: Suite) -> CryptoSuite {
        match suite {
            Suite::Classic => CryptoSuite::Classic,
            Suite::PqcKem => CryptoSuite::PqcKem,
            Suite::HybridKem => CryptoSuite::HybridKem,
        }
    }
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

    /// Remove a member from a group by identity
    RemoveMember {
        /// Group identifier
        #[arg(long, short = 'g')]
        group_id: String,

        /// Identity of the member to remove
        #[arg(long, short = 'm')]
        member_id: String,
    },

    /// Commit pending proposals
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

    /// Join an existing group using a Welcome message
    JoinGroup {
        /// Group identifier (for state file naming)
        #[arg(long, short = 'g')]
        group_id: String,

        /// Identity of the joining member
        #[arg(long, short = 'm')]
        member_id: String,

        /// Path to the Welcome message file
        #[arg(long)]
        welcome: PathBuf,

        /// Path to the KeyPackageData JSON file
        #[arg(long)]
        key_package_data: PathBuf,
    },

    /// Export group state for debugging and analysis
    ExportState {
        /// Group identifier
        #[arg(long, short = 'g')]
        group_id: String,

        /// Output file path (optional, defaults to stdout)
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let engine = MlsEngine::new()?;
    let suite_str = format!("{:?}", cli.suite).to_lowercase();

    // Ensure state dir exists
    if !cli.state_dir.exists() {
        std::fs::create_dir_all(&cli.state_dir)?;
    }

    match &cli.command {
        Commands::InitGroup { group_id, member_id } => {
            let start = Instant::now();
            let crypto_suite: CryptoSuite = cli.suite.into();
            
            match engine.create_group_with_suite(
                group_id.as_bytes(),
                member_id.as_bytes(),
                crypto_suite,
            ) {
                Ok(group_state) => {
                    let path = cli.state_dir.join(format!("{}.json", group_id));
                    if let Err(e) = group_state.save(path.to_str().unwrap()) {
                        BenchmarkOutput::error("init_group", &suite_str, &e.to_string(), start)
                            .with_group_id(group_id)
                            .with_member_id(member_id)
                            .print();
                        return Ok(());
                    }
                    
                    let group_size = group_state.group.members().count() as u32;
                    BenchmarkOutput::new("init_group", &suite_str)
                        .with_group_id(group_id)
                        .with_member_id(member_id)
                        .with_group_size(group_size)
                        .with_epoch_after(group_state.epoch())
                        .with_timing(start)
                        .print();
                }
                Err(e) => {
                    BenchmarkOutput::error("init_group", &suite_str, &e.to_string(), start)
                        .with_group_id(group_id)
                        .with_member_id(member_id)
                        .print();
                }
            }
        }
        
        Commands::AddMember { group_id, key_package } => {
            let start = Instant::now();
            let path = cli.state_dir.join(format!("{}.json", group_id));
            
            // Load group state
            let mut group_state = match GroupState::load(path.to_str().unwrap()) {
                Ok(state) => state,
                Err(e) => {
                    BenchmarkOutput::error("add_member", &suite_str, &e.to_string(), start)
                        .with_group_id(group_id)
                        .with_run_id(cli.run_id.as_deref())
                        .print();
                    return Ok(());
                }
            };
            
            let epoch_before = group_state.epoch();
            let suite_actual = group_state.suite.to_string();
            
            // Read key package from file
            let mut file = match File::open(key_package) {
                Ok(f) => f,
                Err(e) => {
                    BenchmarkOutput::error("add_member", &suite_actual, &e.to_string(), start)
                        .with_group_id(group_id)
                        .with_epoch_before(epoch_before)
                        .with_run_id(cli.run_id.as_deref())
                        .print();
                    return Ok(());
                }
            };
            let mut kp_bytes = Vec::new();
            if let Err(e) = file.read_to_end(&mut kp_bytes) {
                BenchmarkOutput::error("add_member", &suite_actual, &e.to_string(), start)
                    .with_group_id(group_id)
                    .with_epoch_before(epoch_before)
                    .with_run_id(cli.run_id.as_deref())
                    .print();
                return Ok(());
            }
            
            let bytes_in = kp_bytes.len() as u64;
            
            // Extract member ID from key package filename for artifact naming
            let new_member_id = key_package
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown");
            
            match engine.add_member(&mut group_state, &kp_bytes) {
                Ok((welcome, commit)) => {
                    if let Err(e) = group_state.save(path.to_str().unwrap()) {
                        BenchmarkOutput::error("add_member", &suite_actual, &e.to_string(), start)
                            .with_group_id(group_id)
                            .with_epoch_before(epoch_before)
                            .with_run_id(cli.run_id.as_deref())
                            .print();
                        return Ok(());
                    }
                    
                    // Create artifact manager and save artifacts
                    let artifact_manager = ArtifactManager::new(
                        &cli.state_dir,
                        group_id,
                        cli.run_id.as_deref(),
                    );
                    
                    let epoch_after = group_state.epoch();
                    let mut artifact_paths = ArtifactPaths::default();
                    
                    // Save Welcome artifact
                    match artifact_manager.save_welcome(new_member_id, &welcome) {
                        Ok(p) => artifact_paths.welcome = Some(p.to_string_lossy().to_string()),
                        Err(e) => eprintln!("Warning: Failed to save welcome artifact: {}", e),
                    }
                    
                    // Save Commit artifact
                    match artifact_manager.save_commit(epoch_after, &commit) {
                        Ok(p) => artifact_paths.commit = Some(p.to_string_lossy().to_string()),
                        Err(e) => eprintln!("Warning: Failed to save commit artifact: {}", e),
                    }
                    
                    let group_size = group_state.group.members().count() as u32;
                    let artifacts = ArtifactBytes {
                        welcome: Some(welcome.len() as u64),
                        commit: Some(commit.len() as u64),
                        ..Default::default()
                    };
                    
                    BenchmarkOutput::new("add_member", &suite_actual)
                        .with_group_id(group_id)
                        .with_member_id(new_member_id)
                        .with_group_size(group_size)
                        .with_epoch_before(epoch_before)
                        .with_epoch_after(epoch_after)
                        .with_bytes_in(bytes_in)
                        .with_artifact_bytes(artifacts)
                        .with_artifact_paths(artifact_paths)
                        .with_run_id(cli.run_id.as_deref())
                        .with_timing(start)
                        .print();
                }
                Err(e) => {
                    BenchmarkOutput::error("add_member", &suite_actual, &e.to_string(), start)
                        .with_group_id(group_id)
                        .with_epoch_before(epoch_before)
                        .with_run_id(cli.run_id.as_deref())
                        .print();
                }
            }
        }

        
        Commands::Encrypt { group_id, plaintext } => {
            let start = Instant::now();
            let path = cli.state_dir.join(format!("{}.json", group_id));
            
            let mut group_state = match GroupState::load(path.to_str().unwrap()) {
                Ok(state) => state,
                Err(e) => {
                    BenchmarkOutput::error("encrypt", &suite_str, &e.to_string(), start)
                        .with_group_id(group_id)
                        .with_run_id(cli.run_id.as_deref())
                        .print();
                    return Ok(());
                }
            };
            
            let epoch_before = group_state.epoch();
            let suite_actual = group_state.suite.to_string();
            let bytes_in = plaintext.len() as u64;
            
            match engine.encrypt_message(&mut group_state, plaintext.as_bytes()) {
                Ok(ciphertext) => {
                    if let Err(e) = group_state.save(path.to_str().unwrap()) {
                        BenchmarkOutput::error("encrypt", &suite_actual, &e.to_string(), start)
                            .with_group_id(group_id)
                            .with_epoch_before(epoch_before)
                            .with_run_id(cli.run_id.as_deref())
                            .print();
                        return Ok(());
                    }
                    
                    // Create artifact manager and save ciphertext
                    let artifact_manager = ArtifactManager::new(
                        &cli.state_dir,
                        group_id,
                        cli.run_id.as_deref(),
                    );
                    
                    let mut artifact_paths = ArtifactPaths::default();
                    
                    // Get next sequence number and save ciphertext
                    match artifact_manager.next_ciphertext_seq() {
                        Ok(seq) => {
                            match artifact_manager.save_ciphertext(seq, &ciphertext) {
                                Ok(p) => artifact_paths.ciphertext = Some(p.to_string_lossy().to_string()),
                                Err(e) => eprintln!("Warning: Failed to save ciphertext artifact: {}", e),
                            }
                        }
                        Err(e) => eprintln!("Warning: Failed to get ciphertext sequence: {}", e),
                    }
                    
                    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
                    let ct_b64 = BASE64.encode(&ciphertext);
                    
                    let group_size = group_state.group.members().count() as u32;
                    let bytes_out = ciphertext.len() as u64;
                    let artifacts = ArtifactBytes {
                        ciphertext: Some(bytes_out),
                        ..Default::default()
                    };
                    
                    // Output the ciphertext to stderr so stdout has only JSONL
                    eprintln!("{}", ct_b64);
                    
                    BenchmarkOutput::new("encrypt", &suite_actual)
                        .with_group_id(group_id)
                        .with_group_size(group_size)
                        .with_epoch_before(epoch_before)
                        .with_epoch_after(group_state.epoch())
                        .with_bytes_in(bytes_in)
                        .with_bytes_out(bytes_out)
                        .with_artifact_bytes(artifacts)
                        .with_artifact_paths(artifact_paths)
                        .with_run_id(cli.run_id.as_deref())
                        .with_timing(start)
                        .print();
                }
                Err(e) => {
                    BenchmarkOutput::error("encrypt", &suite_actual, &e.to_string(), start)
                        .with_group_id(group_id)
                        .with_epoch_before(epoch_before)
                        .with_run_id(cli.run_id.as_deref())
                        .print();
                }
            }
        }

        
        Commands::Decrypt { group_id, ciphertext } => {
            let start = Instant::now();
            let path = cli.state_dir.join(format!("{}.json", group_id));
            
            let mut group_state = match GroupState::load(path.to_str().unwrap()) {
                Ok(state) => state,
                Err(e) => {
                    BenchmarkOutput::error("decrypt", &suite_str, &e.to_string(), start)
                        .with_group_id(group_id)
                        .print();
                    return Ok(());
                }
            };
            
            let epoch_before = group_state.epoch();
            let suite_actual = group_state.suite.to_string();
            
            use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
            let ct_bytes = match BASE64.decode(ciphertext) {
                Ok(bytes) => bytes,
                Err(e) => {
                    BenchmarkOutput::error("decrypt", &suite_actual, &format!("Base64 error: {}", e), start)
                        .with_group_id(group_id)
                        .with_epoch_before(epoch_before)
                        .print();
                    return Ok(());
                }
            };
            
            let bytes_in = ct_bytes.len() as u64;
            
            match engine.decrypt_message(&mut group_state, &ct_bytes) {
                Ok(pt_bytes) => {
                    if let Err(e) = group_state.save(path.to_str().unwrap()) {
                        BenchmarkOutput::error("decrypt", &suite_actual, &e.to_string(), start)
                            .with_group_id(group_id)
                            .with_epoch_before(epoch_before)
                            .print();
                        return Ok(());
                    }
                    
                    let pt = String::from_utf8_lossy(&pt_bytes).to_string();
                    let bytes_out = pt_bytes.len() as u64;
                    let group_size = group_state.group.members().count() as u32;
                    
                    // Output plaintext to stderr so stdout has only JSONL
                    eprintln!("{}", pt);
                    
                    BenchmarkOutput::new("decrypt", &suite_actual)
                        .with_group_id(group_id)
                        .with_group_size(group_size)
                        .with_epoch_before(epoch_before)
                        .with_epoch_after(group_state.epoch())
                        .with_bytes_in(bytes_in)
                        .with_bytes_out(bytes_out)
                        .with_timing(start)
                        .print();
                }
                Err(e) => {
                    BenchmarkOutput::error("decrypt", &suite_actual, &e.to_string(), start)
                        .with_group_id(group_id)
                        .with_epoch_before(epoch_before)
                        .print();
                }
            }
        }

        Commands::KeyPackage { member_id, output } => {
            let start = Instant::now();
            let crypto_suite: CryptoSuite = cli.suite.into();
            
            match engine.generate_key_package_with_suite(member_id.as_bytes(), crypto_suite) {
                Ok(kp_data) => {
                    use std::io::Write;
                    
                    // Write key package bytes to output file
                    let mut file = match File::create(&output) {
                        Ok(f) => f,
                        Err(e) => {
                            BenchmarkOutput::error("key_package", &suite_str, &e.to_string(), start)
                                .with_member_id(member_id)
                                .print();
                            return Ok(());
                        }
                    };
                    
                    if let Err(e) = file.write_all(&kp_data.key_package_bytes) {
                        BenchmarkOutput::error("key_package", &suite_str, &e.to_string(), start)
                            .with_member_id(member_id)
                            .print();
                        return Ok(());
                    }
                    
                    // Create companion _data.json file path
                    let data_path_str = if output.extension().is_some() {
                        let stem = output.file_stem().unwrap().to_str().unwrap();
                        let parent = output.parent().unwrap_or(std::path::Path::new("."));
                        parent.join(format!("{}_data.json", stem))
                    } else {
                        output.with_extension("_data.json")
                    };
                    
                    // Serialize and save KeyPackageData
                    let serialized = match kp_data.to_serialized() {
                        Ok(s) => s,
                        Err(e) => {
                            BenchmarkOutput::error("key_package", &suite_str, &format!("Failed to serialize: {}", e), start)
                                .with_member_id(member_id)
                                .print();
                            return Ok(());
                        }
                    };
                    
                    if let Err(e) = serialized.save(data_path_str.to_str().unwrap()) {
                        BenchmarkOutput::error("key_package", &suite_str, &format!("Failed to save data: {}", e), start)
                            .with_member_id(member_id)
                            .print();
                        return Ok(());
                    }
                    
                    let kp_size = kp_data.key_package_bytes.len() as u64;
                    let artifacts = ArtifactBytes {
                        key_package: Some(kp_size),
                        ..Default::default()
                    };
                    
                    BenchmarkOutput::new("key_package", &suite_str)
                        .with_member_id(member_id)
                        .with_artifact_bytes(artifacts)
                        .with_timing(start)
                        .print();
                }
                Err(e) => {
                    BenchmarkOutput::error("key_package", &suite_str, &e.to_string(), start)
                        .with_member_id(member_id)
                        .print();
                }
            }
        }

        Commands::JoinGroup { group_id, member_id, welcome, key_package_data } => {
            let start = Instant::now();
            
            // Load welcome bytes from file
            let mut welcome_file = match File::open(&welcome) {
                Ok(f) => f,
                Err(e) => {
                    BenchmarkOutput::error("join_group", &suite_str, &e.to_string(), start)
                        .with_group_id(group_id)
                        .with_member_id(member_id)
                        .print();
                    return Ok(());
                }
            };
            let mut welcome_bytes = Vec::new();
            if let Err(e) = welcome_file.read_to_end(&mut welcome_bytes) {
                BenchmarkOutput::error("join_group", &suite_str, &e.to_string(), start)
                    .with_group_id(group_id)
                    .with_member_id(member_id)
                    .print();
                return Ok(());
            }
            
            let bytes_in = welcome_bytes.len() as u64;
            
            // Load KeyPackageData from JSON
            let serialized_kp_data = match SerializedKeyPackageData::load(key_package_data.to_str().unwrap()) {
                Ok(data) => data,
                Err(e) => {
                    BenchmarkOutput::error("join_group", &suite_str, &format!("Failed to load key package data: {}", e), start)
                        .with_group_id(group_id)
                        .with_member_id(member_id)
                        .print();
                    return Ok(());
                }
            };
            
            // Reconstruct KeyPackageData
            let kp_data = match KeyPackageData::from_serialized(serialized_kp_data) {
                Ok(data) => data,
                Err(e) => {
                    BenchmarkOutput::error("join_group", &suite_str, &format!("Failed to reconstruct key package data: {}", e), start)
                        .with_group_id(group_id)
                        .with_member_id(member_id)
                        .print();
                    return Ok(());
                }
            };
            
            let suite = kp_data.suite;
            let suite_actual = suite.to_string();
            
            // Process welcome message to join group
            match engine.process_welcome(&welcome_bytes, kp_data) {
                Ok(group_state) => {
                    let member_state_path = cli.state_dir.join(format!("{}_{}.json", group_id, 
                        String::from_utf8_lossy(&group_state.identity.name)));
                    
                    if let Err(e) = group_state.save(member_state_path.to_str().unwrap()) {
                        BenchmarkOutput::error("join_group", &suite_actual, &e.to_string(), start)
                            .with_group_id(group_id)
                            .with_member_id(member_id)
                            .print();
                        return Ok(());
                    }
                    
                    let group_size = group_state.group.members().count() as u32;
                    
                    BenchmarkOutput::new("join_group", &suite_actual)
                        .with_group_id(group_id)
                        .with_member_id(member_id)
                        .with_group_size(group_size)
                        .with_epoch_after(group_state.epoch())
                        .with_bytes_in(bytes_in)
                        .with_timing(start)
                        .print();
                }
                Err(e) => {
                    BenchmarkOutput::error("join_group", &suite_actual, &e.to_string(), start)
                        .with_group_id(group_id)
                        .with_member_id(member_id)
                        .print();
                }
            }
        }

        Commands::RemoveMember { group_id, member_id } => {
            let start = Instant::now();
            let path = cli.state_dir.join(format!("{}.json", group_id));
            
            // Load group state
            let mut group_state = match GroupState::load(path.to_str().unwrap()) {
                Ok(state) => state,
                Err(e) => {
                    BenchmarkOutput::error("remove_member", &suite_str, &e.to_string(), start)
                        .with_group_id(group_id)
                        .with_member_id(member_id)
                        .with_run_id(cli.run_id.as_deref())
                        .print();
                    return Ok(());
                }
            };
            
            let epoch_before = group_state.epoch();
            let suite_actual = group_state.suite.to_string();
            
            // Find the member's leaf index by identity
            let leaf_index = match group_state.find_member(member_id) {
                Some(idx) => idx,
                None => {
                    BenchmarkOutput::error("remove_member", &suite_actual, 
                        &format!("Member '{}' not found in group", member_id), start)
                        .with_group_id(group_id)
                        .with_member_id(member_id)
                        .with_epoch_before(epoch_before)
                        .with_run_id(cli.run_id.as_deref())
                        .print();
                    return Ok(());
                }
            };
            
            // Remove the member
            match engine.remove_member(&mut group_state, leaf_index) {
                Ok(commit_bytes) => {
                    // Save updated state
                    if let Err(e) = group_state.save(path.to_str().unwrap()) {
                        BenchmarkOutput::error("remove_member", &suite_actual, &e.to_string(), start)
                            .with_group_id(group_id)
                            .with_member_id(member_id)
                            .with_epoch_before(epoch_before)
                            .with_run_id(cli.run_id.as_deref())
                            .print();
                        return Ok(());
                    }
                    
                    // Create artifact manager and save commit artifact
                    let artifact_manager = ArtifactManager::new(
                        &cli.state_dir,
                        group_id,
                        cli.run_id.as_deref(),
                    );
                    
                    let epoch_after = group_state.epoch();
                    let mut artifact_paths = ArtifactPaths::default();
                    
                    // Save Commit artifact
                    match artifact_manager.save_commit(epoch_after, &commit_bytes) {
                        Ok(p) => artifact_paths.commit = Some(p.to_string_lossy().to_string()),
                        Err(e) => eprintln!("Warning: Failed to save commit artifact: {}", e),
                    }
                    
                    let group_size = group_state.group.members().count() as u32;
                    let artifacts = ArtifactBytes {
                        commit: Some(commit_bytes.len() as u64),
                        ..Default::default()
                    };
                    
                    BenchmarkOutput::new("remove_member", &suite_actual)
                        .with_group_id(group_id)
                        .with_member_id(member_id)
                        .with_group_size(group_size)
                        .with_epoch_before(epoch_before)
                        .with_epoch_after(epoch_after)
                        .with_artifact_bytes(artifacts)
                        .with_artifact_paths(artifact_paths)
                        .with_run_id(cli.run_id.as_deref())
                        .with_timing(start)
                        .print();
                }
                Err(e) => {
                    BenchmarkOutput::error("remove_member", &suite_actual, &e.to_string(), start)
                        .with_group_id(group_id)
                        .with_member_id(member_id)
                        .with_epoch_before(epoch_before)
                        .with_run_id(cli.run_id.as_deref())
                        .print();
                }
            }
        }

        Commands::Commit { group_id } => {
            let start = Instant::now();
            let path = cli.state_dir.join(format!("{}.json", group_id));
            
            // Load group state
            let group_state = match GroupState::load(path.to_str().unwrap()) {
                Ok(state) => state,
                Err(e) => {
                    BenchmarkOutput::error("commit", &suite_str, &e.to_string(), start)
                        .with_group_id(group_id)
                        .with_run_id(cli.run_id.as_deref())
                        .print();
                    return Ok(());
                }
            };
            
            let epoch_before = group_state.epoch();
            let suite_actual = group_state.suite.to_string();
            
            // Note: In our current implementation, add_member already includes commit/merge.
            // This command outputs the current state - no pending proposals in our flow.
            // We output a success with no epoch change to indicate "no pending proposals".
            
            // Save state (no changes, but confirms it's valid)
            if let Err(e) = group_state.save(path.to_str().unwrap()) {
                BenchmarkOutput::error("commit", &suite_actual, &e.to_string(), start)
                    .with_group_id(group_id)
                    .with_epoch_before(epoch_before)
                    .with_run_id(cli.run_id.as_deref())
                    .print();
                return Ok(());
            }
            
            let group_size = group_state.group.members().count() as u32;
            
            BenchmarkOutput::new("commit", &suite_actual)
                .with_group_id(group_id)
                .with_group_size(group_size)
                .with_epoch_before(epoch_before)
                .with_epoch_after(epoch_before) // No change since no pending proposals
                .with_run_id(cli.run_id.as_deref())
                .with_timing(start)
                .print();
        }

        Commands::ExportState { group_id, output } => {
            let start = Instant::now();
            let path = cli.state_dir.join(format!("{}.json", group_id));
            
            // Load group state
            let group_state = match GroupState::load(path.to_str().unwrap()) {
                Ok(state) => state,
                Err(e) => {
                    BenchmarkOutput::error("export_state", &suite_str, &e.to_string(), start)
                        .with_group_id(group_id)
                        .with_run_id(cli.run_id.as_deref())
                        .print();
                    return Ok(());
                }
            };
            
            let suite_actual = group_state.suite.to_string();
            
            // Build export JSON
            let members = group_state.list_members();
            let export_data = serde_json::json!({
                "schema_version": 1,
                "group_id": group_state.group_id_string(),
                "suite": suite_actual,
                "epoch": group_state.epoch(),
                "member_count": members.len(),
                "members": members,
                "exported_at_ms": output::now_ms()
            });
            
            let export_json = serde_json::to_string_pretty(&export_data)
                .expect("Failed to serialize export data");
            
            // Write to file or stdout
            match output {
                Some(out_path) => {
                    use std::io::Write;
                    let mut file = match File::create(out_path) {
                        Ok(f) => f,
                        Err(e) => {
                            BenchmarkOutput::error("export_state", &suite_actual, &e.to_string(), start)
                                .with_group_id(group_id)
                                .with_run_id(cli.run_id.as_deref())
                                .print();
                            return Ok(());
                        }
                    };
                    if let Err(e) = file.write_all(export_json.as_bytes()) {
                        BenchmarkOutput::error("export_state", &suite_actual, &e.to_string(), start)
                            .with_group_id(group_id)
                            .with_run_id(cli.run_id.as_deref())
                            .print();
                        return Ok(());
                    }
                }
                None => {
                    // Output to stderr so stdout has only JSONL
                    eprintln!("{}", export_json);
                }
            }
            
            let group_size = group_state.group.members().count() as u32;
            
            BenchmarkOutput::new("export_state", &suite_actual)
                .with_group_id(group_id)
                .with_group_size(group_size)
                .with_epoch_after(group_state.epoch())
                .with_run_id(cli.run_id.as_deref())
                .with_timing(start)
                .print();
        }
    }

    Ok(())
}
