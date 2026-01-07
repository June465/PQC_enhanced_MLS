use openmls::prelude::*;
use serde::{Deserialize, Serialize};
use crate::error::{EngineResult, EngineError};
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::collections::HashMap;
use openmls_traits::storage::*;
use openmls_traits::OpenMlsProvider;
use openmls_rust_crypto::OpenMlsRustCrypto;
use std::fmt::Debug;

/// A simple, serializable storage provider for OpenMLS.
/// It keeps all data in memory in a hash map.
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct SerializableStorage {
    /// The inner key-value store.
    pub values: HashMap<Vec<u8>, Vec<u8>>,
}

impl StorageProvider for SerializableStorage {
    type Error = EngineError;

    fn write(&mut self, label: &[u8], key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        let mut composite_key = Vec::with_capacity(label.len() + key.len());
        composite_key.extend_from_slice(label);
        composite_key.extend_from_slice(key);
        self.values.insert(composite_key, value.to_vec());
        Ok(())
    }

    fn read(&self, label: &[u8], key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        let mut composite_key = Vec::with_capacity(label.len() + key.len());
        composite_key.extend_from_slice(label);
        composite_key.extend_from_slice(key);
        Ok(self.values.get(&composite_key).cloned())
    }

    fn delete(&mut self, label: &[u8], key: &[u8]) -> Result<(), Self::Error> {
         let mut composite_key = Vec::with_capacity(label.len() + key.len());
        composite_key.extend_from_slice(label);
        composite_key.extend_from_slice(key);
        self.values.remove(&composite_key);
        Ok(())
    }
}

/// Holds the runtime state of a group and acts as the Provider.
pub struct GroupState {
    /// The OpenMLS group instance. 
    /// Note: This is optional during initialization, but we usually have it.
    pub group: Option<MlsGroup>,
    
    /// The storage backend.
    pub storage: SerializableStorage,
    
    /// The crypto provider (stateless/default).
    /// Skipped during serialization.
    pub crypto: OpenMlsRustCrypto,
}

// Manual serialization to handle flipping `group` and ignoring `crypto`.
#[derive(Serialize, Deserialize)]
struct GroupStateSnapshot {
    storage: SerializableStorage,
    group_id: Vec<u8>,
}

impl GroupState {
    pub fn new() -> Self {
        Self {
            group: None,
            storage: SerializableStorage::default(),
            crypto: OpenMlsRustCrypto::default(),
        }
    }

    pub fn save(&self, path: &str) -> EngineResult<()> {
        let group_id = self.group.as_ref()
            .ok_or_else(|| EngineError::Generic("No group to save".into()))?
            .group_id()
            .to_slice();

        let snapshot = GroupStateSnapshot {
            storage: self.storage.clone(),
            group_id,
        };

        let file = File::create(path).map_err(|e| EngineError::Io(e))?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &snapshot).map_err(|e| EngineError::Serialization(e.to_string()))?;
        Ok(())
    }

    pub fn load(path: &str) -> EngineResult<Self> {
        let file = File::open(path).map_err(|e| EngineError::Io(e))?;
        let reader = BufReader::new(file);
        
        let snapshot: GroupStateSnapshot = serde_json::from_reader(reader)
            .map_err(|e| EngineError::Deserialization(e.to_string()))?;

        // Construct partial state
        let mut state = Self {
            group: None,
            storage: snapshot.storage,
            crypto: OpenMlsRustCrypto::default(),
        };

        // Load the group using `state.storage`.
        // MlsGroup::load needs `StorageProvider`.
        let loaded_group = MlsGroup::load(&state.storage, &GroupId::from_slice(&snapshot.group_id))
             .map_err(|e| EngineError::Generic(format!("Failed to load group: {:?}", e)))?;

        state.group = Some(loaded_group);
        Ok(state)
    }
}

impl OpenMlsProvider for GroupState {
    type CryptoProvider = OpenMlsRustCrypto;
    type RandProvider = OpenMlsRustCrypto;
    type StorageProvider = SerializableStorage;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
}
