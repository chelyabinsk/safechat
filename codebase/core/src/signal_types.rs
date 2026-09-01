//! SafeChat-owned value types used at the Signal boundary.

use anyhow::{Result, bail};
use std::fmt;

/// Stable SafeChat representation of a Signal peer address.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PeerAddress {
    name: String,
    device_id: u32,
}

impl PeerAddress {
    pub fn new(name: impl Into<String>, device_id: u32) -> Result<Self> {
        let name = name.into();
        if name.is_empty() {
            bail!("peer name must not be empty");
        }
        if device_id == 0 {
            bail!("peer device ID must be non-zero");
        }
        Ok(Self { name, device_id })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn device_id(&self) -> u32 {
        self.device_id
    }
}

impl fmt::Display for PeerAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}", self.name, self.device_id)
    }
}

/// Validated serialized public identity key owned by SafeChat.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityPublicKey(Vec<u8>);

impl IdentityPublicKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        signal_protocol::IdentityKey::try_from(bytes.as_slice())
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn fingerprint(&self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
