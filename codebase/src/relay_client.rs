//! Client-side HTTPS transport for the standalone SafeChat relay.
//!
//! This module contains only the HTTP contract and request signing. It does
//! not expose relay storage or make the relay part of the Signal session.

use crate::signal_adapter::SignalPreKeyBundle;
use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::blocking::{Client, Response};
use reqwest::{Method, StatusCode, Url, header};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::json;
use sha2::{Digest, Sha256};
use signal_protocol::IdentityKeyPair;
use signal_rand::{Rng, TryRngCore, rngs::OsRng};
use std::time::{SystemTime, UNIX_EPOCH};

const REGISTER_DOMAIN: &[u8] = b"safechat-relay-register-v1\0";
const REQUEST_DOMAIN: &[u8] = b"safechat-relay-request-v1\0";
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct RelayClientConfig {
    pub base_url: String,
    pub client_id: String,
    pub enrollment_secret: String,
    pub ca_certificate_pem: Option<Vec<u8>>,
}

pub struct RelayClient {
    config: RelayClientConfig,
    identity_pair: IdentityKeyPair,
    http: Client,
    access_token: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RelayMessage {
    pub server_id: i64,
    pub sender: String,
    pub sender_address: Option<String>,
    pub message_id: String,
    pub ciphertext: String,
    pub accepted_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RelayMessageStatus {
    pub message_id: String,
    pub status: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ChallengeResponse {
    challenge: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RelayRegistration {
    pub access_token: String,
    pub device_id: String,
    pub api_version: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RelayBundle {
    pub device_id: String,
    pub bundle: String,
}

impl RelayClient {
    pub fn new(config: RelayClientConfig, identity_pair: IdentityKeyPair) -> Result<Self> {
        let mut base = Url::parse(&config.base_url).context("invalid relay URL")?;
        if base.scheme() != "https" {
            bail!("relay URL must use HTTPS");
        }
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        let mut builder = Client::builder().https_only(true);
        if let Some(certificate) = &config.ca_certificate_pem {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(certificate)
                    .context("loading relay CA certificate")?,
            );
        }
        let http = builder.build().context("creating relay HTTPS client")?;
        Ok(Self {
            config: RelayClientConfig {
                base_url: base.to_string().trim_end_matches('/').to_owned(),
                ..config
            },
            identity_pair,
            http,
            access_token: None,
        })
    }

    pub fn is_registered(&self) -> bool {
        self.access_token.is_some()
    }

    pub fn restore_access_token(&mut self, token: String) {
        self.access_token = Some(token);
    }

    pub fn access_token(&self) -> Option<&str> {
        self.access_token.as_deref()
    }

    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    pub fn client_id(&self) -> &str {
        &self.config.client_id
    }

    pub fn register(&mut self, bundle: &SignalPreKeyBundle) -> Result<RelayRegistration> {
        let challenge: ChallengeResponse = self
            .http
            .post(self.url("/v1/devices/challenge")?)
            .json(&json!({
                "client_id": self.config.client_id,
                "enrollment_secret": self.config.enrollment_secret,
            }))
            .send()
            .context("requesting relay enrollment challenge")
            .and_then(parse_json)?;
        let challenge = decode(&challenge.challenge)?;
        let bundle_bytes = bundle.encode()?;
        let device_address = bundle.address().to_string();
        let mut signed = REGISTER_DOMAIN.to_vec();
        signed.extend(self.config.client_id.as_bytes());
        signed.push(0);
        signed.extend(device_address.as_bytes());
        signed.push(0);
        signed.extend(Sha256::digest(&bundle_bytes));
        signed.extend(challenge);
        let mut rng = OsRng.unwrap_err();
        let signature = self
            .identity_pair
            .private_key()
            .calculate_signature(&signed, &mut rng)?;
        let identity_key = self.identity_pair.identity_key().serialize();
        let registration: RelayRegistration = self
            .http
            .post(self.url("/v1/devices/register")?)
            .json(&json!({
                "client_id": self.config.client_id,
                "device_address": device_address,
                "identity_key": encode(&identity_key),
                "bundle": encode(&bundle_bytes),
                "signature": encode(&signature),
            }))
            .send()
            .context("registering device with relay")
            .and_then(parse_json)?;
        self.access_token = Some(registration.access_token.clone());
        Ok(registration)
    }

    pub fn publish_bundle(&self, bundle: &SignalPreKeyBundle) -> Result<RelayBundle> {
        let bundle = encode(&bundle.encode()?);
        self.signed_json(
            Method::PUT,
            &format!("/v1/devices/{}/bundle", self.config.client_id),
            json!({"bundle": bundle}),
        )
    }

    pub fn fetch_bundle(&self, device_id: &str) -> Result<RelayBundle> {
        self.signed_json(
            Method::GET,
            &format!("/v1/devices/{device_id}/bundle"),
            serde_json::Value::Null,
        )
    }

    pub fn fetch_bundle_by_address(&self, address: &str) -> Result<RelayBundle> {
        self.signed_json(
            Method::GET,
            &format!("/v1/devices/by-address/{address}/bundle"),
            serde_json::Value::Null,
        )
    }

    pub fn decode_bundle(bundle: &RelayBundle) -> Result<SignalPreKeyBundle> {
        SignalPreKeyBundle::decode(&URL_SAFE_NO_PAD.decode(&bundle.bundle)?)
    }

    pub fn send_message(
        &self,
        recipient: &str,
        message_id: &str,
        ciphertext: &[u8],
        expires_at: Option<u64>,
    ) -> Result<RelayMessage> {
        self.signed_json(
            Method::POST,
            "/v1/messages",
            json!({
                "recipient": recipient,
                "message_id": message_id,
                "ciphertext": encode(ciphertext),
                "expires_at": expires_at,
            }),
        )
    }

    pub fn receive_messages(&self, cursor: i64) -> Result<Vec<RelayMessage>> {
        self.signed_json(
            Method::GET,
            &format!("/v1/messages?cursor={cursor}"),
            serde_json::Value::Null,
        )
    }

    pub fn acknowledge(&self, server_id: i64) -> Result<()> {
        let _: serde_json::Value = self.signed_json(
            Method::POST,
            &format!("/v1/messages/{server_id}/ack"),
            json!({"acknowledged": true}),
        )?;
        Ok(())
    }

    pub fn message_status(&self, message_id: &str) -> Result<RelayMessageStatus> {
        self.signed_json(
            Method::GET,
            &format!("/v1/messages/status?message_id={message_id}"),
            serde_json::Value::Null,
        )
    }

    fn signed_json<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        value: serde_json::Value,
    ) -> Result<T> {
        let body = if method == Method::GET {
            Vec::new()
        } else {
            serde_json::to_vec(&value)?
        };
        let token = self
            .access_token
            .as_deref()
            .context("relay client is not registered")?;
        let signed_path = path.split('?').next().unwrap_or(path);
        let nonce = random_nonce();
        let timestamp = now();
        let mut signed = REQUEST_DOMAIN.to_vec();
        signed.extend(method.as_str().as_bytes());
        signed.push(0);
        signed.extend(signed_path.as_bytes());
        signed.push(0);
        signed.extend(Sha256::digest(&body));
        signed.extend(nonce.as_bytes());
        signed.push(0);
        signed.extend(timestamp.to_be_bytes());
        let mut rng = OsRng.unwrap_err();
        let signature = self
            .identity_pair
            .private_key()
            .calculate_signature(&signed, &mut rng)?;
        let mut request = self
            .http
            .request(method, self.url(path)?)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header("x-safechat-nonce", &nonce)
            .header("x-safechat-timestamp", timestamp.to_string())
            .header("x-safechat-signature", encode(&signature));
        if !body.is_empty() {
            request = request
                .header(header::CONTENT_TYPE, "application/json")
                .body(body);
        }
        request
            .send()
            .context("sending signed relay request")
            .and_then(parse_json)
    }

    fn url(&self, path: &str) -> Result<Url> {
        Ok(Url::parse(&format!("{}{}", self.config.base_url, path))?)
    }
}

fn parse_json<T: DeserializeOwned>(response: Response) -> Result<T> {
    let status = response.status();
    let body = response.bytes().context("reading relay response")?;
    if body.len() > MAX_RESPONSE_BYTES {
        bail!("relay response is too large");
    }
    if status != StatusCode::OK {
        bail!(
            "relay request failed with {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    Ok(serde_json::from_slice(&body)?)
}

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode(value: &str) -> Result<Vec<u8>> {
    Ok(URL_SAFE_NO_PAD.decode(value)?)
}

fn random_nonce() -> String {
    let mut bytes = [0u8; 16];
    let mut rng = OsRng.unwrap_err();
    rng.fill(&mut bytes);
    encode(&bytes)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_requires_https() {
        let pair = IdentityKeyPair::generate(&mut OsRng.unwrap_err());
        assert!(
            RelayClient::new(
                RelayClientConfig {
                    base_url: "http://relay.invalid".to_owned(),
                    client_id: "client".to_owned(),
                    enrollment_secret: "secret".to_owned(),
                    ca_certificate_pem: None,
                },
                pair,
            )
            .is_err()
        );
    }

    #[test]
    fn request_nonce_is_url_safe_and_128_bits() {
        let nonce = random_nonce();
        assert_eq!(decode(&nonce).unwrap().len(), 16);
        assert!(
            nonce
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        );
    }
}
