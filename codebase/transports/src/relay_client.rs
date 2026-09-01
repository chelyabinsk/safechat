//! Client-side HTTP(S) transport for the standalone SafeChat relay.
//!
//! This module contains only the HTTP contract and request signing. It does
//! not expose relay storage or make the relay part of the Signal session.

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::{Method, StatusCode, Url, header};
use safechat_core::signal::SignalPreKeyBundle;
use safechat_core::transport::{
    ContactRequest, DeliveryStatus, MessageTransport, TransportMessage,
};
use safechat_relay_protocol as relay_binary;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::json;
use sha2::{Digest, Sha256};
use signal_protocol::IdentityKeyPair;
use signal_rand::{Rng, TryRngCore, rngs::OsRng};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const REGISTER_DOMAIN: &[u8] = b"safechat-relay-register-v1\0";
const REQUEST_DOMAIN: &[u8] = b"safechat-relay-request-v1\0";
const ENROLLMENT_REQUEST_DOMAIN: &[u8] = b"safechat-relay-enrollment-request-v1\0";
const MAX_RESPONSE_BYTES: usize = relay_binary::MAX_BODY;
const MAX_REQUEST_ATTEMPTS: usize = 4;

#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct RelayClientConfig {
    pub base_url: String,
    pub client_id: String,
    pub enrollment_secret: String,
    pub ca_certificate_pem: Option<Vec<u8>>,
    pub allow_insecure_http: bool,
}

impl RelayClientConfig {
    /// Creates a relay configuration with secure defaults.
    pub fn new(
        base_url: impl Into<String>,
        client_id: impl Into<String>,
        enrollment_secret: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            client_id: client_id.into(),
            enrollment_secret: enrollment_secret.into(),
            ca_certificate_pem: None,
            allow_insecure_http: false,
        }
    }

    /// Adds a private CA certificate used to validate the relay.
    pub fn with_ca_certificate(mut self, certificate_pem: Vec<u8>) -> Self {
        self.ca_certificate_pem = Some(certificate_pem);
        self
    }

    /// Explicitly permits HTTP for a trusted private-network hop.
    pub fn with_insecure_http(mut self, allowed: bool) -> Self {
        self.allow_insecure_http = allowed;
        self
    }
}

pub struct RelayClient {
    config: RelayClientConfig,
    identity_pair: IdentityKeyPair,
    http: Client,
    access_token: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayMessage {
    pub server_id: i64,
    pub sender: String,
    pub sender_address: Option<String>,
    pub message_id: String,
    pub ciphertext: Vec<u8>,
    pub accepted_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RelayMessageStatus {
    pub message_id: String,
    pub status: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ContactResponse {
    request_id: String,
    sender_id: String,
    sender_name: String,
    sender_fingerprint: String,
    bundle: String,
    status: String,
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
pub struct EnrollmentResponse {
    pub accepted: bool,
    pub client_id: String,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RelayBundle {
    pub device_id: String,
    pub bundle: String,
}

impl RelayClient {
    pub fn new(config: RelayClientConfig, identity_pair: IdentityKeyPair) -> Result<Self> {
        let mut base = Url::parse(&config.base_url).context("invalid relay URL")?;
        if base.scheme() != "https" && !(config.allow_insecure_http && base.scheme() == "http") {
            bail!("relay URL must use HTTPS unless insecure HTTP is explicitly enabled");
        }
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        let mut builder = Client::builder().https_only(!config.allow_insecure_http);
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

    pub fn set_client_id(&mut self, client_id: String) {
        self.config.client_id = client_id;
    }

    pub fn register(&mut self, bundle: &SignalPreKeyBundle) -> Result<RelayRegistration> {
        let challenge: ChallengeResponse = parse_json(send_with_retry(|| {
            Ok(self
                .http
                .post(self.url("/v1/devices/challenge")?)
                .json(&json!({
                    "client_id": self.config.client_id,
                    "enrollment_secret": self.config.enrollment_secret,
                })))
        })?)
        .context("requesting relay enrollment challenge")?;
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
        let registration: RelayRegistration = parse_json(send_with_retry(|| {
            Ok(self
                .http
                .post(self.url("/v1/devices/register")?)
                .json(&json!({
                    "client_id": self.config.client_id,
                    "device_address": device_address,
                    "identity_key": encode(&identity_key),
                    "bundle": encode(&bundle_bytes),
                    "signature": encode(&signature),
                })))
        })?)
        .context("registering device with relay")?;
        self.access_token = Some(registration.access_token.clone());
        Ok(registration)
    }

    pub fn submit_enrollment_request(
        &mut self,
        bundle: &SignalPreKeyBundle,
        fingerprint: &str,
    ) -> Result<EnrollmentResponse> {
        let bundle_bytes = bundle.encode()?;
        let identity_key = self.identity_pair.identity_key().serialize();
        let secret_hash = hash(&self.config.enrollment_secret);
        let mut signed = ENROLLMENT_REQUEST_DOMAIN.to_vec();
        signed.extend(bundle.address().to_string().as_bytes());
        signed.push(0);
        signed.extend(fingerprint.as_bytes());
        signed.push(0);
        signed.extend(secret_hash.as_bytes());
        signed.push(0);
        signed.extend(Sha256::digest(&bundle_bytes));
        let mut rng = OsRng.unwrap_err();
        let signature = self
            .identity_pair
            .private_key()
            .calculate_signature(&signed, &mut rng)?;
        let response: EnrollmentResponse = parse_json(send_with_retry(|| {
            Ok(self
                .http
                .post(self.url("/v1/devices/enrollment-requests")?)
                .json(&json!({
                    "device_address": bundle.address().to_string(),
                    "identity_key": encode(&identity_key),
                    "fingerprint": fingerprint,
                    "bundle": encode(&bundle_bytes),
                    "enrollment_secret_hash": secret_hash,
                    "signature": encode(&signature),
                })))
        })?)
        .context("submitting relay enrollment request")?;
        self.set_client_id(response.client_id.clone());
        Ok(response)
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
        let body = relay_binary::encode_submit(&relay_binary::Submit::new(
            recipient,
            message_id,
            expires_at,
            ciphertext.to_vec(),
        ))?;
        let response = self.signed_binary(Method::POST, "/v1/messages", body, true)?;
        parse_binary_messages(&response)?
            .into_iter()
            .next()
            .context("relay returned no sent message")
    }

    pub fn receive_messages(&self, cursor: i64) -> Result<Vec<RelayMessage>> {
        let response = self.signed_binary(
            Method::GET,
            &format!("/v1/messages?cursor={cursor}"),
            Vec::new(),
            false,
        )?;
        parse_binary_messages(&response)
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

    pub fn request_contact(&self, recipient: &str, request: &ContactRequest) -> Result<()> {
        let _: ContactResponse = self.signed_json(
            Method::POST,
            "/v1/contacts/requests",
            json!({
                "request_id": request.request_id,
                "recipient": recipient,
                "sender_name": request.sender_name,
                "sender_fingerprint": request.sender_fingerprint,
                "bundle": encode(&request.bundle),
            }),
        )?;
        Ok(())
    }

    pub fn contact_requests(&self, outgoing: bool) -> Result<Vec<ContactRequest>> {
        let path = if outgoing {
            "/v1/contacts/requests?direction=outgoing"
        } else {
            "/v1/contacts/requests"
        };
        let responses: Vec<ContactResponse> =
            self.signed_json(Method::GET, path, serde_json::Value::Null)?;
        responses
            .into_iter()
            .map(|response| {
                Ok(ContactRequest::new(
                    response.request_id,
                    response.sender_id,
                    response.sender_name,
                    response.sender_fingerprint,
                    URL_SAFE_NO_PAD.decode(response.bundle)?,
                ))
            })
            .collect()
    }

    pub fn accepted_contacts(&self) -> Result<Vec<ContactRequest>> {
        let responses: Vec<ContactResponse> = self.signed_json(
            Method::GET,
            "/v1/contacts/requests?direction=outgoing",
            serde_json::Value::Null,
        )?;
        responses
            .into_iter()
            .filter(|response| response.status == "accepted")
            .map(|response| {
                Ok(ContactRequest::new(
                    response.request_id,
                    response.sender_id,
                    response.sender_name,
                    response.sender_fingerprint,
                    URL_SAFE_NO_PAD.decode(response.bundle)?,
                ))
            })
            .collect()
    }

    pub fn accept_contact(&self, request_id: &str) -> Result<ContactRequest> {
        let response: ContactResponse = self.signed_json(
            Method::POST,
            &format!("/v1/contacts/requests/{request_id}/accept"),
            serde_json::Value::Null,
        )?;
        Ok(ContactRequest::new(
            response.request_id,
            response.sender_id,
            response.sender_name,
            response.sender_fingerprint,
            URL_SAFE_NO_PAD.decode(response.bundle)?,
        ))
    }

    pub fn reject_contact(&self, request_id: &str) -> Result<()> {
        let _: serde_json::Value = self.signed_json(
            Method::POST,
            &format!("/v1/contacts/requests/{request_id}/reject"),
            serde_json::Value::Null,
        )?;
        Ok(())
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
        let body_for_request = body.clone();
        let method_for_request = method.clone();
        parse_json(send_with_retry(|| {
            let nonce = random_nonce();
            let timestamp = now();
            let mut signed = REQUEST_DOMAIN.to_vec();
            signed.extend(method_for_request.as_str().as_bytes());
            signed.push(0);
            signed.extend(signed_path.as_bytes());
            signed.push(0);
            signed.extend(Sha256::digest(&body_for_request));
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
                .request(method_for_request.clone(), self.url(path)?)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("x-safechat-nonce", &nonce)
                .header("x-safechat-timestamp", timestamp.to_string())
                .header("x-safechat-signature", encode(&signature));
            if !body_for_request.is_empty() {
                request = request
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(body_for_request.clone());
            }
            Ok(request)
        })?)
    }

    fn signed_binary(
        &self,
        method: Method,
        path: &str,
        body: Vec<u8>,
        send_body: bool,
    ) -> Result<Vec<u8>> {
        let token = self
            .access_token
            .as_deref()
            .context("relay client is not registered")?;
        let signed_path = path.split('?').next().unwrap_or(path);
        let body_for_request = body.clone();
        let method_for_request = method.clone();
        let response = send_with_retry(|| {
            let nonce = random_nonce();
            let timestamp = now();
            let mut signed = REQUEST_DOMAIN.to_vec();
            signed.extend(method_for_request.as_str().as_bytes());
            signed.push(0);
            signed.extend(signed_path.as_bytes());
            signed.push(0);
            signed.extend(Sha256::digest(&body_for_request));
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
                .request(method_for_request.clone(), self.url(path)?)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("x-safechat-nonce", &nonce)
                .header("x-safechat-timestamp", timestamp.to_string())
                .header("x-safechat-signature", encode(&signature))
                .header(header::ACCEPT, "application/octet-stream");
            if send_body {
                request = request
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .body(body_for_request.clone());
            }
            Ok(request)
        })?;
        let status = response.status();
        let bytes = response.bytes().context("reading relay response")?;
        if status != StatusCode::OK {
            bail!(
                "relay request failed with {status}: {}",
                String::from_utf8_lossy(&bytes)
            );
        }
        Ok(bytes.to_vec())
    }

    fn url(&self, path: &str) -> Result<Url> {
        Ok(Url::parse(&format!("{}{}", self.config.base_url, path))?)
    }
}

impl MessageTransport for RelayClient {
    fn send(
        &mut self,
        recipient: &str,
        message_id: &str,
        ciphertext: &[u8],
        expires_at: Option<u64>,
    ) -> Result<()> {
        self.send_message(recipient, message_id, ciphertext, expires_at)
            .map(|_| ())
    }

    fn receive(&mut self, cursor: i64) -> Result<Vec<TransportMessage>> {
        self.receive_messages(cursor)?
            .into_iter()
            .map(|message| {
                Ok(TransportMessage::new(
                    message.server_id.to_string(),
                    message.sender,
                    message.sender_address,
                    message.message_id,
                    message.ciphertext,
                    message.accepted_at,
                    message.expires_at,
                ))
            })
            .collect()
    }

    fn acknowledge(&mut self, message: &TransportMessage) -> Result<()> {
        let server_id = message
            .transport_id
            .parse::<i64>()
            .context("relay returned an invalid transport message ID")?;
        RelayClient::acknowledge(self, server_id)
    }

    fn status(&mut self, message_id: &str) -> Result<DeliveryStatus> {
        let status = self.message_status(message_id)?.status;
        match status.as_str() {
            "sent" => Ok(DeliveryStatus::Sent),
            "read" => Ok(DeliveryStatus::Read),
            other => bail!("relay returned unknown delivery status {other}"),
        }
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

fn parse_binary_messages(input: &[u8]) -> Result<Vec<RelayMessage>> {
    relay_binary::decode_messages(input).map(|messages| {
        messages
            .into_iter()
            .map(|message| RelayMessage {
                server_id: message.server_id,
                sender: message.sender,
                sender_address: message.sender_address,
                message_id: message.message_id,
                ciphertext: message.ciphertext,
                accepted_at: message.accepted_at,
                expires_at: message.expires_at,
            })
            .collect()
    })
}

fn send_with_retry<F>(mut build: F) -> Result<Response>
where
    F: FnMut() -> Result<RequestBuilder>,
{
    for attempt in 0..MAX_REQUEST_ATTEMPTS {
        let response = build()?.send();
        match response {
            Ok(response) if retryable_status(response.status()) => {
                if attempt + 1 == MAX_REQUEST_ATTEMPTS {
                    return Ok(response);
                }
                let _ = response.bytes();
                thread::sleep(retry_delay(attempt));
            }
            Ok(response) => return Ok(response),
            Err(error) if attempt + 1 < MAX_REQUEST_ATTEMPTS => {
                thread::sleep(retry_delay(attempt));
                let _ = error;
            }
            Err(error) => {
                return Err(error).context("relay request failed after retries");
            }
        }
    }
    unreachable!("relay retry loop always returns")
}

fn retryable_status(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_EARLY
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

fn retry_delay(attempt: usize) -> Duration {
    Duration::from_millis(250u64.saturating_mul(1u64 << attempt.min(3)))
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

fn hash(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_message_response_round_trips_raw_ciphertext() {
        let message = RelayMessage {
            server_id: 7,
            sender: "alice".to_owned(),
            sender_address: Some("Alice.1".to_owned()),
            message_id: "message-1".to_owned(),
            ciphertext: vec![0, 1, 2, 255],
            accepted_at: 42,
            expires_at: Some(99),
        };
        let encoded = encode_test_binary_messages(&[message.clone()]);
        assert_eq!(parse_binary_messages(&encoded).unwrap(), vec![message]);
    }

    #[test]
    fn binary_message_response_rejects_trailing_bytes() {
        let mut encoded = encode_test_binary_messages(&[]);
        encoded.push(0);
        assert!(parse_binary_messages(&encoded).is_err());
    }

    fn encode_test_binary_messages(messages: &[RelayMessage]) -> Vec<u8> {
        relay_binary::encode_messages(
            &messages
                .iter()
                .map(|message| {
                    relay_binary::Message::new(
                        message.server_id,
                        message.sender.clone(),
                        message.sender_address.clone(),
                        message.message_id.clone(),
                        message.accepted_at,
                        message.expires_at,
                        message.ciphertext.clone(),
                    )
                })
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    #[test]
    fn relay_requires_https_by_default() {
        let pair = IdentityKeyPair::generate(&mut OsRng.unwrap_err());
        assert!(
            RelayClient::new(
                RelayClientConfig {
                    base_url: "http://relay.invalid".to_owned(),
                    client_id: "client".to_owned(),
                    enrollment_secret: "secret".to_owned(),
                    ca_certificate_pem: None,
                    allow_insecure_http: false,
                },
                pair,
            )
            .is_err()
        );
    }

    #[test]
    fn relay_allows_explicit_insecure_http() {
        let pair = IdentityKeyPair::generate(&mut OsRng.unwrap_err());
        assert!(
            RelayClient::new(
                RelayClientConfig {
                    base_url: "http://relay.invalid".to_owned(),
                    client_id: "client".to_owned(),
                    enrollment_secret: "secret".to_owned(),
                    ca_certificate_pem: None,
                    allow_insecure_http: true,
                },
                pair,
            )
            .is_ok()
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

    #[test]
    fn retry_policy_only_retries_transient_failures() {
        assert!(retryable_status(StatusCode::REQUEST_TIMEOUT));
        assert!(retryable_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(retryable_status(StatusCode::SERVICE_UNAVAILABLE));
        assert!(!retryable_status(StatusCode::UNAUTHORIZED));
        assert!(!retryable_status(StatusCode::NOT_FOUND));
        assert_eq!(retry_delay(0), Duration::from_millis(250));
        assert_eq!(retry_delay(3), Duration::from_millis(2_000));
    }

    #[test]
    fn binary_message_parser_preserves_ciphertext_bytes() {
        let ciphertext = [0, 1, 2, 250, 255];
        let packet = relay_binary::encode_messages(&[relay_binary::Message::new(
            7,
            "alice",
            Some("alice.1".into()),
            "message-7",
            12,
            None,
            ciphertext.to_vec(),
        )])
        .unwrap();

        let messages = parse_binary_messages(&packet).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].ciphertext, ciphertext);
    }
}
