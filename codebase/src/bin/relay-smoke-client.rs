//! Disposable client for the local relay Docker smoke test.

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
use reqwest::blocking::Client;
use safechat_relay_protocol as relay_binary;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use signal_protocol::IdentityKeyPair;
use signal_rand::{Rng, TryRngCore, rngs::OsRng};
use std::time::{SystemTime, UNIX_EPOCH};

const REGISTER_DOMAIN: &[u8] = b"safechat-relay-register-v1\0";
const REQUEST_DOMAIN: &[u8] = b"safechat-relay-request-v1\0";

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Identity {
        client_id: String,
    },
    Run {
        #[arg(long)]
        base_url: String,
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        enrollment_secret: String,
        #[arg(long)]
        identity_key: String,
        #[arg(long)]
        identity_pair: String,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        send: bool,
    },
}

#[derive(Deserialize)]
struct Challenge {
    challenge: String,
}
#[derive(Deserialize)]
struct Registration {
    access_token: String,
}
#[derive(Deserialize)]
struct BinaryMessageMetadata {
    server_id: i64,
    message_id: String,
}

fn main() -> Result<()> {
    match Args::parse().command {
        Command::Identity { client_id } => {
            let mut rng = OsRng.unwrap_err();
            let pair = IdentityKeyPair::generate(&mut rng);
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "client_id": client_id,
                    "identity_key": enc(pair.identity_key().serialize().as_ref()),
                    "identity_pair": enc(pair.serialize().as_ref()),
                    "fingerprint": format!("smoke-{}", client_id),
                }))?
            );
        }
        Command::Run {
            base_url,
            client_id,
            enrollment_secret,
            identity_key: _,
            identity_pair,
            recipient,
            send,
        } => {
            run(
                &base_url,
                &client_id,
                &enrollment_secret,
                &identity_pair,
                &recipient,
                send,
            )?;
        }
    }
    Ok(())
}

fn run(
    base: &str,
    client_id: &str,
    secret: &str,
    identity: &str,
    recipient: &str,
    send: bool,
) -> Result<()> {
    let pair = IdentityKeyPair::try_from(dec(identity)?.as_slice())
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let http = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let base = base.trim_end_matches('/');
    let bundle = format!("opaque-smoke-bundle-{}", client_id).into_bytes();
    let challenge: Challenge = http
        .post(format!("{}/v1/devices/challenge", base))
        .json(&json!({"client_id": client_id, "enrollment_secret": secret}))
        .send()?
        .error_for_status()?
        .json()?;
    let address = format!("{}.1", client_id);
    let mut signed = REGISTER_DOMAIN.to_vec();
    signed.extend(client_id.as_bytes());
    signed.push(0);
    signed.extend(address.as_bytes());
    signed.push(0);
    signed.extend(Sha256::digest(&bundle));
    signed.extend(dec(&challenge.challenge)?);
    let mut rng = OsRng.unwrap_err();
    let signature = pair.private_key().calculate_signature(&signed, &mut rng)?;
    let registration: Registration = http.post(format!("{}/v1/devices/register", base))
        .json(&json!({"client_id": client_id, "device_address": address, "identity_key": enc(pair.identity_key().serialize().as_ref()), "bundle": enc(&bundle), "signature": enc(&signature)}))
        .send()?.error_for_status()?.json()?;
    println!("{}: registered", client_id);
    if send {
        let message_id = format!("smoke-{}-{}", client_id, now());
        let body = relay_binary::encode_submit(&relay_binary::Submit {
            recipient: recipient.to_owned(),
            message_id: message_id.clone(),
            expires_at: None,
            ciphertext: b"encrypted-smoke-payload".to_vec(),
        })?;
        let h = headers(
            &pair,
            &registration.access_token,
            "POST",
            "/v1/messages",
            &body,
        );
        let mut h = h;
        h.insert("content-type", "application/octet-stream".parse().unwrap());
        h.insert("accept", "application/octet-stream".parse().unwrap());
        http.post(format!("{}/v1/messages", base))
            .headers(h)
            .body(body)
            .send()?
            .error_for_status()?;
        println!("{}: sent {}", client_id, message_id);
    } else {
        let path = "/v1/messages?cursor=0";
        let message = (0..120)
            .find_map(|_| {
                let response: Result<Vec<u8>, _> = http
                    .get(format!("{}{}", base, path))
                    .headers({
                        let mut h = headers(
                            &pair,
                            &registration.access_token,
                            "GET",
                            "/v1/messages",
                            &[],
                        );
                        h.insert("accept", "application/octet-stream".parse().unwrap());
                        h
                    })
                    .send()
                    .and_then(|r| r.error_for_status())
                    .and_then(|r| r.bytes().map(|bytes| bytes.to_vec()));
                let response = response.ok()?;
                let found = parse_binary_message(&response)
                    .filter(|(_, ciphertext)| ciphertext == b"encrypted-smoke-payload")
                    .map(|(message, _)| message);
                if found.is_none() {
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
                found
            })
            .context("message was not delivered")?;
        let ack_path = format!("/v1/messages/{}/ack", message.server_id);
        let body = br#"{"acknowledged":true}"#;
        http.post(format!("{}{}", base, ack_path))
            .headers({
                let mut h = headers(&pair, &registration.access_token, "POST", &ack_path, body);
                h.insert("content-type", "application/json".parse().unwrap());
                h
            })
            .body(body.to_vec())
            .send()?
            .error_for_status()?;
        println!(
            "{}: received and acknowledged {}",
            client_id, message.message_id
        );
    }
    Ok(())
}

fn headers(
    pair: &IdentityKeyPair,
    token: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> reqwest::header::HeaderMap {
    let nonce = enc(&rand_bytes());
    let timestamp = now();
    let mut payload = REQUEST_DOMAIN.to_vec();
    payload.extend(method.as_bytes());
    payload.push(0);
    payload.extend(path.as_bytes());
    payload.push(0);
    payload.extend(Sha256::digest(body));
    payload.extend(nonce.as_bytes());
    payload.push(0);
    payload.extend(timestamp.to_be_bytes());
    let mut rng = OsRng.unwrap_err();
    let signature = pair
        .private_key()
        .calculate_signature(&payload, &mut rng)
        .unwrap();
    let mut h = reqwest::header::HeaderMap::new();
    h.insert(
        "authorization",
        format!("Bearer {}", token).parse().unwrap(),
    );
    h.insert("x-safechat-nonce", nonce.parse().unwrap());
    h.insert(
        "x-safechat-timestamp",
        timestamp.to_string().parse().unwrap(),
    );
    h.insert("x-safechat-signature", enc(&signature).parse().unwrap());
    h
}

fn parse_binary_message(input: &[u8]) -> Option<(BinaryMessageMetadata, Vec<u8>)> {
    relay_binary::decode_messages(input)
        .ok()?
        .into_iter()
        .find_map(|message| {
            (message.ciphertext == b"encrypted-smoke-payload").then_some((
                BinaryMessageMetadata {
                    server_id: message.server_id,
                    message_id: message.message_id,
                },
                message.ciphertext,
            ))
        })
}

fn rand_bytes() -> [u8; 16] {
    let mut b = [0; 16];
    let mut r = OsRng.unwrap_err();
    r.fill(&mut b);
    b
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
fn enc(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
fn dec(value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(value).context("invalid base64")
}
