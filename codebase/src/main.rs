use anyhow::{Context, Result, bail};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use png::{BitDepth, ColorType, Decoder, Encoder, Transformations};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use x25519_dalek::{PublicKey, StaticSecret};

mod carrier;
mod transport;

use carrier::{CarrierAdapter, PngCarrier, RgbaImage};
use transport::TextTransport;

type HmacSha256 = Hmac<Sha256>;

const VERSION: u8 = 1;
const SUITE_CHACHA20_POLY1305: u8 = 1;
const SUITE_X25519_CHACHA20_POLY1305_AUTHENTICATED: u8 = 3;
const LOCATOR_LEN: usize = 16;
const CONTEXT_HASH_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 1 + 1 + CONTEXT_HASH_LEN + NONCE_LEN + 4;
const PUBLIC_KEY_LEN: usize = 32;
const IDENTITY_KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const HANDSHAKE_HEADER: &str = "safechat-handshake-v1:";
const PREKEY_CERT_HEADER: &str = "safechat-prekey-cert-v1";
const SESSION_KEY_HEADER: &str = "safechat-session-v1";

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum EncryptionMode {
    Symmetric,
    Public,
    Identity,
}

#[derive(Parser)]
#[command(
    name = "safechat",
    version,
    about = "Encrypted local steganography MVP"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Keygen {
        output: PathBuf,
        #[arg(long, value_enum, default_value_t = EncryptionMode::Symmetric)]
        mode: EncryptionMode,
        #[arg(long)]
        public_output: Option<PathBuf>,
    },
    Fingerprint {
        input: PathBuf,
    },
    PrekeyCert {
        #[arg(long)]
        recipient_public_key: PathBuf,
        #[arg(long)]
        prekey_public_key: PathBuf,
        #[arg(long)]
        identity_private_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    HandshakeInit {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        session_output: PathBuf,
        #[arg(long)]
        recipient_public_key: PathBuf,
        #[arg(long)]
        recipient_identity_public_key: PathBuf,
        #[arg(long)]
        recipient_prekey_public_key: PathBuf,
        #[arg(long)]
        recipient_prekey_certificate: PathBuf,
        #[arg(long)]
        sender_identity_private_key: PathBuf,
    },
    HandshakeAccept {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        recipient_private_key: PathBuf,
        #[arg(long)]
        recipient_prekey_private_key: PathBuf,
        #[arg(long)]
        recipient_identity_private_key: PathBuf,
        #[arg(long)]
        trusted_sender_identity_public_key: PathBuf,
    },
    Encode {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        carrier: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = EncryptionMode::Symmetric)]
        mode: EncryptionMode,
        #[arg(long)]
        recipient_public_key: Option<PathBuf>,
        #[arg(long)]
        sender_private_key: Option<PathBuf>,
        #[arg(long, default_value = "")]
        context: String,
    },
    Decode {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = EncryptionMode::Symmetric)]
        mode: EncryptionMode,
        #[arg(long)]
        private_key: Option<PathBuf>,
        #[arg(long)]
        trusted_sender_public_key: Option<PathBuf>,
        #[arg(long, default_value = "")]
        context: String,
    },
    TextEncode {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = EncryptionMode::Symmetric)]
        mode: EncryptionMode,
        #[arg(long)]
        recipient_public_key: Option<PathBuf>,
        #[arg(long)]
        sender_private_key: Option<PathBuf>,
        #[arg(long, default_value = "")]
        context: String,
    },
    TextDecode {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = EncryptionMode::Symmetric)]
        mode: EncryptionMode,
        #[arg(long)]
        private_key: Option<PathBuf>,
        #[arg(long)]
        trusted_sender_public_key: Option<PathBuf>,
        #[arg(long, default_value = "")]
        context: String,
    },
    Inspect {
        input: PathBuf,
    },
    Detect {
        #[arg(long)]
        reference: PathBuf,
        #[arg(long)]
        candidate: PathBuf,
    },
    BlindDetect {
        input: PathBuf,
        #[arg(long, default_value_t = 1024)]
        window_bits: usize,
        #[arg(long, default_value_t = 0.05)]
        threshold: f64,
    },
    Benchmark {
        #[arg(long)]
        clean_dir: PathBuf,
        #[arg(long)]
        encoded_dir: PathBuf,
        #[arg(long, default_value_t = 1024)]
        window_bits: usize,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen {
            output,
            mode,
            public_output,
        } => keygen(&output, mode, public_output.as_ref()),
        Command::Fingerprint { input } => fingerprint(&input),
        Command::PrekeyCert {
            recipient_public_key,
            prekey_public_key,
            identity_private_key,
            output,
        } => prekey_cert(
            &recipient_public_key,
            &prekey_public_key,
            &identity_private_key,
            &output,
        ),
        Command::HandshakeInit {
            output,
            session_output,
            recipient_public_key,
            recipient_identity_public_key,
            recipient_prekey_public_key,
            recipient_prekey_certificate,
            sender_identity_private_key,
        } => handshake_init(
            &output,
            &session_output,
            &recipient_public_key,
            &recipient_identity_public_key,
            &recipient_prekey_public_key,
            &recipient_prekey_certificate,
            &sender_identity_private_key,
        ),
        Command::HandshakeAccept {
            input,
            output,
            recipient_private_key,
            recipient_prekey_private_key,
            recipient_identity_private_key,
            trusted_sender_identity_public_key,
        } => handshake_accept(
            &input,
            &output,
            &recipient_private_key,
            &recipient_prekey_private_key,
            &recipient_identity_private_key,
            &trusted_sender_identity_public_key,
        ),
        Command::Encode {
            input,
            carrier,
            output,
            key,
            mode,
            recipient_public_key,
            sender_private_key,
            context,
        } => encode(
            &input,
            &carrier,
            &output,
            key.as_ref(),
            mode,
            recipient_public_key.as_ref(),
            sender_private_key.as_ref(),
            &context,
        ),
        Command::Decode {
            input,
            output,
            key,
            mode,
            private_key,
            trusted_sender_public_key,
            context,
        } => decode(
            &input,
            &output,
            key.as_ref(),
            mode,
            private_key.as_ref(),
            trusted_sender_public_key.as_ref(),
            &context,
        ),
        Command::TextEncode {
            input,
            output,
            key,
            mode,
            recipient_public_key,
            sender_private_key,
            context,
        } => text_encode(
            &input,
            &output,
            key.as_ref(),
            mode,
            recipient_public_key.as_ref(),
            sender_private_key.as_ref(),
            &context,
        ),
        Command::TextDecode {
            input,
            output,
            key,
            mode,
            private_key,
            trusted_sender_public_key,
            context,
        } => text_decode(
            &input,
            &output,
            key.as_ref(),
            mode,
            private_key.as_ref(),
            trusted_sender_public_key.as_ref(),
            &context,
        ),
        Command::Inspect { input } => inspect(&input),
        Command::Detect {
            reference,
            candidate,
        } => detect(&reference, &candidate),
        Command::BlindDetect {
            input,
            window_bits,
            threshold,
        } => blind_detect(&input, window_bits, threshold),
        Command::Benchmark {
            clean_dir,
            encoded_dir,
            window_bits,
        } => benchmark(&clean_dir, &encoded_dir, window_bits),
    }
}

fn write_secret_file(path: &PathBuf, header: &str, bytes: &[u8]) -> Result<()> {
    let encoded = STANDARD_NO_PAD.encode(bytes);
    fs::write(path, format!("{header}:{encoded}\n"))
        .with_context(|| format!("writing key file {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("protecting key file {}", path.display()))?;
    }
    Ok(())
}

fn keygen(path: &PathBuf, mode: EncryptionMode, public_output: Option<&PathBuf>) -> Result<()> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    match mode {
        EncryptionMode::Symmetric => {
            if public_output.is_some() {
                bail!("--public-output is only valid with --mode public");
            }
            write_secret_file(path, "safechat-key-v1", &key)?;
        }
        EncryptionMode::Public => {
            let public_path = public_output.context("public mode requires --public-output")?;
            let secret = StaticSecret::from(key);
            let public = PublicKey::from(&secret);
            write_secret_file(path, "safechat-private-v1", secret.as_bytes())?;
            write_secret_file(public_path, "safechat-public-v1", public.as_bytes())?;
            println!("generated public key: {}", public_path.display());
        }
        EncryptionMode::Identity => {
            let public_path = public_output.context("identity mode requires --public-output")?;
            let signing_key = SigningKey::from_bytes(&key);
            write_secret_file(path, "safechat-identity-private-v1", &key)?;
            write_secret_file(
                public_path,
                "safechat-identity-public-v1",
                signing_key.verifying_key().as_bytes(),
            )?;
            println!("generated identity public key: {}", public_path.display());
        }
    }
    println!("generated key: {}", path.display());
    Ok(())
}

fn load_material(path: &PathBuf, expected_header: &str) -> Result<[u8; 32]> {
    let text =
        fs::read_to_string(path).with_context(|| format!("reading key file {}", path.display()))?;
    let encoded = text
        .trim()
        .strip_prefix(expected_header)
        .with_context(|| format!("invalid key file header; expected {expected_header}"))?;
    let bytes = STANDARD_NO_PAD
        .decode(encoded)
        .context("invalid base64 key")?;
    if bytes.len() != 32 {
        bail!("key must contain exactly 32 bytes");
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn load_symmetric_key(path: &PathBuf) -> Result<[u8; 32]> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading symmetric key {}", path.display()))?;
    if text.trim().starts_with(SESSION_KEY_HEADER) {
        load_session_key(path)
    } else {
        load_material(path, "safechat-key-v1:")
    }
}

fn load_private_key(path: &PathBuf) -> Result<[u8; 32]> {
    load_material(path, "safechat-private-v1:")
}

fn load_public_key(path: &PathBuf) -> Result<[u8; 32]> {
    load_material(path, "safechat-public-v1:")
}

fn load_identity_private_key(path: &PathBuf) -> Result<[u8; IDENTITY_KEY_LEN]> {
    load_material(path, "safechat-identity-private-v1:")
}

fn load_identity_public_key(path: &PathBuf) -> Result<[u8; IDENTITY_KEY_LEN]> {
    load_material(path, "safechat-identity-public-v1:")
}

fn load_session_key(path: &PathBuf) -> Result<[u8; 32]> {
    load_material(path, &format!("{SESSION_KEY_HEADER}:"))
}

fn public_key_fingerprint(key: &[u8]) -> String {
    Sha256::digest(key)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|chunk| chunk.join(""))
        .collect::<Vec<_>>()
        .join(" ")
}

fn fingerprint(path: &PathBuf) -> Result<()> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading public key {}", path.display()))?;
    let key = if text.trim().starts_with("safechat-public-v1:") {
        load_public_key(path)?.to_vec()
    } else if text.trim().starts_with("safechat-identity-public-v1:") {
        load_identity_public_key(path)?.to_vec()
    } else {
        bail!("fingerprint requires a SafeChat public or identity public key")
    };
    println!("{}", public_key_fingerprint(&key));
    Ok(())
}

fn prekey_certificate_message(
    recipient_public: &[u8; PUBLIC_KEY_LEN],
    prekey_public: &[u8; PUBLIC_KEY_LEN],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(32 + PUBLIC_KEY_LEN * 2);
    message.extend(b"safechat/prekey-cert/v1");
    message.extend(recipient_public);
    message.extend(prekey_public);
    message
}

fn prekey_cert(
    recipient_public_path: &PathBuf,
    prekey_public_path: &PathBuf,
    identity_private_path: &PathBuf,
    output: &PathBuf,
) -> Result<()> {
    let recipient_public = load_public_key(recipient_public_path)?;
    let prekey_public = load_public_key(prekey_public_path)?;
    let identity_private = load_identity_private_key(identity_private_path)?;
    let identity = SigningKey::from_bytes(&identity_private);
    let signature = identity.sign(&prekey_certificate_message(
        &recipient_public,
        &prekey_public,
    ));
    let mut certificate = Vec::with_capacity(PUBLIC_KEY_LEN * 2 + SIGNATURE_LEN);
    certificate.extend(recipient_public);
    certificate.extend(prekey_public);
    certificate.extend(signature.to_bytes());
    write_secret_file(output, PREKEY_CERT_HEADER, &certificate)?;
    println!("wrote signed prekey certificate: {}", output.display());
    Ok(())
}

fn load_prekey_certificate(path: &PathBuf) -> Result<([u8; 32], [u8; 32], [u8; 64])> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading prekey certificate {}", path.display()))?;
    let encoded = text
        .trim()
        .strip_prefix(&format!("{PREKEY_CERT_HEADER}:"))
        .context("invalid prekey certificate header")?;
    let bytes = STANDARD_NO_PAD
        .decode(encoded)
        .context("invalid prekey certificate encoding")?;
    if bytes.len() != PUBLIC_KEY_LEN * 2 + SIGNATURE_LEN {
        bail!("invalid prekey certificate length");
    }
    let mut recipient = [0u8; 32];
    let mut prekey = [0u8; 32];
    let mut signature = [0u8; 64];
    recipient.copy_from_slice(&bytes[..32]);
    prekey.copy_from_slice(&bytes[32..64]);
    signature.copy_from_slice(&bytes[64..]);
    Ok((recipient, prekey, signature))
}

fn handshake_signature_message(
    recipient_public: &[u8; PUBLIC_KEY_LEN],
    recipient_identity_public: &[u8; IDENTITY_KEY_LEN],
    recipient_prekey_public: &[u8; PUBLIC_KEY_LEN],
    initiator_ephemeral_public: &[u8; PUBLIC_KEY_LEN],
    initiator_identity_public: &[u8; IDENTITY_KEY_LEN],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(32 + 32 * 5);
    message.extend(b"safechat/handshake/v1");
    message.extend(recipient_public);
    message.extend(recipient_identity_public);
    message.extend(recipient_prekey_public);
    message.extend(initiator_ephemeral_public);
    message.extend(initiator_identity_public);
    message
}

fn derive_handshake_session(
    first_dh: &[u8; PUBLIC_KEY_LEN],
    second_dh: &[u8; PUBLIC_KEY_LEN],
    recipient_public: &[u8; PUBLIC_KEY_LEN],
    recipient_prekey_public: &[u8; PUBLIC_KEY_LEN],
    initiator_ephemeral_public: &[u8; PUBLIC_KEY_LEN],
    initiator_identity_public: &[u8; IDENTITY_KEY_LEN],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(PUBLIC_KEY_LEN * 5 + IDENTITY_KEY_LEN);
    input.extend(first_dh);
    input.extend(second_dh);
    input.extend(recipient_public);
    input.extend(recipient_prekey_public);
    input.extend(initiator_ephemeral_public);
    input.extend(initiator_identity_public);
    let hkdf = Hkdf::<Sha256>::new(Some(b"safechat/handshake/v1"), &input);
    let mut session = [0u8; 32];
    hkdf.expand(b"safechat/session-key/v1", &mut session)
        .expect("32-byte HKDF output is valid");
    session
}

#[allow(clippy::too_many_arguments)]
fn handshake_init(
    output: &PathBuf,
    session_output: &PathBuf,
    recipient_public_path: &PathBuf,
    recipient_identity_public_path: &PathBuf,
    recipient_prekey_public_path: &PathBuf,
    certificate_path: &PathBuf,
    sender_identity_private_path: &PathBuf,
) -> Result<()> {
    let recipient_public = load_public_key(recipient_public_path)?;
    let recipient_identity_public = load_identity_public_key(recipient_identity_public_path)?;
    let recipient_prekey_public = load_public_key(recipient_prekey_public_path)?;
    let (cert_recipient, cert_prekey, cert_signature) = load_prekey_certificate(certificate_path)?;
    if cert_recipient != recipient_public || cert_prekey != recipient_prekey_public {
        bail!("prekey certificate does not match the supplied recipient keys");
    }
    let recipient_identity = VerifyingKey::from_bytes(&recipient_identity_public)
        .context("invalid recipient identity public key")?;
    recipient_identity
        .verify(
            &prekey_certificate_message(&recipient_public, &recipient_prekey_public),
            &Signature::from_bytes(&cert_signature),
        )
        .map_err(|_| anyhow::anyhow!("recipient prekey certificate is invalid"))?;
    let sender_identity_private = load_identity_private_key(sender_identity_private_path)?;
    let sender_identity = SigningKey::from_bytes(&sender_identity_private);
    let sender_identity_public = sender_identity.verifying_key();
    let mut ephemeral_bytes = [0u8; PUBLIC_KEY_LEN];
    OsRng.fill_bytes(&mut ephemeral_bytes);
    let ephemeral_secret = StaticSecret::from(ephemeral_bytes);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let signature_message = handshake_signature_message(
        &recipient_public,
        &recipient_identity_public,
        &recipient_prekey_public,
        ephemeral_public.as_bytes(),
        sender_identity_public.as_bytes(),
    );
    let signature = sender_identity.sign(&signature_message);
    let mut handshake =
        Vec::with_capacity(1 + PUBLIC_KEY_LEN * 3 + IDENTITY_KEY_LEN * 2 + SIGNATURE_LEN * 2);
    handshake.extend([VERSION]);
    handshake.extend(recipient_public);
    handshake.extend(recipient_identity_public);
    handshake.extend(recipient_prekey_public);
    handshake.extend(cert_signature);
    handshake.extend(ephemeral_public.as_bytes());
    handshake.extend(sender_identity_public.as_bytes());
    handshake.extend(signature.to_bytes());
    let encoded = format!("{HANDSHAKE_HEADER}{}\n", URL_SAFE_NO_PAD.encode(handshake));
    fs::write(output, encoded)
        .with_context(|| format!("writing handshake {}", output.display()))?;
    let first = ephemeral_secret.diffie_hellman(&PublicKey::from(recipient_public));
    let second = ephemeral_secret.diffie_hellman(&PublicKey::from(recipient_prekey_public));
    let session = derive_handshake_session(
        first.as_bytes(),
        second.as_bytes(),
        &recipient_public,
        &recipient_prekey_public,
        ephemeral_public.as_bytes(),
        sender_identity_public.as_bytes(),
    );
    write_secret_file(session_output, SESSION_KEY_HEADER, &session)?;
    println!(
        "wrote handshake and session key for sender fingerprint: {}",
        public_key_fingerprint(sender_identity_public.as_bytes())
    );
    Ok(())
}

fn handshake_accept(
    input: &PathBuf,
    output: &PathBuf,
    recipient_private_path: &PathBuf,
    recipient_prekey_private_path: &PathBuf,
    recipient_identity_private_path: &PathBuf,
    trusted_sender_identity_public_path: &PathBuf,
) -> Result<()> {
    let text = fs::read_to_string(input)
        .with_context(|| format!("reading handshake {}", input.display()))?;
    let encoded = text
        .trim()
        .strip_prefix(HANDSHAKE_HEADER)
        .context("invalid handshake header")?;
    let handshake = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("invalid handshake encoding")?;
    let expected_len = 1 + PUBLIC_KEY_LEN * 3 + IDENTITY_KEY_LEN * 2 + SIGNATURE_LEN * 2;
    if handshake.len() != expected_len {
        bail!("invalid handshake length");
    }
    if handshake[0] != VERSION {
        bail!("unsupported handshake version");
    }
    let recipient_private = load_private_key(recipient_private_path)?;
    let recipient_prekey_private = load_private_key(recipient_prekey_private_path)?;
    let recipient_public = PublicKey::from(&StaticSecret::from(recipient_private)).to_bytes();
    let recipient_identity_private = load_identity_private_key(recipient_identity_private_path)?;
    let recipient_identity = SigningKey::from_bytes(&recipient_identity_private);
    let trusted_sender = load_identity_public_key(trusted_sender_identity_public_path)?;
    let mut supplied_recipient = [0u8; 32];
    supplied_recipient.copy_from_slice(&handshake[1..33]);
    if supplied_recipient != recipient_public {
        bail!("handshake is addressed to a different recipient");
    }
    let mut recipient_identity_public = [0u8; 32];
    recipient_identity_public.copy_from_slice(&handshake[33..65]);
    if recipient_identity_public != *recipient_identity.verifying_key().as_bytes() {
        bail!("recipient identity does not match local identity key");
    }
    let mut recipient_prekey_public = [0u8; 32];
    recipient_prekey_public.copy_from_slice(&handshake[65..97]);
    let cert_signature = Signature::from_bytes(handshake[97..161].try_into()?);
    recipient_identity
        .verifying_key()
        .verify(
            &prekey_certificate_message(&recipient_public, &recipient_prekey_public),
            &cert_signature,
        )
        .map_err(|_| anyhow::anyhow!("recipient prekey certificate is invalid"))?;
    let mut initiator_ephemeral_public = [0u8; 32];
    initiator_ephemeral_public.copy_from_slice(&handshake[161..193]);
    let mut initiator_identity_public = [0u8; 32];
    initiator_identity_public.copy_from_slice(&handshake[193..225]);
    if initiator_identity_public != trusted_sender {
        bail!("sender identity does not match trusted fingerprint");
    }
    let signature = Signature::from_bytes(handshake[225..289].try_into()?);
    let trusted_sender_key = VerifyingKey::from_bytes(&trusted_sender)
        .context("invalid trusted sender identity public key")?;
    trusted_sender_key
        .verify(
            &handshake_signature_message(
                &recipient_public,
                &recipient_identity_public,
                &recipient_prekey_public,
                &initiator_ephemeral_public,
                &initiator_identity_public,
            ),
            &signature,
        )
        .map_err(|_| anyhow::anyhow!("handshake sender signature is invalid"))?;
    let ephemeral_public = PublicKey::from(initiator_ephemeral_public);
    let first = StaticSecret::from(recipient_private).diffie_hellman(&ephemeral_public);
    let second = StaticSecret::from(recipient_prekey_private).diffie_hellman(&ephemeral_public);
    let session = derive_handshake_session(
        first.as_bytes(),
        second.as_bytes(),
        &recipient_public,
        &recipient_prekey_public,
        &initiator_ephemeral_public,
        &initiator_identity_public,
    );
    write_secret_file(output, SESSION_KEY_HEADER, &session)?;
    println!(
        "accepted handshake; session key written to {}",
        output.display()
    );
    Ok(())
}

fn context_hash(context: &str) -> [u8; CONTEXT_HASH_LEN] {
    let digest = Sha256::digest(context.as_bytes());
    let mut result = [0u8; CONTEXT_HASH_LEN];
    result.copy_from_slice(&digest[..CONTEXT_HASH_LEN]);
    result
}

fn locator(key: &[u8; 32], context: &[u8; CONTEXT_HASH_LEN]) -> [u8; LOCATOR_LEN] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts every key length");
    mac.update(b"safechat/locator/v1");
    mac.update(context);
    let digest = mac.finalize().into_bytes();
    let mut result = [0u8; LOCATOR_LEN];
    result.copy_from_slice(&digest[..LOCATOR_LEN]);
    result
}

fn make_envelope(plaintext: &[u8], key: &[u8; 32], context: &str) -> Result<Vec<u8>> {
    let context_hash = context_hash(context);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext_len = plaintext
        .len()
        .checked_add(16)
        .context("payload too large")?;
    let length = u32::try_from(ciphertext_len).context("payload exceeds MVP size limit")?;
    let mut aad = Vec::with_capacity(1 + 1 + CONTEXT_HASH_LEN + 4);
    aad.extend([VERSION, SUITE_CHACHA20_POLY1305]);
    aad.extend(context_hash);
    aad.extend(length.to_be_bytes());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;

    let mut envelope = Vec::with_capacity(LOCATOR_LEN + HEADER_LEN + ciphertext.len());
    envelope.extend(locator(key, &context_hash));
    envelope.extend([VERSION, SUITE_CHACHA20_POLY1305]);
    envelope.extend(context_hash);
    envelope.extend(nonce_bytes);
    envelope.extend(length.to_be_bytes());
    envelope.extend(ciphertext);
    Ok(envelope)
}

fn public_locator(
    ephemeral_public: &[u8; PUBLIC_KEY_LEN],
    context: &[u8; CONTEXT_HASH_LEN],
) -> [u8; LOCATOR_LEN] {
    let mut hash = Sha256::new();
    hash.update(b"safechat/public-locator/v1");
    hash.update(ephemeral_public);
    hash.update(context);
    let digest = hash.finalize();
    let mut result = [0u8; LOCATOR_LEN];
    result.copy_from_slice(&digest[..LOCATOR_LEN]);
    result
}

fn derive_public_mode_key(
    shared_secret: &[u8; PUBLIC_KEY_LEN],
    context: &[u8; CONTEXT_HASH_LEN],
    ephemeral_public: &[u8; PUBLIC_KEY_LEN],
    recipient_public: &[u8; PUBLIC_KEY_LEN],
) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(context), shared_secret);
    let mut info = Vec::with_capacity(32 + PUBLIC_KEY_LEN * 2);
    info.extend(b"safechat/x25519-chacha20poly1305/v1");
    info.extend(ephemeral_public);
    info.extend(recipient_public);
    let mut key = [0u8; 32];
    hkdf.expand(&info, &mut key)
        .expect("32-byte HKDF output is valid");
    key
}

#[allow(clippy::too_many_arguments)]
fn public_signature_message(
    version: u8,
    suite: u8,
    context_hash: &[u8; CONTEXT_HASH_LEN],
    ephemeral_public: &[u8; PUBLIC_KEY_LEN],
    sender_identity_public: &[u8; IDENTITY_KEY_LEN],
    recipient_public: &[u8; PUBLIC_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Vec<u8> {
    let length = (ciphertext.len() as u32).to_be_bytes();
    let mut message = Vec::with_capacity(
        32 + 2
            + CONTEXT_HASH_LEN
            + PUBLIC_KEY_LEN
            + IDENTITY_KEY_LEN
            + PUBLIC_KEY_LEN
            + NONCE_LEN
            + 4
            + ciphertext.len(),
    );
    message.extend(b"safechat/public-auth/v1");
    message.extend([version, suite]);
    message.extend(context_hash);
    message.extend(ephemeral_public);
    message.extend(sender_identity_public);
    message.extend(recipient_public);
    message.extend(nonce);
    message.extend(length);
    message.extend(ciphertext);
    message
}

fn make_public_envelope(
    plaintext: &[u8],
    recipient_public: &[u8; PUBLIC_KEY_LEN],
    sender_identity_private: &[u8; IDENTITY_KEY_LEN],
    context: &str,
) -> Result<Vec<u8>> {
    let context_hash = context_hash(context);
    let mut ephemeral_bytes = [0u8; PUBLIC_KEY_LEN];
    OsRng.fill_bytes(&mut ephemeral_bytes);
    let ephemeral_secret = StaticSecret::from(ephemeral_bytes);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared_secret = ephemeral_secret.diffie_hellman(&PublicKey::from(*recipient_public));
    let encryption_key = derive_public_mode_key(
        shared_secret.as_bytes(),
        &context_hash,
        ephemeral_public.as_bytes(),
        recipient_public,
    );
    let signing_key = SigningKey::from_bytes(sender_identity_private);
    let sender_identity_public = signing_key.verifying_key();

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext_len = plaintext
        .len()
        .checked_add(16)
        .context("payload too large")?;
    let length = u32::try_from(ciphertext_len).context("payload exceeds MVP size limit")?;
    let mut aad =
        Vec::with_capacity(1 + 1 + CONTEXT_HASH_LEN + PUBLIC_KEY_LEN + IDENTITY_KEY_LEN + 4);
    aad.extend([VERSION, SUITE_X25519_CHACHA20_POLY1305_AUTHENTICATED]);
    aad.extend(context_hash);
    aad.extend(ephemeral_public.as_bytes());
    aad.extend(sender_identity_public.as_bytes());
    aad.extend(length.to_be_bytes());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&encryption_key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;

    let signature_message = public_signature_message(
        VERSION,
        SUITE_X25519_CHACHA20_POLY1305_AUTHENTICATED,
        &context_hash,
        ephemeral_public.as_bytes(),
        sender_identity_public.as_bytes(),
        recipient_public,
        &nonce_bytes,
        &ciphertext,
    );
    let signature = signing_key.sign(&signature_message);

    let mut envelope = Vec::with_capacity(
        LOCATOR_LEN
            + 1
            + 1
            + CONTEXT_HASH_LEN
            + PUBLIC_KEY_LEN
            + IDENTITY_KEY_LEN
            + NONCE_LEN
            + 4
            + ciphertext.len()
            + SIGNATURE_LEN,
    );
    envelope.extend(public_locator(ephemeral_public.as_bytes(), &context_hash));
    envelope.extend([VERSION, SUITE_X25519_CHACHA20_POLY1305_AUTHENTICATED]);
    envelope.extend(context_hash);
    envelope.extend(ephemeral_public.as_bytes());
    envelope.extend(sender_identity_public.as_bytes());
    envelope.extend(nonce_bytes);
    envelope.extend(length.to_be_bytes());
    envelope.extend(ciphertext);
    envelope.extend(signature.to_bytes());
    Ok(envelope)
}

fn open_envelope(envelope: &[u8], key: &[u8; 32], context: &str) -> Result<Vec<u8>> {
    if envelope.len() < LOCATOR_LEN + HEADER_LEN + 16 {
        bail!("envelope is too short");
    }
    let expected_context = context_hash(context);
    if envelope[..LOCATOR_LEN] != locator(key, &expected_context) {
        bail!("no matching authenticated payload");
    }
    let body = &envelope[LOCATOR_LEN..];
    if body[0] != VERSION {
        bail!("unsupported envelope version");
    }
    if body[1] != SUITE_CHACHA20_POLY1305 {
        bail!("unsupported encryption suite");
    }
    if body[2..2 + CONTEXT_HASH_LEN] != expected_context {
        bail!("context does not match");
    }
    let nonce_start = 2 + CONTEXT_HASH_LEN;
    let length_start = nonce_start + NONCE_LEN;
    let length = u32::from_be_bytes(body[length_start..length_start + 4].try_into()?) as usize;
    let ciphertext_start = length_start + 4;
    if length != body.len() - ciphertext_start {
        bail!("invalid envelope length");
    }
    if length < 16 {
        bail!("invalid ciphertext length");
    }
    let mut aad = Vec::with_capacity(1 + 1 + CONTEXT_HASH_LEN + 4);
    aad.extend([body[0], body[1]]);
    aad.extend(&body[2..2 + CONTEXT_HASH_LEN]);
    aad.extend((length as u32).to_be_bytes());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(&body[nonce_start..length_start]),
            chacha20poly1305::aead::Payload {
                msg: &body[ciphertext_start..],
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("authentication failed"))
}

fn open_public_envelope(
    envelope: &[u8],
    private_key: &[u8; PUBLIC_KEY_LEN],
    trusted_sender_identity_public: &[u8; IDENTITY_KEY_LEN],
    context: &str,
) -> Result<Vec<u8>> {
    let minimum = LOCATOR_LEN
        + 1
        + 1
        + CONTEXT_HASH_LEN
        + PUBLIC_KEY_LEN
        + IDENTITY_KEY_LEN
        + NONCE_LEN
        + 4
        + 16
        + SIGNATURE_LEN;
    if envelope.len() < minimum {
        bail!("public-key envelope is too short");
    }
    let body = &envelope[LOCATOR_LEN..];
    if body[0] != VERSION {
        bail!("unsupported envelope version");
    }
    if body[1] != SUITE_X25519_CHACHA20_POLY1305_AUTHENTICATED {
        bail!("unsupported encryption suite");
    }
    let expected_context = context_hash(context);
    if body[2..2 + CONTEXT_HASH_LEN] != expected_context {
        bail!("context does not match");
    }
    let ephemeral_start = 2 + CONTEXT_HASH_LEN;
    let ephemeral_end = ephemeral_start + PUBLIC_KEY_LEN;
    let ephemeral_bytes: [u8; PUBLIC_KEY_LEN] = body[ephemeral_start..ephemeral_end].try_into()?;
    if envelope[..LOCATOR_LEN] != public_locator(&ephemeral_bytes, &expected_context) {
        bail!("no matching public-key payload");
    }
    let sender_start = ephemeral_end;
    let sender_end = sender_start + IDENTITY_KEY_LEN;
    let sender_identity_bytes: [u8; IDENTITY_KEY_LEN] =
        body[sender_start..sender_end].try_into()?;
    if sender_identity_bytes != *trusted_sender_identity_public {
        bail!("sender identity does not match trusted public key");
    }
    let nonce_start = sender_end;
    let length_start = nonce_start + NONCE_LEN;
    let length = u32::from_be_bytes(body[length_start..length_start + 4].try_into()?) as usize;
    let ciphertext_start = length_start + 4;
    let ciphertext_end = ciphertext_start
        .checked_add(length)
        .context("envelope length overflow")?;
    let signature_start = ciphertext_end;
    let signature_end = signature_start + SIGNATURE_LEN;
    if length < 16 || signature_end != body.len() {
        bail!("invalid public-key envelope length");
    }
    let private_secret = StaticSecret::from(*private_key);
    let recipient_public = PublicKey::from(&private_secret);
    let shared_secret = private_secret.diffie_hellman(&PublicKey::from(ephemeral_bytes));
    let encryption_key = derive_public_mode_key(
        shared_secret.as_bytes(),
        &expected_context,
        &ephemeral_bytes,
        recipient_public.as_bytes(),
    );
    let signature_message = public_signature_message(
        body[0],
        body[1],
        &expected_context,
        &ephemeral_bytes,
        &sender_identity_bytes,
        recipient_public.as_bytes(),
        body[nonce_start..length_start].try_into()?,
        &body[ciphertext_start..ciphertext_end],
    );
    let verifying_key = VerifyingKey::from_bytes(trusted_sender_identity_public)
        .context("invalid trusted sender public key")?;
    let signature = Signature::from_bytes(body[signature_start..signature_end].try_into()?);
    verifying_key
        .verify(&signature_message, &signature)
        .map_err(|_| anyhow::anyhow!("sender signature verification failed"))?;

    let mut aad =
        Vec::with_capacity(1 + 1 + CONTEXT_HASH_LEN + PUBLIC_KEY_LEN + IDENTITY_KEY_LEN + 4);
    aad.extend([body[0], body[1]]);
    aad.extend(&body[2..2 + CONTEXT_HASH_LEN]);
    aad.extend(&body[ephemeral_start..ephemeral_end]);
    aad.extend(&body[sender_start..sender_end]);
    aad.extend((length as u32).to_be_bytes());
    ChaCha20Poly1305::new(Key::from_slice(&encryption_key))
        .decrypt(
            Nonce::from_slice(&body[nonce_start..length_start]),
            chacha20poly1305::aead::Payload {
                msg: &body[ciphertext_start..ciphertext_end],
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("authentication failed"))
}

fn read_png(path: &PathBuf) -> Result<RgbaImage> {
    let file =
        fs::File::open(path).with_context(|| format!("opening carrier {}", path.display()))?;
    let mut decoder = Decoder::new(file);
    decoder.set_transformations(Transformations::EXPAND | Transformations::STRIP_16);
    let mut reader = decoder.read_info().context("reading PNG header")?;
    let mut buffer = vec![0; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buffer).context("decoding PNG")?;
    let data = &buffer[..info.buffer_size()];
    let pixels = match info.color_type {
        ColorType::Rgb => data
            .chunks_exact(3)
            .flat_map(|p| [p[0], p[1], p[2], 255])
            .collect(),
        ColorType::Rgba => data.to_vec(),
        _ => bail!("PNG must decode to RGB or RGBA"),
    };
    Ok(RgbaImage {
        width: info.width,
        height: info.height,
        pixels,
    })
}

fn write_png(path: &PathBuf, image: &RgbaImage) -> Result<()> {
    let file =
        fs::File::create(path).with_context(|| format!("creating output {}", path.display()))?;
    let mut encoder = Encoder::new(file, image.width, image.height);
    encoder.set_color(ColorType::Rgba);
    encoder.set_depth(BitDepth::Eight);
    let mut writer = encoder.write_header().context("writing PNG header")?;
    writer
        .write_image_data(&image.pixels)
        .context("writing PNG pixels")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_envelope(
    plaintext: &[u8],
    key_path: Option<&PathBuf>,
    mode: EncryptionMode,
    recipient_public_key_path: Option<&PathBuf>,
    sender_private_key_path: Option<&PathBuf>,
    context: &str,
) -> Result<Vec<u8>> {
    match mode {
        EncryptionMode::Symmetric => {
            if recipient_public_key_path.is_some() {
                bail!("--recipient-public-key is only valid with --mode public");
            }
            if sender_private_key_path.is_some() {
                bail!("--sender-private-key is only valid with --mode public");
            }
            let key_path = key_path.context("symmetric mode requires --key")?;
            let key = load_symmetric_key(key_path)?;
            make_envelope(plaintext, &key, context)
        }
        EncryptionMode::Public => {
            if key_path.is_some() {
                bail!("--key is only valid with --mode symmetric");
            }
            let public_path =
                recipient_public_key_path.context("public mode requires --recipient-public-key")?;
            let public_key = load_public_key(public_path)?;
            let sender_path =
                sender_private_key_path.context("public mode requires --sender-private-key")?;
            let sender_private_key = load_identity_private_key(sender_path)?;
            make_public_envelope(plaintext, &public_key, &sender_private_key, context)
        }
        EncryptionMode::Identity => bail!("identity mode is only valid with keygen"),
    }
}

fn open_mode_envelope(
    envelope: &[u8],
    key_path: Option<&PathBuf>,
    mode: EncryptionMode,
    private_key_path: Option<&PathBuf>,
    trusted_sender_public_key_path: Option<&PathBuf>,
    context: &str,
) -> Result<Vec<u8>> {
    if private_key_path.is_some() && !matches!(mode, EncryptionMode::Public) {
        bail!("--private-key is only valid with --mode public");
    }
    if trusted_sender_public_key_path.is_some() && !matches!(mode, EncryptionMode::Public) {
        bail!("--trusted-sender-public-key is only valid with --mode public");
    }
    match mode {
        EncryptionMode::Symmetric => {
            let key_path = key_path.context("symmetric mode requires --key")?;
            let key = load_symmetric_key(key_path)?;
            open_envelope(envelope, &key, context)
        }
        EncryptionMode::Public => {
            if key_path.is_some() {
                bail!("--key is only valid with --mode symmetric");
            }
            let private_path = private_key_path.context("public mode requires --private-key")?;
            let private_key = load_private_key(private_path)?;
            let trusted_sender_path = trusted_sender_public_key_path
                .context("public mode requires --trusted-sender-public-key")?;
            let trusted_sender_public = load_identity_public_key(trusted_sender_path)?;
            open_public_envelope(envelope, &private_key, &trusted_sender_public, context)
        }
        EncryptionMode::Identity => bail!("identity mode is only valid with keygen"),
    }
}

#[allow(clippy::too_many_arguments)]
fn text_encode(
    input: &PathBuf,
    output: &PathBuf,
    key_path: Option<&PathBuf>,
    mode: EncryptionMode,
    recipient_public_key_path: Option<&PathBuf>,
    sender_private_key_path: Option<&PathBuf>,
    context: &str,
) -> Result<()> {
    let plaintext =
        fs::read(input).with_context(|| format!("reading input {}", input.display()))?;
    let envelope = build_envelope(
        &plaintext,
        key_path,
        mode,
        recipient_public_key_path,
        sender_private_key_path,
        context,
    )?;
    let encoded = TextTransport.encode(&envelope);
    fs::write(output, encoded)
        .with_context(|| format!("writing text message {}", output.display()))?;
    println!(
        "encoded {} bytes into {}",
        plaintext.len(),
        output.display()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn text_decode(
    input: &PathBuf,
    output: &PathBuf,
    key_path: Option<&PathBuf>,
    mode: EncryptionMode,
    private_key_path: Option<&PathBuf>,
    trusted_sender_public_key_path: Option<&PathBuf>,
    context: &str,
) -> Result<()> {
    let text = fs::read_to_string(input)
        .with_context(|| format!("reading text message {}", input.display()))?;
    let envelope = TextTransport.decode(&text)?;
    let plaintext = open_mode_envelope(
        &envelope,
        key_path,
        mode,
        private_key_path,
        trusted_sender_public_key_path,
        context,
    )?;
    fs::write(output, plaintext).with_context(|| format!("writing output {}", output.display()))?;
    println!("decoded text message to {}", output.display());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn encode(
    input: &PathBuf,
    carrier: &PathBuf,
    output: &PathBuf,
    key_path: Option<&PathBuf>,
    mode: EncryptionMode,
    recipient_public_key_path: Option<&PathBuf>,
    sender_private_key_path: Option<&PathBuf>,
    context: &str,
) -> Result<()> {
    let plaintext =
        fs::read(input).with_context(|| format!("reading input {}", input.display()))?;
    let envelope = build_envelope(
        &plaintext,
        key_path,
        mode,
        recipient_public_key_path,
        sender_private_key_path,
        context,
    )?;
    let mut image = read_png(carrier)?;
    PngCarrier.embed(&mut image, &envelope)?;
    write_png(output, &image)?;
    println!(
        "encoded {} bytes into {}",
        plaintext.len(),
        output.display()
    );
    Ok(())
}

fn decode(
    input: &PathBuf,
    output: &PathBuf,
    key_path: Option<&PathBuf>,
    mode: EncryptionMode,
    private_key_path: Option<&PathBuf>,
    trusted_sender_public_key_path: Option<&PathBuf>,
    context: &str,
) -> Result<()> {
    if private_key_path.is_some() && !matches!(mode, EncryptionMode::Public) {
        bail!("--private-key is only valid with --mode public");
    }
    if trusted_sender_public_key_path.is_some() && !matches!(mode, EncryptionMode::Public) {
        bail!("--trusted-sender-public-key is only valid with --mode public");
    }
    let image = read_png(input)?;
    if PngCarrier.capacity_bytes(&image) < LOCATOR_LEN + 2 {
        bail!("carrier is too small");
    }
    let suite_prefix = PngCarrier.extract(&image, LOCATOR_LEN + 2)?;
    let suite = suite_prefix[LOCATOR_LEN + 1];
    let (header_len, length_start) = match suite {
        SUITE_CHACHA20_POLY1305 => (
            HEADER_LEN,
            LOCATOR_LEN + 1 + 1 + CONTEXT_HASH_LEN + NONCE_LEN,
        ),
        SUITE_X25519_CHACHA20_POLY1305_AUTHENTICATED => (
            1 + 1 + CONTEXT_HASH_LEN + PUBLIC_KEY_LEN + IDENTITY_KEY_LEN + NONCE_LEN + 4,
            LOCATOR_LEN + 1 + 1 + CONTEXT_HASH_LEN + PUBLIC_KEY_LEN + IDENTITY_KEY_LEN + NONCE_LEN,
        ),
        _ => bail!("unsupported encryption suite"),
    };
    let expected_mode = if suite == SUITE_CHACHA20_POLY1305 {
        EncryptionMode::Symmetric
    } else {
        EncryptionMode::Public
    };
    if std::mem::discriminant(&mode) != std::mem::discriminant(&expected_mode) {
        bail!("selected encryption mode does not match the envelope");
    }
    let prefix = PngCarrier.extract(&image, length_start + 4)?;
    let ciphertext_len =
        u32::from_be_bytes(prefix[length_start..length_start + 4].try_into()?) as usize;
    let signature_len = if suite == SUITE_X25519_CHACHA20_POLY1305_AUTHENTICATED {
        SIGNATURE_LEN
    } else {
        0
    };
    let total_len = LOCATOR_LEN + header_len + ciphertext_len + signature_len;
    let envelope = PngCarrier.extract(&image, total_len)?;
    let plaintext = match mode {
        EncryptionMode::Symmetric => {
            if private_key_path.is_some() {
                bail!("--private-key is only valid with --mode public");
            }
            let key_path = key_path.context("symmetric mode requires --key")?;
            let key = load_symmetric_key(key_path)?;
            open_envelope(&envelope, &key, context)?
        }
        EncryptionMode::Public => {
            if key_path.is_some() {
                bail!("--key is only valid with --mode symmetric");
            }
            let private_path = private_key_path.context("public mode requires --private-key")?;
            let private_key = load_private_key(private_path)?;
            let trusted_sender_path = trusted_sender_public_key_path
                .context("public mode requires --trusted-sender-public-key")?;
            let trusted_sender_public = load_identity_public_key(trusted_sender_path)?;
            open_public_envelope(&envelope, &private_key, &trusted_sender_public, context)?
        }
        EncryptionMode::Identity => {
            bail!("identity mode is only valid with keygen")
        }
    };
    fs::write(output, plaintext).with_context(|| format!("writing output {}", output.display()))?;
    println!("decoded message to {}", output.display());
    Ok(())
}

fn inspect(input: &PathBuf) -> Result<()> {
    let image = read_png(input)?;
    println!("format: PNG");
    println!("dimensions: {}x{}", image.width, image.height);
    println!("LSB capacity: {} bytes", PngCarrier.capacity_bytes(&image));
    println!("note: this MVP supports local PNG carriers only");
    Ok(())
}

fn changed_lsb_count(reference: &RgbaImage, candidate: &RgbaImage) -> Result<usize> {
    if reference.width != candidate.width || reference.height != candidate.height {
        bail!("reference and candidate dimensions do not match");
    }
    Ok(reference
        .pixels
        .chunks_exact(4)
        .zip(candidate.pixels.chunks_exact(4))
        .flat_map(|(reference_pixel, candidate_pixel)| {
            reference_pixel[..3].iter().zip(&candidate_pixel[..3]).map(
                |(reference_channel, candidate_channel)| {
                    usize::from((reference_channel & 1) != (candidate_channel & 1))
                },
            )
        })
        .sum())
}

fn detect(reference_path: &PathBuf, candidate_path: &PathBuf) -> Result<()> {
    let reference = read_png(reference_path)?;
    let candidate = read_png(candidate_path)?;
    let changed = changed_lsb_count(&reference, &candidate)?;
    let inspected = reference.pixels.len() / 4 * 3;
    let percentage = changed as f64 / inspected as f64 * 100.0;
    println!("reference: {}", reference_path.display());
    println!("candidate: {}", candidate_path.display());
    println!("changed RGB LSBs: {changed} of {inspected} ({percentage:.4}%)");
    println!(
        "verdict: {}",
        if changed > 0 {
            "modified LSBs detected"
        } else {
            "no RGB LSB changes detected"
        }
    );
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct BlindFeatures {
    prefix_balance: f64,
    suffix_balance: f64,
    prefix_transitions: f64,
    suffix_transitions: f64,
    score: f64,
}

fn lsb_bits(image: &RgbaImage) -> Vec<u8> {
    image
        .pixels
        .chunks_exact(4)
        .flat_map(|pixel| pixel[..3].iter().map(|channel| channel & 1))
        .collect()
}

fn bit_balance(bits: &[u8]) -> f64 {
    if bits.is_empty() {
        return 0.0;
    }
    bits.iter().map(|bit| f64::from(*bit)).sum::<f64>() / bits.len() as f64
}

fn transition_rate(bits: &[u8]) -> f64 {
    if bits.len() < 2 {
        return 0.0;
    }
    bits.windows(2).filter(|pair| pair[0] != pair[1]).count() as f64 / (bits.len() - 1) as f64
}

fn blind_features(image: &RgbaImage, window_bits: usize) -> Result<BlindFeatures> {
    let bits = lsb_bits(image);
    if window_bits < 16 || window_bits >= bits.len() {
        bail!("window_bits must be between 16 and the carrier bit count");
    }
    let prefix = &bits[..window_bits];
    let suffix = &bits[window_bits..];
    let prefix_balance = bit_balance(prefix);
    let suffix_balance = bit_balance(suffix);
    let prefix_transitions = transition_rate(prefix);
    let suffix_transitions = transition_rate(suffix);
    let score =
        (prefix_balance - suffix_balance).abs() + (prefix_transitions - suffix_transitions).abs();
    Ok(BlindFeatures {
        prefix_balance,
        suffix_balance,
        prefix_transitions,
        suffix_transitions,
        score,
    })
}

fn blind_detect(input: &PathBuf, window_bits: usize, threshold: f64) -> Result<()> {
    if !threshold.is_finite() || threshold < 0.0 {
        bail!("threshold must be a finite non-negative number");
    }
    let image = read_png(input)?;
    let features = blind_features(&image, window_bits)?;
    println!("input: {}", input.display());
    println!("window bits: {window_bits}");
    println!("prefix bit balance: {:.6}", features.prefix_balance);
    println!("suffix bit balance: {:.6}", features.suffix_balance);
    println!("prefix transition rate: {:.6}", features.prefix_transitions);
    println!("suffix transition rate: {:.6}", features.suffix_transitions);
    println!("blind score: {:.6}", features.score);
    println!("threshold: {threshold:.6}");
    println!(
        "verdict: {}",
        if features.score >= threshold {
            "statistically suspicious"
        } else {
            "not flagged by this baseline"
        }
    );
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct BenchmarkSample {
    score: f64,
    encoded: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct Confusion {
    true_positive: usize,
    false_positive: usize,
    true_negative: usize,
    false_negative: usize,
}

impl Confusion {
    fn accuracy(self) -> f64 {
        let total =
            self.true_positive + self.false_positive + self.true_negative + self.false_negative;
        if total == 0 {
            0.0
        } else {
            (self.true_positive + self.true_negative) as f64 / total as f64
        }
    }

    fn false_positive_rate(self) -> f64 {
        let denominator = self.false_positive + self.true_negative;
        if denominator == 0 {
            0.0
        } else {
            self.false_positive as f64 / denominator as f64
        }
    }

    fn false_negative_rate(self) -> f64 {
        let denominator = self.false_negative + self.true_positive;
        if denominator == 0 {
            0.0
        } else {
            self.false_negative as f64 / denominator as f64
        }
    }
}

fn png_paths(dir: &PathBuf) -> Result<Vec<PathBuf>> {
    let mut paths = fs::read_dir(dir)
        .with_context(|| format!("reading benchmark directory {}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("png"))
        })
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn classify(samples: &[BenchmarkSample], threshold: f64) -> Confusion {
    samples
        .iter()
        .fold(Confusion::default(), |mut result, sample| {
            let predicted_encoded = sample.score >= threshold;
            match (sample.encoded, predicted_encoded) {
                (true, true) => result.true_positive += 1,
                (false, true) => result.false_positive += 1,
                (false, false) => result.true_negative += 1,
                (true, false) => result.false_negative += 1,
            }
            result
        })
}

fn benchmark(clean_dir: &PathBuf, encoded_dir: &PathBuf, window_bits: usize) -> Result<()> {
    let clean_paths = png_paths(clean_dir)?;
    let encoded_paths = png_paths(encoded_dir)?;
    if clean_paths.is_empty() || encoded_paths.is_empty() {
        bail!("benchmark requires at least one clean and one encoded PNG");
    }

    let mut samples = Vec::with_capacity(clean_paths.len() + encoded_paths.len());
    for path in clean_paths {
        let image = read_png(&path)?;
        samples.push(BenchmarkSample {
            score: blind_features(&image, window_bits)?.score,
            encoded: false,
        });
    }
    for path in encoded_paths {
        let image = read_png(&path)?;
        samples.push(BenchmarkSample {
            score: blind_features(&image, window_bits)?.score,
            encoded: true,
        });
    }

    let mut thresholds = samples
        .iter()
        .map(|sample| sample.score)
        .collect::<Vec<_>>();
    thresholds.sort_by(f64::total_cmp);
    thresholds.dedup_by(|left, right| left == right);
    let mut best_threshold = thresholds[0];
    let mut best = classify(&samples, best_threshold);
    for threshold in thresholds {
        let current = classify(&samples, threshold);
        if current.accuracy() > best.accuracy()
            || (current.accuracy() == best.accuracy()
                && current.false_positive_rate() < best.false_positive_rate())
        {
            best_threshold = threshold;
            best = current;
        }
    }

    println!(
        "clean samples: {}",
        samples.iter().filter(|sample| !sample.encoded).count()
    );
    println!(
        "encoded samples: {}",
        samples.iter().filter(|sample| sample.encoded).count()
    );
    println!("window bits: {window_bits}");
    println!("best corpus threshold: {best_threshold:.6}");
    println!("accuracy: {:.4}", best.accuracy());
    println!("false-positive rate: {:.4}", best.false_positive_rate());
    println!("false-negative rate: {:.4}", best.false_negative_rate());
    println!("true positives: {}", best.true_positive);
    println!("false positives: {}", best.false_positive);
    println!("true negatives: {}", best.true_negative);
    println!("false negatives: {}", best.false_negative);
    println!("warning: threshold is fitted and evaluated on the same corpus");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn envelope_round_trip_authenticates_context() {
        let key = test_key();
        let envelope = make_envelope(b"private test message", &key, "test-context").unwrap();
        assert_eq!(
            open_envelope(&envelope, &key, "test-context").unwrap(),
            b"private test message"
        );
        assert!(open_envelope(&envelope, &key, "wrong-context").is_err());
    }

    #[test]
    fn envelope_rejects_tampering() {
        let key = test_key();
        let mut envelope = make_envelope(b"message", &key, "context").unwrap();
        *envelope.last_mut().unwrap() ^= 1;
        assert!(open_envelope(&envelope, &key, "context").is_err());
    }

    #[test]
    fn public_envelope_round_trip_and_wrong_key_rejection() {
        let recipient_secret = [9u8; 32];
        let recipient_public = PublicKey::from(&StaticSecret::from(recipient_secret));
        let sender_secret = [3u8; IDENTITY_KEY_LEN];
        let sender_public = SigningKey::from_bytes(&sender_secret).verifying_key();
        let envelope = make_public_envelope(
            b"public-key message",
            recipient_public.as_bytes(),
            &sender_secret,
            "public-context",
        )
        .unwrap();
        assert_eq!(
            open_public_envelope(
                &envelope,
                &recipient_secret,
                sender_public.as_bytes(),
                "public-context"
            )
            .unwrap(),
            b"public-key message"
        );
        assert!(
            open_public_envelope(
                &envelope,
                &[8u8; 32],
                sender_public.as_bytes(),
                "public-context"
            )
            .is_err()
        );
        assert!(
            open_public_envelope(
                &envelope,
                &recipient_secret,
                &[4u8; IDENTITY_KEY_LEN],
                "public-context"
            )
            .is_err()
        );
        assert!(
            open_public_envelope(
                &envelope,
                &recipient_secret,
                sender_public.as_bytes(),
                "wrong"
            )
            .is_err()
        );
        let mut tampered = envelope;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(
            open_public_envelope(
                &tampered,
                &recipient_secret,
                sender_public.as_bytes(),
                "public-context"
            )
            .is_err()
        );
    }

    #[test]
    fn carrier_bits_round_trip() {
        let mut image = RgbaImage {
            width: 16,
            height: 16,
            pixels: vec![255; 16 * 16 * 4],
        };
        let payload = b"carrier payload";
        PngCarrier.embed(&mut image, payload).unwrap();
        assert_eq!(PngCarrier.extract(&image, payload.len()).unwrap(), payload);
        assert!(PngCarrier.embed(&mut image, &[0u8; 200]).is_err());
    }

    #[test]
    fn text_transport_round_trip() {
        let message = TextTransport.encode(b"protocol payload");
        assert!(message.starts_with("safechat-text-v1:"));
        assert_eq!(TextTransport.decode(&message).unwrap(), b"protocol payload");
        assert!(TextTransport.decode("not-safechat").is_err());
    }

    #[test]
    fn handshake_derivation_is_symmetric() {
        let initiator_secret = StaticSecret::from([1u8; 32]);
        let recipient_secret = StaticSecret::from([2u8; 32]);
        let prekey_secret = StaticSecret::from([3u8; 32]);
        let initiator_public = PublicKey::from(&initiator_secret);
        let recipient_public = PublicKey::from(&recipient_secret);
        let prekey_public = PublicKey::from(&prekey_secret);
        let initiator_identity = [4u8; IDENTITY_KEY_LEN];
        let initiator_first = initiator_secret.diffie_hellman(&recipient_public);
        let initiator_second = initiator_secret.diffie_hellman(&prekey_public);
        let recipient_first = recipient_secret.diffie_hellman(&initiator_public);
        let recipient_second = prekey_secret.diffie_hellman(&initiator_public);
        let initiator_session = derive_handshake_session(
            initiator_first.as_bytes(),
            initiator_second.as_bytes(),
            recipient_public.as_bytes(),
            prekey_public.as_bytes(),
            initiator_public.as_bytes(),
            &initiator_identity,
        );
        let recipient_session = derive_handshake_session(
            recipient_first.as_bytes(),
            recipient_second.as_bytes(),
            recipient_public.as_bytes(),
            prekey_public.as_bytes(),
            initiator_public.as_bytes(),
            &initiator_identity,
        );
        assert_eq!(initiator_session, recipient_session);
    }

    #[test]
    fn png_io_round_trip() {
        let path =
            std::env::temp_dir().join(format!("safechat-png-test-{}.png", std::process::id()));
        let image = RgbaImage {
            width: 32,
            height: 32,
            pixels: vec![127; 32 * 32 * 4],
        };
        write_png(&path, &image).unwrap();
        let loaded = read_png(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!((loaded.width, loaded.height), (32, 32));
        assert_eq!(loaded.pixels, image.pixels);
    }

    #[test]
    fn detector_detects_current_lsb_embedding() {
        let reference = RgbaImage {
            width: 32,
            height: 32,
            pixels: vec![127; 32 * 32 * 4],
        };
        let mut candidate = RgbaImage {
            width: reference.width,
            height: reference.height,
            pixels: reference.pixels.clone(),
        };
        PngCarrier.embed(&mut candidate, b"detector test").unwrap();
        assert!(changed_lsb_count(&reference, &candidate).unwrap() > 0);
        assert_eq!(changed_lsb_count(&reference, &reference).unwrap(), 0);
    }

    #[test]
    fn blind_features_are_bounded() {
        let image = RgbaImage {
            width: 32,
            height: 32,
            pixels: vec![127; 32 * 32 * 4],
        };
        let features = blind_features(&image, 1024).unwrap();
        assert!((0.0..=1.0).contains(&features.prefix_balance));
        assert!((0.0..=1.0).contains(&features.suffix_balance));
        assert!(features.score.is_finite());
    }
}
