use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use clap::{Parser, Subcommand};
use hmac::{Hmac, Mac};
use png::{BitDepth, ColorType, Decoder, Encoder, Transformations};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

type HmacSha256 = Hmac<Sha256>;

const VERSION: u8 = 1;
const SUITE_CHACHA20_POLY1305: u8 = 1;
const LOCATOR_LEN: usize = 16;
const CONTEXT_HASH_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 1 + 1 + CONTEXT_HASH_LEN + NONCE_LEN + 4;

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
    },
    Encode {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        carrier: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = "")]
        context: String,
    },
    Decode {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        key: PathBuf,
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
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen { output } => keygen(&output),
        Command::Encode {
            input,
            carrier,
            output,
            key,
            context,
        } => encode(&input, &carrier, &output, &key, &context),
        Command::Decode {
            input,
            output,
            key,
            context,
        } => decode(&input, &output, &key, &context),
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
    }
}

fn keygen(path: &PathBuf) -> Result<()> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let encoded = STANDARD_NO_PAD.encode(key);
    fs::write(path, format!("safechat-key-v1:{encoded}\n"))
        .with_context(|| format!("writing key file {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("protecting key file {}", path.display()))?;
    }
    println!("generated key: {}", path.display());
    Ok(())
}

fn load_key(path: &PathBuf) -> Result<[u8; 32]> {
    let text =
        fs::read_to_string(path).with_context(|| format!("reading key file {}", path.display()))?;
    let encoded = text
        .trim()
        .strip_prefix("safechat-key-v1:")
        .context("invalid key file header")?;
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

struct RgbaImage {
    width: u32,
    height: u32,
    pixels: Vec<u8>,
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

fn bits_from_bytes(bytes: &[u8]) -> impl Iterator<Item = u8> + '_ {
    bytes
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |bit| (byte >> bit) & 1))
}

fn bytes_from_bits(bits: &[u8]) -> Vec<u8> {
    bits.chunks_exact(8)
        .map(|chunk| chunk.iter().fold(0, |value, bit| (value << 1) | bit))
        .collect()
}

fn capacity_bytes(image: &RgbaImage) -> usize {
    image.pixels.len() / 4 * 3 / 8
}

fn embed(image: &mut RgbaImage, payload: &[u8]) -> Result<()> {
    if payload.len() > capacity_bytes(image) {
        bail!(
            "payload requires {} bytes, carrier capacity is {} bytes",
            payload.len(),
            capacity_bytes(image)
        );
    }
    let mut bits = bits_from_bytes(payload);
    for pixel in image.pixels.chunks_exact_mut(4) {
        for channel in &mut pixel[..3] {
            if let Some(bit) = bits.next() {
                *channel = (*channel & 0xfe) | bit;
            } else {
                return Ok(());
            }
        }
    }
    Ok(())
}

fn extract(image: &RgbaImage, length: usize) -> Result<Vec<u8>> {
    if length > capacity_bytes(image) {
        bail!("declared payload exceeds carrier capacity");
    }
    let bit_count = length.checked_mul(8).context("payload size overflow")?;
    let mut bits = Vec::with_capacity(bit_count);
    for pixel in image.pixels.chunks_exact(4) {
        for channel in &pixel[..3] {
            if bits.len() == bit_count {
                return Ok(bytes_from_bits(&bits));
            }
            bits.push(channel & 1);
        }
    }
    if bits.len() != bit_count {
        bail!("carrier ended before payload completed");
    }
    Ok(bytes_from_bits(&bits))
}

fn encode(
    input: &PathBuf,
    carrier: &PathBuf,
    output: &PathBuf,
    key_path: &PathBuf,
    context: &str,
) -> Result<()> {
    let key = load_key(key_path)?;
    let plaintext =
        fs::read(input).with_context(|| format!("reading input {}", input.display()))?;
    let envelope = make_envelope(&plaintext, &key, context)?;
    let mut image = read_png(carrier)?;
    embed(&mut image, &envelope)?;
    write_png(output, &image)?;
    println!(
        "encoded {} bytes into {}",
        plaintext.len(),
        output.display()
    );
    Ok(())
}

fn decode(input: &PathBuf, output: &PathBuf, key_path: &PathBuf, context: &str) -> Result<()> {
    let key = load_key(key_path)?;
    let image = read_png(input)?;
    if capacity_bytes(&image) < LOCATOR_LEN + HEADER_LEN + 16 {
        bail!("carrier is too small");
    }
    let prefix = extract(&image, LOCATOR_LEN + HEADER_LEN)?;
    let length_start = LOCATOR_LEN + 1 + 1 + CONTEXT_HASH_LEN + NONCE_LEN;
    let ciphertext_len =
        u32::from_be_bytes(prefix[length_start..length_start + 4].try_into()?) as usize;
    let total_len = LOCATOR_LEN + HEADER_LEN + ciphertext_len;
    let envelope = extract(&image, total_len)?;
    let plaintext = open_envelope(&envelope, &key, context)?;
    fs::write(output, plaintext).with_context(|| format!("writing output {}", output.display()))?;
    println!("decoded message to {}", output.display());
    Ok(())
}

fn inspect(input: &PathBuf) -> Result<()> {
    let image = read_png(input)?;
    println!("format: PNG");
    println!("dimensions: {}x{}", image.width, image.height);
    println!("LSB capacity: {} bytes", capacity_bytes(&image));
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
    fn carrier_bits_round_trip() {
        let mut image = RgbaImage {
            width: 16,
            height: 16,
            pixels: vec![255; 16 * 16 * 4],
        };
        let payload = b"carrier payload";
        embed(&mut image, payload).unwrap();
        assert_eq!(extract(&image, payload.len()).unwrap(), payload);
        assert!(embed(&mut image, &[0u8; 200]).is_err());
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
        embed(&mut candidate, b"detector test").unwrap();
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
