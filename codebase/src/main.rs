use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
use dialoguer::Password;
use png::{ColorType, Decoder, Encoder, Transformations};
use std::{fs, path::PathBuf};

mod carrier;

use carrier::{CarrierAdapter, PngCarrier, RgbaImage};
use safechat::{
    signal_adapter,
    transport::{BundleTransport, TextTransport},
};

#[derive(Parser)]
#[command(
    name = "safechat",
    version,
    about = "SafeChat protocol and detector tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage a persistent Signal device and its peer sessions.
    Signal {
        #[command(subcommand)]
        command: SignalCommand,
    },
    /// Exercise official libsignal session setup, encryption, decryption, and restart recovery.
    SignalDemo,
    /// Compare RGB least-significant bits between an original and candidate PNG.
    Detect {
        #[arg(long)]
        reference: PathBuf,
        #[arg(long)]
        candidate: PathBuf,
    },
    /// Run the blind baseline detector against one PNG.
    BlindDetect {
        input: PathBuf,
        #[arg(long, default_value_t = 1024)]
        window_bits: usize,
        #[arg(long, default_value_t = 0.05)]
        threshold: f64,
    },
    /// Fit and report the blind detector on clean and encoded PNG corpora.
    Benchmark {
        #[arg(long)]
        clean_dir: PathBuf,
        #[arg(long)]
        encoded_dir: PathBuf,
        #[arg(long, default_value_t = 1024)]
        window_bits: usize,
    },
    /// Report PNG dimensions and the evaluation adapter capacity.
    Inspect { input: PathBuf },
    /// Embed opaque bytes into a PNG using the current evaluation carrier.
    Embed {
        carrier: PathBuf,
        payload: PathBuf,
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum SignalCommand {
    /// Create or validate a local Signal device database.
    Init {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        user: String,
        #[arg(long, default_value_t = 1)]
        device_id: u8,
    },
    /// Export Bob's public prekey bundle for Alice to receive out of band.
    Bundle {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Write the public bundle as URL-safe Base64 text.
        #[arg(long)]
        base64: bool,
    },
    /// Trust a verified bundle identity for a peer.
    Trust {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
        /// Exact fingerprint verified through the separate trusted channel.
        #[arg(long)]
        fingerprint: String,
        /// Read the public bundle as URL-safe Base64 text.
        #[arg(long)]
        base64: bool,
    },
    /// Encrypt a plaintext using a trusted peer's prekey bundle.
    Encrypt {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Write the carrier-neutral envelope as URL-safe Base64 text.
        #[arg(long)]
        base64: bool,
    },
    /// Decrypt a SafeChat Signal envelope received from a trusted peer.
    Decrypt {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        sender: String,
        #[arg(long, default_value_t = 1)]
        sender_device_id: u8,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Read the input as URL-safe Base64 text instead of binary bytes.
        #[arg(long)]
        base64: bool,
    },
    /// Print the public identity key needed by a relay administrator.
    IdentityKey {
        #[arg(long)]
        database: PathBuf,
    },
}

fn main() -> Result<()> {
    let _signal_revision = signal_adapter::upstream_revision();
    match Cli::parse().command {
        Command::Signal { command } => run_signal_command(command),
        Command::SignalDemo => {
            let plaintext = signal_adapter::run_signal_demo()?;
            println!(
                "libsignal round trip succeeded: {}",
                String::from_utf8_lossy(&plaintext)
            );
            Ok(())
        }
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
        Command::Inspect { input } => inspect(&input),
        Command::Embed {
            carrier,
            payload,
            output,
        } => embed(&carrier, &payload, &output),
    }
}

fn run_signal_command(command: SignalCommand) -> Result<()> {
    futures_executor::block_on(async move {
        match command {
            SignalCommand::Init {
                database,
                user,
                device_id,
            } => {
                let password = database_password()?;
                let state = signal_adapter::SqliteSignalState::initialize(
                    &database, &user, device_id, &password,
                )
                .await?;
                println!("initialized {}", database.display());
                println!(
                    "identity fingerprint: {}",
                    state.local_identity_fingerprint().await?
                );
            }
            SignalCommand::Bundle {
                database,
                output,
                base64,
            } => {
                let password = database_password()?;
                let mut state =
                    signal_adapter::SqliteSignalState::open(&database, &password).await?;
                let bundle = state.export_bundle().await?;
                let encoded = bundle.encode()?;
                let output_bytes = if base64 {
                    BundleTransport.encode(&encoded).into_bytes()
                } else {
                    encoded
                };
                fs::write(&output, output_bytes)
                    .with_context(|| format!("writing bundle {}", output.display()))?;
                println!(
                    "wrote bundle for {} to {}",
                    bundle.address(),
                    output.display()
                );
                println!(
                    "identity fingerprint: {}",
                    signal_adapter::identity_fingerprint(&bundle.identity_key()?)
                );
            }
            SignalCommand::Trust {
                database,
                bundle,
                fingerprint,
                base64,
            } => {
                let password = database_password()?;
                let bundle_bytes = fs::read(&bundle).context("reading Signal bundle")?;
                let bundle_bytes = if base64 {
                    BundleTransport.decode(
                        std::str::from_utf8(&bundle_bytes)
                            .context("reading Base64 Signal bundle as text")?,
                    )?
                } else {
                    bundle_bytes
                };
                let bundle = signal_adapter::SignalPreKeyBundle::decode(&bundle_bytes)?;
                let actual = signal_adapter::identity_fingerprint(&bundle.identity_key()?);
                if actual != fingerprint {
                    bail!("bundle fingerprint does not match the verified fingerprint");
                }
                let mut state =
                    signal_adapter::SqliteSignalState::open(&database, &password).await?;
                state.trust_bundle(&bundle).await?;
                println!("trusted {}", bundle.address());
            }
            SignalCommand::Encrypt {
                database,
                bundle,
                input,
                output,
                base64,
            } => {
                let password = database_password()?;
                let bundle =
                    signal_adapter::SignalPreKeyBundle::decode(&read_bundle_bytes(&bundle)?)?;
                let plaintext = fs::read(&input)
                    .with_context(|| format!("reading input {}", input.display()))?;
                let mut state =
                    signal_adapter::SqliteSignalState::open(&database, &password).await?;
                let envelope = state.encrypt_for(&bundle, &plaintext).await?;
                let output_bytes = if base64 {
                    TextTransport.encode(&envelope).into_bytes()
                } else {
                    envelope
                };
                fs::write(&output, output_bytes)
                    .with_context(|| format!("writing encrypted output {}", output.display()))?;
                println!("encrypted message for {}", bundle.address());
            }
            SignalCommand::Decrypt {
                database,
                sender,
                sender_device_id,
                input,
                output,
                base64,
            } => {
                let password = database_password()?;
                let device = signal_protocol::DeviceId::new(sender_device_id)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                let sender_address = signal_protocol::ProtocolAddress::new(sender, device);
                let input_bytes = fs::read(&input)
                    .with_context(|| format!("reading encrypted input {}", input.display()))?;
                let envelope = if base64 {
                    TextTransport.decode(
                        std::str::from_utf8(&input_bytes)
                            .context("Base64 ciphertext is not UTF-8")?,
                    )?
                } else {
                    input_bytes
                };
                let mut state =
                    signal_adapter::SqliteSignalState::open(&database, &password).await?;
                let plaintext = state.decrypt_from(&sender_address, &envelope).await?;
                fs::write(&output, plaintext)
                    .with_context(|| format!("writing plaintext output {}", output.display()))?;
                println!("decrypted message from {}", sender_address);
            }
            SignalCommand::IdentityKey { database } => {
                let password = database_password()?;
                let state = signal_adapter::SqliteSignalState::open(&database, &password).await?;
                let identity = state.local_identity_key_pair().await?;
                println!(
                    "identity key: {}",
                    URL_SAFE_NO_PAD.encode(identity.identity_key().serialize().as_ref())
                );
                println!("fingerprint: {}", state.local_identity_fingerprint().await?);
            }
        }
        Ok(())
    })
}

fn database_password() -> Result<String> {
    Password::new()
        .with_prompt("Signal database password")
        .interact()
        .context("reading database password")
}

fn read_png(path: &PathBuf) -> Result<RgbaImage> {
    let file = fs::File::open(path).with_context(|| format!("opening PNG {}", path.display()))?;
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

fn read_bundle_bytes(path: &PathBuf) -> Result<Vec<u8>> {
    let bytes =
        fs::read(path).with_context(|| format!("reading Signal bundle {}", path.display()))?;
    if let Ok(text) = std::str::from_utf8(&bytes)
        && let Ok(bundle) = BundleTransport.decode(text)
    {
        return Ok(bundle);
    }
    Ok(bytes)
}

fn inspect(input: &PathBuf) -> Result<()> {
    let image = read_png(input)?;
    println!("format: PNG");
    println!("dimensions: {}x{}", image.width, image.height);
    println!(
        "evaluation LSB capacity: {} bytes",
        PngCarrier.capacity_bytes(&image)
    );
    println!("carrier adapter: sequential RGB LSB (benchmark only)");
    Ok(())
}

fn embed(carrier: &PathBuf, payload: &PathBuf, output: &PathBuf) -> Result<()> {
    let mut image = read_png(carrier)?;
    let bytes =
        fs::read(payload).with_context(|| format!("reading payload {}", payload.display()))?;
    PngCarrier.embed(&mut image, &bytes)?;
    let file =
        fs::File::create(output).with_context(|| format!("creating PNG {}", output.display()))?;
    let mut encoder = Encoder::new(file, image.width, image.height);
    encoder.set_color(ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().context("writing PNG header")?;
    writer
        .write_image_data(&image.pixels)
        .context("writing PNG pixels")?;
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
        .flat_map(|(a, b)| {
            a[..3]
                .iter()
                .zip(&b[..3])
                .map(|(x, y)| usize::from((x & 1) != (y & 1)))
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
        0.0
    } else {
        bits.iter().map(|bit| f64::from(*bit)).sum::<f64>() / bits.len() as f64
    }
}

fn transition_rate(bits: &[u8]) -> f64 {
    if bits.len() < 2 {
        0.0
    } else {
        bits.windows(2).filter(|pair| pair[0] != pair[1]).count() as f64 / (bits.len() - 1) as f64
    }
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
    let features = blind_features(&read_png(input)?, window_bits)?;
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
        let total = self.false_positive + self.true_negative;
        if total == 0 {
            0.0
        } else {
            self.false_positive as f64 / total as f64
        }
    }
    fn false_negative_rate(self) -> f64 {
        let total = self.false_negative + self.true_positive;
        if total == 0 {
            0.0
        } else {
            self.false_negative as f64 / total as f64
        }
    }
}

fn png_paths(dir: &PathBuf) -> Result<Vec<PathBuf>> {
    let mut paths = fs::read_dir(dir)
        .with_context(|| format!("reading benchmark directory {}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x.eq_ignore_ascii_case("png"))
        })
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn classify(samples: &[BenchmarkSample], threshold: f64) -> Confusion {
    samples
        .iter()
        .fold(Confusion::default(), |mut result, sample| {
            match (sample.encoded, sample.score >= threshold) {
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
        samples.push(BenchmarkSample {
            score: blind_features(&read_png(&path)?, window_bits)?.score,
            encoded: false,
        });
    }
    for path in encoded_paths {
        samples.push(BenchmarkSample {
            score: blind_features(&read_png(&path)?, window_bits)?.score,
            encoded: true,
        });
    }
    let mut thresholds = samples
        .iter()
        .map(|sample| sample.score)
        .collect::<Vec<_>>();
    thresholds.sort_by(f64::total_cmp);
    thresholds.dedup_by(|a, b| a == b);
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

    #[test]
    fn detector_detects_lsb_changes() {
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
