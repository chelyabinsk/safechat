#![allow(dead_code)]

use anyhow::{Context, Result, bail};

/// Decoded carrier pixels used by the PNG adapter and future media adapters.
pub struct RgbaImage {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
}

/// Boundary between the authenticated protocol envelope and a media carrier.
///
/// The protocol produces opaque bytes. A carrier adapter is responsible only
/// for placing those bytes into, and recovering them from, a carrier.
pub trait CarrierAdapter {
    fn capacity_bytes(&self, carrier: &RgbaImage) -> usize;
    fn embed(&self, carrier: &mut RgbaImage, payload: &[u8]) -> Result<()>;
    fn extract(&self, carrier: &RgbaImage, length: usize) -> Result<Vec<u8>>;
}

/// Initial lossless image adapter. Additional adapters can support GIF, audio,
/// or video without changing the protocol envelope API.
pub struct PngCarrier;

impl CarrierAdapter for PngCarrier {
    fn capacity_bytes(&self, carrier: &RgbaImage) -> usize {
        carrier.pixels.len() / 4 * 3 / 8
    }

    fn embed(&self, carrier: &mut RgbaImage, payload: &[u8]) -> Result<()> {
        let capacity = self.capacity_bytes(carrier);
        if payload.len() > capacity {
            bail!(
                "payload requires {} bytes, carrier capacity is {} bytes",
                payload.len(),
                capacity
            );
        }
        let mut bits = bits_from_bytes(payload);
        for pixel in carrier.pixels.chunks_exact_mut(4) {
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

    fn extract(&self, carrier: &RgbaImage, length: usize) -> Result<Vec<u8>> {
        if length > self.capacity_bytes(carrier) {
            bail!("declared payload exceeds carrier capacity");
        }
        let bit_count = length.checked_mul(8).context("payload size overflow")?;
        let mut bits = Vec::with_capacity(bit_count);
        for pixel in carrier.pixels.chunks_exact(4) {
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
