//! Versioned, bounded binary frames used only by the relay message endpoints.
//!
//! Layout (all integers are big-endian):
//! version:u16 | schema:u16 | kind:u8 | payload.
//! A submit payload is recipient:string | message_id:string | expiry:flag |
//! [expires_at:u64] | ciphertext:bytes. A messages payload is count:u32 |
//! message*; each message is server_id:i64 | sender:string |
//! sender_address:optional-string | message_id:string | accepted_at:u64 |
//! expiry:flag | [expires_at:u64] | ciphertext:bytes.
//! Lengths are u32 byte lengths, strings are UTF-8, and flags are exactly 0 or
//! 1. Version/schema changes are incompatible and must be negotiated by the
//!    media type/API capability before deployment.

use anyhow::{Context, Result, bail};

pub const VERSION: u16 = 1;
pub const SCHEMA: u16 = 1;
pub const KIND_SUBMIT: u8 = 1;
pub const KIND_MESSAGES: u8 = 2;
pub const MAX_MESSAGES: usize = 100;
pub const MAX_BODY: usize = 16 * 1024 * 1024;
pub const MAX_RECIPIENT_BYTES: usize = 256;
pub const MAX_MESSAGE_ID_BYTES: usize = 256;
pub const MAX_ADDRESS_BYTES: usize = 256;
pub const MAX_CIPHERTEXT_BYTES: usize = MAX_BODY;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Submit {
    pub recipient: String,
    pub message_id: String,
    pub expires_at: Option<u64>,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub server_id: i64,
    pub sender: String,
    pub sender_address: Option<String>,
    pub message_id: String,
    pub accepted_at: u64,
    pub expires_at: Option<u64>,
    pub ciphertext: Vec<u8>,
}

fn header(kind: u8, output: &mut Vec<u8>) {
    output.extend(VERSION.to_be_bytes());
    output.extend(SCHEMA.to_be_bytes());
    output.push(kind);
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8], limit: usize, field: &str) -> Result<()> {
    if value.len() > limit {
        bail!("{field} exceeds maximum length of {limit} bytes");
    }
    output.extend(
        u32::try_from(value.len())
            .context("field length overflow")?
            .to_be_bytes(),
    );
    output.extend(value);
    Ok(())
}

fn put_string(output: &mut Vec<u8>, value: &str, limit: usize, field: &str) -> Result<()> {
    put_bytes(output, value.as_bytes(), limit, field)
}

pub fn encode_submit(value: &Submit) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    header(KIND_SUBMIT, &mut output);
    put_string(
        &mut output,
        &value.recipient,
        MAX_RECIPIENT_BYTES,
        "recipient",
    )?;
    put_string(
        &mut output,
        &value.message_id,
        MAX_MESSAGE_ID_BYTES,
        "message ID",
    )?;
    put_expiry(&mut output, value.expires_at);
    put_bytes(
        &mut output,
        &value.ciphertext,
        MAX_CIPHERTEXT_BYTES,
        "ciphertext",
    )?;
    check_body(&output)?;
    Ok(output)
}

pub fn decode_submit(input: &[u8]) -> Result<Submit> {
    let mut reader = Reader::new(input, KIND_SUBMIT)?;
    let recipient = reader.string(MAX_RECIPIENT_BYTES, "recipient")?;
    let message_id = reader.string(MAX_MESSAGE_ID_BYTES, "message ID")?;
    let expires_at = reader.expiry()?;
    let ciphertext = reader.bytes(MAX_CIPHERTEXT_BYTES, "ciphertext")?;
    reader.finish()?;
    Ok(Submit {
        recipient,
        message_id,
        expires_at,
        ciphertext,
    })
}

pub fn encode_messages(messages: &[Message]) -> Result<Vec<u8>> {
    if messages.len() > MAX_MESSAGES {
        bail!("too many messages");
    }
    let mut output = Vec::new();
    header(KIND_MESSAGES, &mut output);
    output.extend(
        u32::try_from(messages.len())
            .context("message count overflow")?
            .to_be_bytes(),
    );
    for message in messages {
        output.extend(message.server_id.to_be_bytes());
        put_string(&mut output, &message.sender, MAX_ADDRESS_BYTES, "sender")?;
        match &message.sender_address {
            Some(address) => {
                output.push(1);
                put_string(&mut output, address, MAX_ADDRESS_BYTES, "sender address")?;
            }
            None => output.push(0),
        }
        put_string(
            &mut output,
            &message.message_id,
            MAX_MESSAGE_ID_BYTES,
            "message ID",
        )?;
        output.extend(message.accepted_at.to_be_bytes());
        put_expiry(&mut output, message.expires_at);
        put_bytes(
            &mut output,
            &message.ciphertext,
            MAX_CIPHERTEXT_BYTES,
            "ciphertext",
        )?;
    }
    check_body(&output)?;
    Ok(output)
}

pub fn decode_messages(input: &[u8]) -> Result<Vec<Message>> {
    let mut reader = Reader::new(input, KIND_MESSAGES)?;
    let count = reader.u32()? as usize;
    if count > MAX_MESSAGES {
        bail!("too many messages");
    }
    let mut messages = Vec::with_capacity(count);
    for _ in 0..count {
        let server_id = reader.i64()?;
        let sender = reader.string(MAX_ADDRESS_BYTES, "sender")?;
        let sender_address = match reader.u8()? {
            0 => None,
            1 => Some(reader.string(MAX_ADDRESS_BYTES, "sender address")?),
            _ => bail!("unknown sender address flag"),
        };
        let message_id = reader.string(MAX_MESSAGE_ID_BYTES, "message ID")?;
        let accepted_at = reader.u64()?;
        let expires_at = reader.expiry()?;
        let ciphertext = reader.bytes(MAX_CIPHERTEXT_BYTES, "ciphertext")?;
        messages.push(Message {
            server_id,
            sender,
            sender_address,
            message_id,
            accepted_at,
            expires_at,
            ciphertext,
        });
    }
    reader.finish()?;
    Ok(messages)
}

fn put_expiry(output: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend(value.to_be_bytes());
        }
        None => output.push(0),
    }
}

fn check_body(output: &[u8]) -> Result<()> {
    if output.len() > MAX_BODY {
        bail!("binary relay body exceeds maximum size");
    }
    Ok(())
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8], kind: u8) -> Result<Self> {
        if input.len() > MAX_BODY {
            bail!("binary relay body exceeds maximum size");
        }
        let header_len = 5;
        if input.len() < header_len {
            bail!("truncated binary relay header");
        }
        let version = u16::from_be_bytes(input[..2].try_into()?);
        let schema = u16::from_be_bytes(input[2..4].try_into()?);
        if version != VERSION || schema != SCHEMA {
            bail!("unsupported binary relay version/schema");
        }
        if input[4] != kind {
            bail!("unexpected binary relay frame kind");
        }
        Ok(Self {
            input,
            offset: header_len,
        })
    }
    fn take(&mut self, length: usize, what: &str) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .context("binary length overflow")?;
        let value = self
            .input
            .get(self.offset..end)
            .with_context(|| format!("truncated {what}"))?;
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8> {
        self.take(1, "binary field")?
            .first()
            .copied()
            .context("truncated binary field")
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4, "binary u32")?.try_into()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8, "binary u64")?.try_into()?))
    }
    fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_be_bytes(self.take(8, "binary i64")?.try_into()?))
    }
    fn bytes(&mut self, limit: usize, field: &str) -> Result<Vec<u8>> {
        let len = self.u32()? as usize;
        if len > limit {
            bail!("{field} exceeds maximum length of {limit} bytes");
        }
        Ok(self.take(len, field)?.to_vec())
    }
    fn string(&mut self, limit: usize, field: &str) -> Result<String> {
        String::from_utf8(self.bytes(limit, field)?)
            .with_context(|| format!("{field} is not UTF-8"))
    }
    fn expiry(&mut self) -> Result<Option<u64>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => bail!("unknown expiration flag"),
        }
    }
    fn finish(&self) -> Result<()> {
        if self.offset != self.input.len() {
            bail!("trailing bytes in binary relay frame");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_lengths_are_rejected() {
        let mut x = encode_submit(&Submit {
            recipient: "r".into(),
            message_id: "m".into(),
            expires_at: None,
            ciphertext: vec![1],
        })
        .unwrap();
        let n = 5;
        x[n..n + 4].copy_from_slice(&99u32.to_be_bytes());
        assert!(decode_submit(&x).is_err());
    }
    #[test]
    fn oversized_fields_are_rejected() {
        assert!(
            encode_submit(&Submit {
                recipient: "r".repeat(MAX_RECIPIENT_BYTES + 1),
                message_id: "m".into(),
                expires_at: None,
                ciphertext: vec![]
            })
            .is_err()
        );
        assert!(
            encode_messages(&[Message {
                server_id: 1,
                sender: "s".repeat(MAX_ADDRESS_BYTES + 1),
                sender_address: None,
                message_id: "m".into(),
                accepted_at: 1,
                expires_at: None,
                ciphertext: vec![]
            }])
            .is_err()
        );
    }
    #[test]
    fn unknown_flags_are_rejected() {
        let mut x = encode_submit(&Submit {
            recipient: "r".into(),
            message_id: "m".into(),
            expires_at: None,
            ciphertext: vec![],
        })
        .unwrap();
        x[5 + 4 + 1 + 4 + 1] = 2;
        assert!(decode_submit(&x).is_err());
    }
    #[test]
    fn maximum_ciphertext_round_trips() {
        let value = Submit {
            recipient: "r".into(),
            message_id: "m".into(),
            expires_at: Some(1),
            ciphertext: vec![7; MAX_CIPHERTEXT_BYTES - 64],
        };
        assert_eq!(
            decode_submit(&encode_submit(&value).unwrap()).unwrap(),
            value
        );
    }

    #[test]
    fn json_and_binary_logical_fields_are_equivalent() {
        let json_fields = Submit {
            recipient: "recipient".into(),
            message_id: "message".into(),
            expires_at: Some(7),
            ciphertext: vec![0, 1, 255],
        };
        let binary_fields = decode_submit(&encode_submit(&json_fields).unwrap()).unwrap();
        assert_eq!(json_fields, binary_fields);
    }
}
