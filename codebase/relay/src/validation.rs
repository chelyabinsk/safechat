//! HTTP media-type, size, and message-representation validation.

use axum::http::HeaderMap;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use safechat_relay_protocol as relay_binary;

use super::{BINARY_MEDIA_TYPE, JSON_MEDIA_TYPE, MessageResponse, b64decode};

pub(super) fn media_type(headers: &HeaderMap, name: &str) -> anyhow::Result<Option<String>> {
    let Some(value) = headers.get(name) else {
        return Ok(None);
    };
    let value = value
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .trim()
        .to_ascii_lowercase();
    if value == JSON_MEDIA_TYPE || value == BINARY_MEDIA_TYPE {
        Ok(Some(value))
    } else {
        anyhow::bail!("unsupported {name} media type")
    }
}

pub(super) fn require_json_content(headers: &HeaderMap) -> anyhow::Result<()> {
    if media_type(headers, "content-type")?.as_deref() != Some(JSON_MEDIA_TYPE) {
        anyhow::bail!("Content-Type must be application/json");
    }
    Ok(())
}

pub(super) fn validate_optional_json_content(headers: &HeaderMap) -> anyhow::Result<()> {
    if headers.contains_key("content-type") {
        require_json_content(headers)?;
    }
    Ok(())
}

pub(super) fn validate_json_accept(headers: &HeaderMap) -> anyhow::Result<()> {
    let Some(value) = headers.get("accept") else {
        return Ok(());
    };
    let values: Vec<_> = value.to_str()?.split(',').map(str::trim).collect();
    if values.is_empty()
        || values
            .iter()
            .any(|part| part.is_empty() || (*part != JSON_MEDIA_TYPE && *part != "*/*"))
    {
        anyhow::bail!("Accept must be application/json");
    }
    Ok(())
}

pub(super) fn validate_text(value: &str, limit: usize, field: &str) -> anyhow::Result<()> {
    if value.len() > limit {
        anyhow::bail!("{field} exceeds maximum length of {limit} bytes");
    }
    Ok(())
}

pub(super) fn decode_bounded_base64(
    value: &str,
    encoded_limit: usize,
    decoded_limit: usize,
    field: &str,
) -> anyhow::Result<Vec<u8>> {
    validate_text(value, encoded_limit, field)?;
    let decoded = b64decode(value)?;
    if decoded.len() > decoded_limit {
        anyhow::bail!("{field} exceeds maximum decoded length");
    }
    Ok(decoded)
}

pub(super) fn wants_binary(headers: &HeaderMap) -> anyhow::Result<bool> {
    let Some(value) = headers.get("accept") else {
        return Ok(false);
    };
    let values: Vec<_> = value.to_str()?.split(',').map(str::trim).collect();
    if values.is_empty()
        || values
            .iter()
            .any(|part| part.is_empty() || part.contains(';'))
    {
        anyhow::bail!("unsupported Accept media type or parameters");
    }
    if values
        .iter()
        .any(|part| *part != JSON_MEDIA_TYPE && *part != BINARY_MEDIA_TYPE && *part != "*/*")
    {
        anyhow::bail!("unsupported Accept media type");
    }
    Ok(values
        .iter()
        .any(|part| *part == BINARY_MEDIA_TYPE || *part == "*/*"))
}

pub(super) fn require_binary_accept(headers: &HeaderMap) -> anyhow::Result<()> {
    if !wants_binary(headers)? {
        anyhow::bail!("message endpoints require Accept: application/octet-stream");
    }
    Ok(())
}

pub(super) fn decode_message_request(
    headers: &HeaderMap,
    body: &[u8],
) -> anyhow::Result<(String, String, Option<u64>, Vec<u8>)> {
    if media_type(headers, "content-type")?.as_deref() != Some(BINARY_MEDIA_TYPE) {
        anyhow::bail!("message submission requires Content-Type: application/octet-stream");
    }
    let request = relay_binary::decode_submit(body)?;
    Ok((
        request.recipient,
        request.message_id,
        request.expires_at,
        request.ciphertext,
    ))
}

pub(super) fn binary_message(message: &MessageResponse) -> anyhow::Result<relay_binary::Message> {
    Ok(relay_binary::Message {
        server_id: message.server_id,
        sender: message.sender.clone(),
        sender_address: message.sender_address.clone(),
        message_id: message.message_id.clone(),
        accepted_at: message.accepted_at,
        expires_at: message.expires_at,
        ciphertext: URL_SAFE_NO_PAD
            .decode(&message.ciphertext)
            .map_err(|error| anyhow::anyhow!("stored ciphertext is invalid: {error}"))?,
    })
}

pub(super) fn encode_binary_messages(messages: &[MessageResponse]) -> anyhow::Result<Vec<u8>> {
    messages
        .iter()
        .map(binary_message)
        .collect::<anyhow::Result<Vec<_>>>()
        .and_then(|messages| relay_binary::encode_messages(&messages))
}
