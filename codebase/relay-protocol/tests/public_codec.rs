use safechat_relay_protocol::{
    Message, Submit, decode_messages, decode_submit, encode_messages, encode_submit,
};

#[test]
fn public_submit_codec_round_trips() {
    let value = Submit::new("recipient", "message-id", None, vec![1, 2, 3, 4]);
    assert_eq!(
        decode_submit(&encode_submit(&value).expect("encode")).expect("decode"),
        value
    );
}

#[test]
fn public_message_codec_rejects_trailing_bytes() {
    let encoded = encode_messages(&[Message::new(
        1,
        "sender",
        None,
        "message-id",
        10,
        None,
        vec![9],
    )])
    .expect("encode");
    let mut malformed = encoded;
    malformed.push(0);
    assert!(decode_messages(&malformed).is_err());
}
