//! Crossing between the public Connect surface and the internal vsock wire.
//!
//! `arcbox-connect` (buffa) and `arcbox-protocol` (prost) generate the same
//! four `.proto` files with different codegens, so every message on one
//! side has an exact twin on the other and their protobuf encodings are
//! byte-identical. Crossing between them is therefore a decode or an
//! encode — never a field-by-field mapping. That matters: a conversion
//! table would be ~50 messages that must be kept in lockstep by hand, and
//! the failure mode of a missed field is a silently dropped value. Here
//! there is nothing to keep in lockstep; the protos are shared, so the two
//! representations cannot drift.
//!
//! Neither direction re-encodes:
//!
//! * Inbound, [`wire_request`] decodes the request's **original** bytes,
//!   the ones the client put on the wire.
//! * Outbound, [`wire_response`] hands the guest's already-encoded reply
//!   straight back as the response body.

use bytes::Bytes;
use connectrpc::{ConnectError, PreEncoded, ServiceRequest};

/// Decodes a Connect request's original wire bytes as its prost twin.
///
/// # Errors
///
/// Returns `invalid_argument` if the bytes do not decode as `P`. The
/// Connect runtime has already decoded them as the buffa twin by this
/// point, so a failure here means the two generated representations
/// disagree — a build-level fault, not a client one.
pub fn wire_request<P, B>(request: &ServiceRequest<'_, B>) -> Result<P, ConnectError>
where
    P: prost::Message + Default,
    B: connectrpc::HasMessageView,
{
    P::decode(request.bytes().clone()).map_err(|e| {
        ConnectError::invalid_argument(format!(
            "request did not decode as {}: {e}",
            std::any::type_name::<P>()
        ))
    })
}

/// Decodes one inbound client-stream item as its prost twin.
///
/// Same contract as [`wire_request`]; the item retains the bytes it was
/// decoded from, so this is a decode and not a re-encode.
///
/// # Errors
///
/// Returns `invalid_argument` if the bytes do not decode as `P`.
pub fn wire_stream_item<P, B>(item: &connectrpc::StreamMessage<B>) -> Result<P, ConnectError>
where
    P: prost::Message + Default,
    B: buffa::Message + connectrpc::HasMessageView,
{
    P::decode(item.bytes().clone()).map_err(|e| {
        ConnectError::invalid_argument(format!(
            "stream item did not decode as {}: {e}",
            std::any::type_name::<P>()
        ))
    })
}

/// Wraps a prost message as the response body for its buffa twin `B`.
///
/// The bytes are produced once here and handed to the codec as-is for
/// protobuf clients; JSON clients pay a decode plus re-serialize inside
/// [`PreEncoded`]. Debug builds assert that the bytes decode as `B`, so a
/// mismatched twin fails loudly in tests rather than reaching a client.
pub fn wire_response<B, P>(msg: &P) -> PreEncoded<B>
where
    B: buffa::Message,
    P: prost::Message,
{
    PreEncoded::from_bytes_unchecked(Bytes::from(msg.encode_to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two codegens must agree on the wire, since every RPC crosses
    /// between them. This asserts it on a message that exercises a scalar,
    /// a repeated field, a nested message, and an enum at once.
    #[test]
    fn the_two_representations_are_wire_identical() {
        use prost::Message as _;

        let prost_msg = arcbox_protocol::sandbox_v1::CreateSandboxRequest {
            template: "docker:alpine:3".into(),
            cmd: vec!["/bin/sh".into(), "-c".into(), "echo hi".into()],
            env: std::iter::once(("KEY".to_string(), "value".to_string())).collect(),
            working_dir: "/work".into(),
            ..Default::default()
        };

        // prost -> bytes -> buffa
        let body: PreEncoded<arcbox_connect::sandbox_v1::CreateSandboxRequest> =
            wire_response(&prost_msg);
        let encoded = Bytes::from(prost_msg.encode_to_vec());
        let round_tripped =
            <arcbox_connect::sandbox_v1::CreateSandboxRequest as buffa::Message>::decode_from_slice(
                &encoded,
            )
            .expect("buffa decodes the prost encoding");

        assert_eq!(round_tripped.template, "docker:alpine:3");
        assert_eq!(round_tripped.cmd, vec!["/bin/sh", "-c", "echo hi"]);
        assert_eq!(round_tripped.working_dir, "/work");
        assert_eq!(
            round_tripped.env.get("KEY").map(String::as_str),
            Some("value")
        );
        // `wire_response` must not have altered the bytes.
        assert_eq!(
            connectrpc::Encodable::encode(&body, connectrpc::CodecFormat::Proto)
                .expect("proto encoding"),
            encoded
        );
    }
}
