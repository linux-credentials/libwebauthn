use apdu::Command;

use crate::proto::ctap1::apdu::ApduRequest;

// Copy private impl
const CLA_DEFAULT: u8 = 0x00;
const CLA_INTER_INDUSTRY: u8 = 0x80;

macro_rules! impl_into_vec {
    ($name: ty) => {
        impl<'a> From<$name> for Vec<u8> {
            fn from(cmd: $name) -> Self {
                Command::from(cmd).into()
            }
        }
    };
}

const INS_GET_RESPONSE: u8 = 0xC0;

/// `GET RESPONSE` (0xC0) command.
#[derive(Debug)]
pub struct GetResponseCommand {
    p1: u8,
    p2: u8,
    le: u8,
}

impl GetResponseCommand {
    /// Constructs a `GET RESPONSE` command.
    pub fn new(p1: u8, p2: u8, le: u8) -> Self {
        Self { p1, p2, le }
    }
}

impl<'a> From<GetResponseCommand> for Command<'a> {
    fn from(cmd: GetResponseCommand) -> Self {
        Self::new_with_le(CLA_DEFAULT, INS_GET_RESPONSE, cmd.p1, cmd.p2, cmd.le.into())
    }
}

impl_into_vec!(GetResponseCommand);

/// Constructs a `GET RESPONSE` command.
pub fn command_get_response(p1: u8, p2: u8, le: u8) -> GetResponseCommand {
    GetResponseCommand::new(p1, p2, le)
}

const CLA_HAS_MORE: u8 = 0x10;
const INS_CTAP_MSG: u8 = 0x10;
const _CTAP_P1_SUPP_GET_RESP: u8 = 0x80;
const CTAP_P2: u8 = 0x00;

/// `CTAP MSG` (0x10) command.
#[derive(Debug)]
pub struct CtapMsgCommand<'a> {
    has_more: bool,
    payload: &'a [u8],
}

impl<'a> CtapMsgCommand<'a> {
    /// Constructs a `CTAP MSG` command.
    pub fn new(has_more: bool, payload: &'a [u8]) -> Self {
        Self { has_more, payload }
    }
}

impl<'a> From<CtapMsgCommand<'a>> for Command<'a> {
    fn from(cmd: CtapMsgCommand<'a>) -> Self {
        let cla = match cmd.has_more {
            true => CLA_HAS_MORE,
            false => 0,
        } | CLA_INTER_INDUSTRY;
        Self::new_with_payload(
            cla,
            INS_CTAP_MSG,
            0, //CTAP_P1_SUPP_GET_RESP,
            CTAP_P2,
            cmd.payload,
        )
    }
}

impl<'a> From<&'a ApduRequest> for Command<'a> {
    fn from(cmd: &'a ApduRequest) -> Self {
        // U2F REGISTER and AUTHENTICATE are Case 4 APDUs per FIDO U2F Raw
        // Message Formats §3 / §4 and FIDO U2F NFC §3.1: the encoder must
        // propagate `response_max_length` as Le so the authenticator knows
        // a response payload is expected. Strict implementations reject
        // requests missing Le.
        let payload = cmd.data.as_deref().unwrap_or(&[]);
        match cmd.response_max_length {
            Some(le) => {
                // Short-form Le: APDU_SHORT_LE (256) is mapped to a single
                // byte 0x00 by apdu-core (`l as u8`).
                Self::new_with_payload_le(CLA_DEFAULT, cmd.ins, cmd.p1, cmd.p2, le as u16, payload)
            }
            None => Self::new_with_payload(CLA_DEFAULT, cmd.ins, cmd.p1, cmd.p2, payload),
        }
    }
}

impl_into_vec!(CtapMsgCommand<'a>);

/// Constructs a `GET MSG` command.
pub fn command_ctap_msg(has_more: bool, payload: &[u8]) -> CtapMsgCommand<'_> {
    CtapMsgCommand::new(has_more, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apdu_request_with_le_encodes_as_case_4_short() {
        // U2F REGISTER-style request: 64 byte payload, Le = 256.
        // Short form encodes Le as a single 0x00 byte (since 256 as u8 = 0).
        let payload = vec![0xAAu8; 64];
        let request = ApduRequest::new(0x01, 0x03, 0x00, Some(&payload), Some(0x100));
        let bytes: Vec<u8> = Command::from(&request).into();
        assert_eq!(bytes[0..5], [0x00, 0x01, 0x03, 0x00, 0x40]); // header + Lc=64
        assert_eq!(&bytes[5..69], payload.as_slice());
        assert_eq!(bytes[69], 0x00, "Le must be present (0x00 = 256)");
        assert_eq!(bytes.len(), 70);
    }

    #[test]
    fn apdu_request_without_le_encodes_as_case_3() {
        // Genuine Case 3: no Le.
        let payload = vec![0xAAu8; 64];
        let request = ApduRequest::new(0x01, 0x03, 0x00, Some(&payload), None);
        let bytes: Vec<u8> = Command::from(&request).into();
        assert_eq!(bytes[0..5], [0x00, 0x01, 0x03, 0x00, 0x40]); // header + Lc=64
        assert_eq!(&bytes[5..69], payload.as_slice());
        assert_eq!(bytes.len(), 69, "no trailing Le");
    }
}
