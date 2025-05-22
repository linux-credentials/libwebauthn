use apdu::Command;

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
const CTAP_P1_SUPP_GET_RESP: u8 = 0x80;
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

impl_into_vec!(CtapMsgCommand<'a>);

/// Constructs a `GET MSG` command.
pub fn command_ctap_msg(has_more: bool, payload: &[u8]) -> CtapMsgCommand {
    CtapMsgCommand::new(has_more, payload)
}
