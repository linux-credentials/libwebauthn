use std::convert::TryInto;
use std::io::{Cursor as IOCursor, Error as IOError, ErrorKind as IOErrorKind};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use tracing::{debug, error};

const BROADCAST_CID: u32 = 0xFFFFFFFF;
const PACKET_INITIAL_HEADER_SIZE: usize = 7;
const PACKET_INITIAL_CMD_MASK: u8 = 0x80;
const PACKET_CONT_HEADER_SIZE: usize = 5;

#[derive(Debug, IntoPrimitive, TryFromPrimitive, Copy, Clone, PartialEq)]
#[repr(u8)]
pub enum HidCommand {
    Ping = 0x01,
    Msg = 0x03,
    Lock = 0x04,
    Init = 0x06,
    Wink = 0x08,
    Cbor = 0x10,
    Cancel = 0x11,
    Sync = 0x3C,
    KeepAlive = 0x3B,
    Error = 0x3F,
}

#[derive(Debug, Clone)]
pub struct HidMessage {
    pub cid: u32,
    pub cmd: HidCommand,
    pub payload: Vec<u8>,
}

impl HidMessage {
    pub fn new(cid: u32, cmd: HidCommand, payload: &[u8]) -> Self {
        Self {
            cid,
            cmd,
            payload: Vec::from(payload),
        }
    }

    pub fn broadcast(cmd: HidCommand, payload: &[u8]) -> Self {
        Self::new(BROADCAST_CID, cmd, payload)
    }

    pub fn packets(&self, packet_size: usize) -> Result<Vec<Vec<u8>>, IOError> {
        if packet_size < PACKET_INITIAL_HEADER_SIZE + 1 {
            return Err(IOError::new(
                IOErrorKind::InvalidData,
                format!("Desired packet size is unsupported: {}", packet_size),
            ));
        }

        let mut payload = self.payload.as_slice().iter().cloned().peekable();
        let mut packets = vec![];

        // Initial fragment
        let mut packet = vec![];
        packet.write_u32::<BigEndian>(self.cid)?;
        packet.write_u8(self.cmd as u8 | PACKET_INITIAL_CMD_MASK)?;
        packet.write_u16::<BigEndian>(payload.len() as u16)?;
        let mut chunk: Vec<u8> = payload
            .by_ref()
            .take(packet_size - PACKET_INITIAL_HEADER_SIZE)
            .collect();
        packet.append(&mut chunk);
        packets.push(packet);

        // Sequence fragments
        let mut seq: u8 = 0;
        while payload.peek().is_some() {
            let mut packet = vec![];
            packet.write_u32::<BigEndian>(self.cid)?;
            packet.write_u8(seq)?;

            let mut chunk: Vec<u8> = payload
                .by_ref()
                .take(packet_size - PACKET_CONT_HEADER_SIZE)
                .collect();
            packet.append(&mut chunk);
            packets.push(packet);
            seq += 1;

            if seq > 0x7F {
                return Err(IOError::new(
                    IOErrorKind::InvalidData,
                    format!("Payload is too large for packet size ({}), and would exceed maximum number of packets.", packet_size),
                ));
            }
        }

        Ok(packets)
    }
}

#[derive(Debug, PartialEq)]
pub enum HidMessageParserState {
    MorePacketsExpected,
    Done,
}

#[derive(Debug)]
pub struct HidMessageParser {
    packets: Vec<Vec<u8>>,
}

impl Default for HidMessageParser {
    fn default() -> Self {
        Self::new()
    }
}

impl HidMessageParser {
    pub fn new() -> Self {
        Self { packets: vec![] }
    }

    pub fn update(&mut self, packet: &[u8]) -> Result<HidMessageParserState, IOError> {
        if (self.packets.is_empty() && packet.len() < PACKET_INITIAL_HEADER_SIZE)
            || packet.len() < PACKET_CONT_HEADER_SIZE + 1
        {
            error!("Packet length in invalid");
            return Err(IOError::new(
                IOErrorKind::InvalidInput,
                "Packet length is invalid",
            ));
        }
        if packet.iter().all(|&b| b == 0) {
            debug!("Received unexpected packet of all zeroes, ignoring"); // ?!
        } else {
            self.packets.push(Vec::from(packet));
        }
        if self.more_packets_needed() {
            Ok(HidMessageParserState::MorePacketsExpected)
        } else {
            Ok(HidMessageParserState::Done)
        }
    }

    fn more_packets_needed(&self) -> bool {
        if self.packets.is_empty() {
            return true;
        }

        self.expected_bytes().unwrap() > self.payload_len()
    }

    fn expected_bytes(&self) -> Option<usize> {
        if self.packets.is_empty() {
            return None;
        }

        let mut cursor = IOCursor::new(vec![self.packets[0][5], self.packets[0][6]]);
        Some(cursor.read_u16::<BigEndian>().unwrap() as usize)
    }

    fn payload_len(&self) -> usize {
        if self.packets.is_empty() {
            return 0;
        }

        let mut payload_len = self.packets[0].len() - PACKET_INITIAL_HEADER_SIZE;
        for cont_packet in &self.packets[1..self.packets.len()] {
            payload_len += cont_packet.len() - PACKET_CONT_HEADER_SIZE;
        }
        payload_len
    }

    pub fn message(&self) -> Result<HidMessage, IOError> {
        if self.more_packets_needed() {
            return Err(IOError::new(
                IOErrorKind::InvalidData,
                "Message is not yet complete, more packets need to be ingested.",
            ));
        }

        let mut cursor = IOCursor::new(&self.packets[0]);
        let cid = cursor.read_u32::<BigEndian>()?;
        let cmd = cursor.read_u8()? ^ PACKET_INITIAL_CMD_MASK;
        let Ok(cmd) = cmd.try_into() else {
            error!(?cmd, "Invalid HID message command");
            return Err(IOError::new(
                IOErrorKind::InvalidData,
                format!("Invalid HID message command: {:?}", cmd),
            ));
        };
        let expected_size = cursor.read_u16::<BigEndian>()?;

        let mut payload = vec![];
        payload.extend(&self.packets[0][PACKET_INITIAL_HEADER_SIZE..]);
        for cont_packet in &self.packets[1..] {
            payload.extend_from_slice(&cont_packet[PACKET_CONT_HEADER_SIZE..]);
        }

        payload.truncate(expected_size as usize);
        Ok(HidMessage::new(cid, cmd, &payload))
    }
}

#[cfg(test)]
mod tests {
    use crate::transport::hid::framing::{
        HidCommand, HidMessage, HidMessageParser, HidMessageParserState,
    };
    use std::io::ErrorKind as IOErrorKind;

    const CHANNEL_ID: u32 = 0xC0_C1_C2_C3;

    #[test]
    fn encode_single_packet() {
        let msg = HidMessage::new(CHANNEL_ID, HidCommand::Msg, &[0x0A, 0x0B, 0x0C, 0x0D]);
        let expected: Vec<Vec<u8>> = vec![vec![
            0xC0, 0xC1, 0xC2, 0xC3, 0x83, 0x00, 0x04, 0x0A, 0x0B, 0x0C, 0x0D,
        ]];
        assert_eq!(msg.packets(11).unwrap(), expected)
    }

    #[test]
    fn encode_broadcast() {
        let msg = HidMessage::broadcast(HidCommand::Msg, &[0x0A, 0x0B, 0x0C, 0x0D]);
        let expected: Vec<Vec<u8>> = vec![vec![
            0xFF, 0xFF, 0xFF, 0xFF, 0x83, 0x00, 0x04, 0x0A, 0x0B, 0x0C, 0x0D,
        ]];
        assert_eq!(msg.packets(11).unwrap(), expected)
    }

    #[test]
    fn encode_multiple_packets() {
        let msg = HidMessage::new(
            CHANNEL_ID,
            HidCommand::Msg,
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        );
        let expected: Vec<Vec<u8>> = vec![
            vec![0xC0, 0xC1, 0xC2, 0xC3, 0x83, 0x00, 0x08, 0x01],
            vec![0xC0, 0xC1, 0xC2, 0xC3, 0x00, 0x02, 0x03, 0x04],
            vec![0xC0, 0xC1, 0xC2, 0xC3, 0x01, 0x05, 0x06, 0x07],
            vec![0xC0, 0xC1, 0xC2, 0xC3, 0x02, 0x08],
        ];
        assert_eq!(msg.packets(8).unwrap(), expected)
    }

    #[test]
    fn encode_too_large() {
        let msg = HidMessage::new(CHANNEL_ID, HidCommand::Msg, &[0x00; 0xFFFF]);
        assert_eq!(
            msg.packets(8).map_err(|err| err.kind()).unwrap_err(),
            IOErrorKind::InvalidData
        );
    }

    #[test]
    fn parse_single_packet() {
        let mut parser = HidMessageParser::new();
        assert_eq!(
            parser
                .update(&[
                    0xC0, 0xC1, 0xC2, 0xC3, 0x83, 0x00, 0x04, 0x0A, 0x0B, 0x0C, 0x0D,
                ])
                .unwrap(),
            HidMessageParserState::Done
        );
        let msg = parser.message().unwrap();
        assert_eq!(msg.cid, CHANNEL_ID);
        assert_eq!(msg.cmd, HidCommand::Msg);
        assert_eq!(msg.payload, vec![0x0A, 0x0B, 0x0C, 0x0D]);
    }

    #[test]
    fn parse_multiple_packets() {
        let mut parser = HidMessageParser::new();
        assert_eq!(
            parser
                .update(&[0xC0, 0xC1, 0xC2, 0xC3, 0x83, 0x00, 0x05, 0x0A])
                .unwrap(),
            HidMessageParserState::MorePacketsExpected
        );
        assert_eq!(
            parser
                .update(&[0xC0, 0xC1, 0xC2, 0xC3, 0x00, 0x0B, 0x0C])
                .unwrap(),
            HidMessageParserState::MorePacketsExpected
        );
        assert_eq!(
            parser
                .update(&[0xC0, 0xC1, 0xC2, 0xC3, 0x01, 0x0D, 0x0E, 0xFF]) // excess byte
                .unwrap(),
            HidMessageParserState::Done
        );

        let msg = parser.message().unwrap();
        assert_eq!(msg.cid, CHANNEL_ID);
        assert_eq!(msg.cmd, HidCommand::Msg);
        assert_eq!(msg.payload, vec![0x0A, 0x0B, 0x0C, 0x0D, 0x0E]);
    }
}
