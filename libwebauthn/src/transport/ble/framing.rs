use std::convert::TryInto;
use std::io::{Cursor as IOCursor, Error as IOError, ErrorKind as IOErrorKind};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_enum::{IntoPrimitive, TryFromPrimitive};

const INITIAL_FRAGMENT_HEADER_LENGTH: usize = 3; // 1B op, 2B length
const INITIAL_FRAGMENT_MIN_LENGTH: usize = INITIAL_FRAGMENT_HEADER_LENGTH;
const CONT_FRAGMENT_HEADER_LENGTH: usize = 1;
const CONT_FRAGMENT_MIN_LENGTH: usize = CONT_FRAGMENT_HEADER_LENGTH; // 1B header, 1B data

// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ble-constants
#[derive(Debug, IntoPrimitive, TryFromPrimitive, Copy, Clone, PartialEq)]
#[repr(u8)]
pub enum BleCommand {
    Ping = 0x81,
    Keepalive = 0x82,
    Msg = 0x83,
    Cancel = 0xBE,
    Error = 0xBF,
}

#[derive(Debug, Clone)]
pub struct BleFrame {
    pub cmd: BleCommand,
    pub data: Vec<u8>,
}

impl BleFrame {
    pub fn new(cmd: BleCommand, data: &[u8]) -> Self {
        Self {
            data: Vec::from(data),
            cmd,
        }
    }

    // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ble-framing-fragmentation
    pub fn fragments(&self, max_fragment_length: usize) -> Result<Vec<Vec<u8>>, IOError> {
        if max_fragment_length < 4 {
            return Err(IOError::new(
                IOErrorKind::InvalidData,
                format!(
                    "Desired maximum fragment length is unsupported: {}",
                    max_fragment_length
                ),
            ));
        }

        let length = self.data.len() as u16;
        let mut message = self.data.as_slice().iter().cloned().peekable();
        let mut fragments = vec![];

        // Initial fragment
        let cmd: u8 = self.cmd.into();
        let mut fragment = vec![cmd];
        fragment.write_u16::<BigEndian>(length)?;
        let mut chunk: Vec<u8> = message
            .by_ref()
            .take(max_fragment_length - INITIAL_FRAGMENT_HEADER_LENGTH)
            .collect();
        fragment.append(&mut chunk);
        fragments.push(fragment);

        // Sequence fragments
        let mut seq: u8 = 0;
        while message.peek().is_some() {
            let mut fragment = vec![seq];
            let mut chunk: Vec<u8> = message
                .by_ref()
                .take(max_fragment_length - CONT_FRAGMENT_HEADER_LENGTH)
                .collect();
            fragment.append(&mut chunk);
            fragments.push(fragment);
            seq += 1;
        }

        Ok(fragments)
    }
}

#[derive(Debug, PartialEq)]
pub enum BleFrameParserResult {
    MoreFragmentsExpected,
    Done,
}

#[derive(Debug)]
pub struct BleFrameParser {
    fragments: Vec<Vec<u8>>,
}

impl Default for BleFrameParser {
    fn default() -> Self {
        Self::new()
    }
}

impl BleFrameParser {
    pub fn new() -> Self {
        Self { fragments: vec![] }
    }

    pub fn update(&mut self, fragment: &[u8]) -> Result<BleFrameParserResult, IOError> {
        if (self.fragments.is_empty() && fragment.len() < INITIAL_FRAGMENT_MIN_LENGTH)
            || fragment.len() < CONT_FRAGMENT_MIN_LENGTH
        {
            return Err(IOError::new(
                IOErrorKind::InvalidInput,
                "Fragment length is invalid. 3 bytes are required for an initial fragment, 2 bytes for each continuation fragment."
            ));
        }

        self.fragments.push(Vec::from(fragment));
        if self.more_fragments_needed() {
            Ok(BleFrameParserResult::MoreFragmentsExpected)
        } else {
            Ok(BleFrameParserResult::Done)
        }
    }

    pub fn frame(&self) -> Result<BleFrame, IOError> {
        if self.more_fragments_needed() {
            return Err(IOError::new(
                IOErrorKind::InvalidData,
                "Frame is not yet complete, more fragments need to be ingested.",
            ));
        }

        let cmd = self.fragments[0][0].try_into().or(Err(IOError::new(
            IOErrorKind::InvalidData,
            format!("Invalid BLE frame command: {:x}", self.fragments[0][0]),
        )))?;
        let mut data = vec![];
        data.extend(&self.fragments[0][INITIAL_FRAGMENT_HEADER_LENGTH..self.fragments[0].len()]);
        for cont_fragment in &self.fragments[1..self.fragments.len()] {
            data.extend_from_slice(
                &cont_fragment[CONT_FRAGMENT_HEADER_LENGTH..cont_fragment.len()],
            );
        }

        Ok(BleFrame::new(cmd, &data))
    }

    pub fn reset(&mut self) {
        self.fragments = vec![];
    }

    fn more_fragments_needed(&self) -> bool {
        if self.fragments.is_empty() {
            return true;
        }

        self.expected_bytes().unwrap() > self.data_len()
    }

    fn expected_bytes(&self) -> Option<usize> {
        if self.fragments.is_empty() {
            return None;
        }

        let mut cursor = IOCursor::new(vec![self.fragments[0][1], self.fragments[0][2]]);
        Some(cursor.read_u16::<BigEndian>().unwrap() as usize)
    }

    fn data_len(&self) -> usize {
        if self.fragments.is_empty() {
            return 0;
        }

        let mut data_len = self.fragments[0].len() - INITIAL_FRAGMENT_HEADER_LENGTH;
        for cont_fragment in &self.fragments[1..self.fragments.len()] {
            data_len += cont_fragment.len() - CONT_FRAGMENT_HEADER_LENGTH;
        }
        data_len
    }
}

#[cfg(test)]
mod tests {
    use crate::transport::ble::framing::{
        BleCommand, BleFrame, BleFrameParser, BleFrameParserResult,
    };

    #[test]
    fn encode_single_fragment() {
        let frame = BleFrame::new(BleCommand::Msg, &[0x0A, 0x0B, 0x0C, 0x0D]);
        let expected: Vec<Vec<u8>> = vec![vec![0x83, 0x00, 0x04, 0x0A, 0x0B, 0x0C, 0x0D]];
        assert_eq!(frame.fragments(8).unwrap(), expected)
    }

    #[test]
    fn encode_multiple_frames() {
        let frame = BleFrame::new(
            BleCommand::Msg,
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        );
        let expected: Vec<Vec<u8>> = vec![
            vec![0x83, 0x00, 0x08, 0x01],
            vec![0x00, 0x02, 0x03, 0x04],
            vec![0x01, 0x05, 0x06, 0x07],
            vec![0x02, 0x08],
        ];
        assert_eq!(frame.fragments(4).unwrap(), expected)
    }

    #[test]
    fn parse_single_fragment() {
        let mut parser = BleFrameParser::new();
        assert_eq!(
            parser
                .update(&[0x83, 0x00, 0x04, 0x0A, 0x0B, 0x0C, 0x0D])
                .unwrap(),
            BleFrameParserResult::Done
        );
        assert_eq!(parser.frame().unwrap().data, vec![0x0A, 0x0B, 0x0C, 0x0D]);
    }

    #[test]
    fn parse_multiple_fragments() {
        let mut parser = BleFrameParser::new();
        assert_eq!(
            parser.update(&[0x83, 0x00, 0x05, 0x0A]).unwrap(),
            BleFrameParserResult::MoreFragmentsExpected
        );
        assert_eq!(
            parser.update(&[0x00, 0x0B, 0x0C, 0x0D]).unwrap(),
            BleFrameParserResult::MoreFragmentsExpected
        );
        assert_eq!(
            parser.update(&[0x01, 0x0E]).unwrap(),
            BleFrameParserResult::Done
        );
        assert_eq!(
            parser.frame().unwrap().data,
            vec![0x0A, 0x0B, 0x0C, 0x0D, 0x0E]
        );
    }
}
