// Extracted from the usbd-ctaphid crate:
//   https://github.com/trussed-dev/usbd-ctaphid/blob/1db2e014f28669bc484c81ab0406c54b16bba33c/src/pipe.rs
//
// License: Apache-2.0 or MIT
//
// Authors:
// - Conor Patrick <conorpp94@gmail.com>
// - Nicolas Stalder <n@stalder.io>
// - Robin Krahl <robin@nitrokey.com>
// - Sosthène Guédon <sosthene@nitrokey.com>

use crate::proto::CtapError;
use cosey::Bytes;
use ctaphid_dispatch::{app::Command, Requester};
use interchange;
use std::collections::VecDeque;
use tracing::{error, info};

const MESSAGE_SIZE: usize = 3072;
const PACKET_SIZE: usize = 64;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
struct Version {
    major: u8,
    minor: u8,
    build: u8,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Request {
    channel: u32,
    command: Command,
    length: u16,
    timestamp: u32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Response {
    channel: u32,
    command: Command,
    length: u16,
}

impl Response {
    fn from_request_and_size(request: Request, size: usize) -> Self {
        Self {
            channel: request.channel,
            command: request.command,
            length: size as u16,
        }
    }

    fn error_from_request(request: Request) -> Self {
        Self::error_on_channel(request.channel)
    }

    fn error_on_channel(channel: u32) -> Self {
        Self {
            channel,
            command: Command::Error,
            length: 1,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MessageState {
    next_sequence: u8,
    transmitted: usize,
}

impl Default for MessageState {
    fn default() -> Self {
        Self {
            next_sequence: 0,
            transmitted: PACKET_SIZE - 7,
        }
    }
}

impl MessageState {
    fn absorb_packet(&mut self) {
        self.next_sequence += 1;
        self.transmitted += PACKET_SIZE - 5;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum State {
    Idle,
    Receiving((Request, MessageState)),
    WaitingOnAuthenticator(Request),
    WaitingToSend(Response),
    Sending((Response, MessageState)),
}

pub struct Pipe<'a, const N: usize> {
    queue: VecDeque<[u8; PACKET_SIZE]>,
    state: State,
    interchange: Requester<'a, N>,
    buffer: [u8; MESSAGE_SIZE],
    last_channel: u32,
    implements: u8,
    last_milliseconds: u32,
    started_processing: bool,
    needs_keepalive: bool,
    version: Version,
}

impl<'a, const N: usize> Pipe<'a, N> {
    pub fn new(interchange: Requester<'a, N>) -> Self {
        Self {
            queue: Default::default(),
            state: State::Idle,
            interchange,
            buffer: [0; MESSAGE_SIZE],
            last_channel: Default::default(),
            implements: 0x84,
            last_milliseconds: Default::default(),
            started_processing: Default::default(),
            needs_keepalive: Default::default(),
            version: Default::default(),
        }
    }

    pub fn push(&mut self, packet: &[u8]) {
        let (_, packet) = packet.split_first().unwrap();
        self.read_and_handle_packet(packet);
    }

    pub fn pop(&mut self) -> Option<[u8; PACKET_SIZE]> {
        self.handle_response();
        self.maybe_write_packet();
        self.queue.pop_front()
    }

    fn read_and_handle_packet(&mut self, packet: &[u8]) {
        if packet.len() != PACKET_SIZE {
            panic!("unexpected packet size");
        }
        let channel = u32::from_be_bytes(packet[..4].try_into().unwrap());
        let is_initialization = (packet[4] >> 7) != 0;
        if is_initialization {
            let command_number = packet[4] & !0x80;
            let Ok(command) = Command::try_from(command_number) else {
                self.start_sending_error_on_channel(channel, CtapError::InvalidCommand);
                return;
            };
            let length = u16::from_be_bytes(packet[5..][..2].try_into().unwrap());
            let timestamp = self.last_milliseconds;
            let current_request = Request {
                channel,
                command,
                length,
                timestamp,
            };

            if !(self.state == State::Idle) {
                let request = match self.state {
                    State::WaitingOnAuthenticator(request) => request,
                    State::Receiving((request, _message_state)) => request,
                    _ => {
                        return;
                    }
                };
                if packet[4] == 0x86 {
                    // self.cancel_ongoing_activity();
                } else {
                    if channel == request.channel {
                        if command == Command::Cancel {
                            // self.cancel_ongoing_activity();
                        } else {
                            self.start_sending_error(request, CtapError::InvalidSeq);
                        }
                    } else {
                        self.send_error_now(current_request, CtapError::ChannelBusy);
                    }

                    return;
                }
            }

            if length > MESSAGE_SIZE as u16 {
                self.send_error_now(current_request, CtapError::InvalidLength);
                return;
            }

            if length > PACKET_SIZE as u16 - 7 {
                self.buffer[..PACKET_SIZE - 7].copy_from_slice(&packet[7..]);
                self.state = State::Receiving((current_request, { MessageState::default() }));
            } else {
                self.buffer[..length as usize].copy_from_slice(&packet[7..][..length as usize]);
                self.dispatch_request(current_request);
            }
        } else {
            match self.state {
                State::Receiving((request, mut message_state)) => {
                    let sequence = packet[4];
                    if sequence != message_state.next_sequence {
                        self.start_sending_error(request, CtapError::InvalidSeq);
                        return;
                    }
                    if channel != request.channel {
                        return;
                    }

                    let payload_length = request.length as usize;
                    if message_state.transmitted + (PACKET_SIZE - 5) < payload_length {
                        self.buffer[message_state.transmitted..][..PACKET_SIZE - 5]
                            .copy_from_slice(&packet[5..]);
                        message_state.absorb_packet();
                        self.state = State::Receiving((request, message_state));
                    } else {
                        let missing = request.length as usize - message_state.transmitted;
                        self.buffer[message_state.transmitted..payload_length]
                            .copy_from_slice(&packet[5..][..missing]);
                        self.dispatch_request(request);
                    }
                }
                _ => {
                    panic!("unexpected continuation packet");
                }
            }
        }
    }

    fn start_sending(&mut self, response: Response) {
        self.state = State::WaitingToSend(response);
        self.maybe_write_packet();
    }

    fn start_sending_error(&mut self, request: Request, error: CtapError) {
        self.start_sending_error_on_channel(request.channel, error);
    }

    fn start_sending_error_on_channel(&mut self, channel: u32, error: CtapError) {
        self.buffer[0] = error as u8;
        let response = Response::error_on_channel(channel);
        self.start_sending(response);
    }

    fn send_error_now(&mut self, request: Request, error: CtapError) {
        let last_state = core::mem::replace(&mut self.state, State::Idle);
        let last_first_byte = self.buffer[0];

        self.buffer[0] = error as u8;
        let response = Response::error_from_request(request);
        self.start_sending(response);
        self.maybe_write_packet();

        self.state = last_state;
        self.buffer[0] = last_first_byte;
    }

    fn maybe_write_packet(&mut self) {
        match self.state {
            State::WaitingToSend(response) => {
                let mut packet = [0u8; PACKET_SIZE];
                packet[..4].copy_from_slice(&response.channel.to_be_bytes());
                packet[4] = response.command.into_u8() | 0x80;
                packet[5..7].copy_from_slice(&response.length.to_be_bytes());

                let fits_in_one_packet = 7 + response.length as usize <= PACKET_SIZE;
                if fits_in_one_packet {
                    packet[7..][..response.length as usize]
                        .copy_from_slice(&self.buffer[..response.length as usize]);
                    self.state = State::Idle;
                } else {
                    packet[7..].copy_from_slice(&self.buffer[..PACKET_SIZE - 7]);
                }

                self.queue.push_back(packet);

                if fits_in_one_packet {
                    self.state = State::Idle;
                } else {
                    self.state = State::Sending((response, MessageState::default()));
                }
            }
            State::Sending((response, mut message_state)) => {
                let mut packet = [0u8; PACKET_SIZE];
                packet[..4].copy_from_slice(&response.channel.to_be_bytes());
                packet[4] = message_state.next_sequence;

                let sent = message_state.transmitted;
                let remaining = response.length as usize - sent;
                let last_packet = 5 + remaining <= PACKET_SIZE;
                if last_packet {
                    packet[5..][..remaining]
                        .copy_from_slice(&self.buffer[message_state.transmitted..][..remaining]);
                } else {
                    packet[5..].copy_from_slice(
                        &self.buffer[message_state.transmitted..][..PACKET_SIZE - 5],
                    );
                }

                self.queue.push_back(packet);

                if last_packet {
                    self.state = State::Idle;
                } else {
                    message_state.absorb_packet();
                    self.state = State::Sending((response, message_state));
                }
            }
            _ => {}
        }
    }

    fn dispatch_request(&mut self, request: Request) {
        match request.command {
            Command::Init => {}
            _ => {
                if request.channel == 0xffffffff {
                    self.start_sending_error(request, CtapError::InvalidChannel);
                    return;
                }
            }
        }
        match request.command {
            Command::Init => {
                match request.channel {
                    0 => {
                        self.start_sending_error(request, CtapError::InvalidChannel);
                    }
                    cid => {
                        if request.length == 8 {
                            self.last_channel += 1;
                            let _nonce = &self.buffer[..8];
                            let response = Response {
                                channel: cid,
                                command: request.command,
                                length: 17,
                            };

                            self.buffer[8..12].copy_from_slice(&self.last_channel.to_be_bytes());
                            // CTAPHID protocol version
                            self.buffer[12] = 2;
                            // major device version number
                            self.buffer[13] = self.version.major;
                            // minor device version number
                            self.buffer[14] = self.version.minor;
                            // build device version number
                            self.buffer[15] = self.version.build;
                            // capabilities flags
                            // 0x1: implements WINK
                            // 0x4: implements CBOR
                            // 0x8: does not implement MSG
                            // self.buffer[16] = 0x01 | 0x08;
                            self.buffer[16] = self.implements;
                            self.start_sending(response);
                        }
                    }
                }
            }

            Command::Ping => {
                let response = Response::from_request_and_size(request, request.length as usize);
                self.start_sending(response);
            }

            Command::Cancel => {
                // self.cancel_ongoing_activity();
            }

            _ => {
                self.needs_keepalive = request.command == Command::Cbor;
                if self.interchange.state() == interchange::State::Responded {
                    self.interchange.take_response();
                }
                match self.interchange.request((
                    request.command,
                    Bytes::from_slice(&self.buffer[..request.length as usize]).unwrap(),
                )) {
                    Ok(_) => {
                        self.state = State::WaitingOnAuthenticator(request);
                        self.started_processing = true;
                    }
                    Err(_) => {
                        self.send_error_now(request, CtapError::ChannelBusy);
                    }
                }
            }
        }
    }

    fn handle_response(&mut self) {
        if let State::WaitingOnAuthenticator(request) = self.state {
            if let Ok(response) = self.interchange.response() {
                match &response.0 {
                    Err(ctaphid_dispatch::app::Error::InvalidCommand) => {
                        self.start_sending_error(request, CtapError::InvalidCommand);
                    }
                    Err(ctaphid_dispatch::app::Error::InvalidLength) => {
                        self.start_sending_error(request, CtapError::InvalidLength);
                    }
                    Err(ctaphid_dispatch::app::Error::NoResponse) => {
                        info!("Got waiting noresponse from authenticator??");
                    }

                    Ok(message) => {
                        if message.len() > self.buffer.len() {
                            error!(
                                "Message is longer than buffer ({} > {})",
                                message.len(),
                                self.buffer.len(),
                            );
                            self.start_sending_error(request, CtapError::InvalidLength);
                        } else {
                            info!(
                                "Got {} bytes response from authenticator, starting send",
                                message.len()
                            );
                            let response = Response::from_request_and_size(request, message.len());
                            self.buffer[..message.len()].copy_from_slice(message);
                            self.start_sending(response);
                        }
                    }
                }
            }
        }
    }
}
