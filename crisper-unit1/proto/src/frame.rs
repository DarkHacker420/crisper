use crate::crypto::{open, seal, KEY_LEN};
use crate::ProtoError;

pub const HEADER_LEN: usize = 10;
pub const TAG_LEN: usize = 16;
pub const MAX_BODY: usize = 8 * 1024 * 1024;
pub const WINDOW: u32 = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    Hello = 0x01,
    HelloAck = 0x02,
    Checkin = 0x03,
    Task = 0x10,
    TaskResult = 0x11,
    TaskCancel = 0x12,
    Ping = 0x20,
    Pong = 0x21,
    Rekey = 0x22,
    FileChunk = 0x30,
    FileAck = 0x31,
    FileEnd = 0x32,
    PivotStart = 0x40,
    PivotData = 0x41,
    PivotEnd = 0x42,
    Kill = 0xF0,
    Error = 0xFF,
}

impl TryFrom<u8> for MsgType {
    type Error = ProtoError;

    fn try_from(v: u8) -> Result<Self, ProtoError> {
        Ok(match v {
            0x01 => Self::Hello,
            0x02 => Self::HelloAck,
            0x03 => Self::Checkin,
            0x10 => Self::Task,
            0x11 => Self::TaskResult,
            0x12 => Self::TaskCancel,
            0x20 => Self::Ping,
            0x21 => Self::Pong,
            0x22 => Self::Rekey,
            0x30 => Self::FileChunk,
            0x31 => Self::FileAck,
            0x32 => Self::FileEnd,
            0x40 => Self::PivotStart,
            0x41 => Self::PivotData,
            0x42 => Self::PivotEnd,
            0xF0 => Self::Kill,
            0xFF => Self::Error,
            other => return Err(ProtoError::UnknownType(other)),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub typ: MsgType,
    pub flags: u8,
    pub seq: u32,
    pub body: Vec<u8>,
}

impl Frame {
    pub fn encode(key: &[u8; KEY_LEN], seq: u32, typ: MsgType, flags: u8, body: &[u8]) -> Result<Vec<u8>, ProtoError> {
        let ct_len = body.len().checked_add(TAG_LEN).ok_or(ProtoError::BodyTooLarge)?;
        if ct_len > MAX_BODY {
            return Err(ProtoError::BodyTooLarge);
        }
        let mut header = [0u8; HEADER_LEN];
        header[0] = typ as u8;
        header[1] = flags;
        header[2..6].copy_from_slice(&seq.to_be_bytes());
        header[6..10].copy_from_slice(&(ct_len as u32).to_be_bytes());
        let ct = seal(key, seq, &header, body)?;
        let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn decode(key: &[u8; KEY_LEN], buf: &[u8]) -> Result<(Self, usize), ProtoError> {
        if buf.len() < HEADER_LEN {
            return Err(ProtoError::Short { need: HEADER_LEN, have: buf.len() });
        }
        let typ = MsgType::try_from(buf[0])?;
        let flags = buf[1];
        let seq = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
        let ct_len = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]) as usize;
        if ct_len == 0 || ct_len > MAX_BODY {
            return Err(ProtoError::BodyTooLarge);
        }
        let end = HEADER_LEN + ct_len;
        if buf.len() < end {
            return Err(ProtoError::Short { need: end, have: buf.len() });
        }
        let body = open(key, seq, &buf[..HEADER_LEN], &buf[HEADER_LEN..end])?;
        Ok((Self { typ, flags, seq, body }, end))
    }
}

#[derive(Debug, Clone)]
pub struct ReplayWindow {
    max: u32,
    seen: [u64; 16],
    init: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self { max: 0, seen: [0; 16], init: false }
    }
}

impl ReplayWindow {
    pub fn accept(&mut self, seq: u32) -> Result<(), ProtoError> {
        if !self.init {
            self.init = true;
            self.max = seq;
            self.seen[0] = 1;
            return Ok(());
        }
        if seq > self.max {
            let shift = seq - self.max;
            if shift >= WINDOW {
                self.seen = [0; 16];
            } else {
                self.shift_left(shift);
            }
            self.max = seq;
            self.seen[0] |= 1;
            return Ok(());
        }
        let distance = self.max - seq;
        if distance >= WINDOW {
            return Err(ProtoError::Sequence(seq));
        }
        let word = (distance / 64) as usize;
        let bit = distance % 64;
        if self.seen[word] & (1u64 << bit) != 0 {
            return Err(ProtoError::Sequence(seq));
        }
        self.seen[word] |= 1u64 << bit;
        Ok(())
    }

    fn shift_left(&mut self, shift: u32) {
        let words = (shift / 64) as usize;
        let bits = shift % 64;
        let mut out = [0u64; 16];
        for i in 0..16 {
            let src = i + words;
            if src >= 16 {
                continue;
            }
            out[i] |= self.seen[src] << bits;
            if bits != 0 && src + 1 < 16 {
                out[i] |= self.seen[src + 1] >> (64 - bits);
            }
        }
        self.seen = out;
    }
}
