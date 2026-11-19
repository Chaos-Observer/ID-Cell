//! L2 帧编解码与增量流解析。

use crate::consts::*;
use crate::crc::crc16;
use crate::crypto::hmac_sha256;

/// 8 字节设备标识。独立生成，不由链路层标识派生（SEC-064）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct Did(pub [u8; 8]);

impl Did {
    pub fn broadcast() -> Did {
        Did(BROADCAST)
    }

    pub fn from_u64(v: u64) -> Did {
        Did(v.to_be_bytes())
    }

    pub fn to_u64(self) -> u64 {
        u64::from_be_bytes(self.0)
    }

    pub fn is_broadcast(self) -> bool {
        self.0 == BROADCAST
    }

    pub fn to_hex(self) -> String {
        format!(
            "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7]
        )
    }

    pub fn from_hex(s: &str) -> Option<Did> {
        let clean: String = s.chars().filter(|c| *c != '-').collect();
        if clean.len() != 16 {
            return None;
        }
        let mut out = [0u8; 8];
        for i in 0..8 {
            out[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(Did(out))
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub ver: u8,
    pub prof: u8,
    pub flags: u8,
    pub frame_type: u8,
    pub seq: u16,
    pub txn: u16,
    pub src: Did,
    pub dst: Did,
    pub group: u16,
    pub ts_us: u64,
    pub payload: Vec<u8>,
    pub auth_tag: [u8; AUTH_TAG_LEN],
}

impl Default for Frame {
    fn default() -> Self {
        Frame {
            ver: PROTO_VER_BYTE,
            prof: 0,
            flags: 0,
            frame_type: ftype::DISCOVER,
            seq: 0,
            txn: 0,
            src: Did::default(),
            dst: Did::default(),
            group: 0,
            ts_us: 0,
            payload: Vec::new(),
            auth_tag: [0; AUTH_TAG_LEN],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    BadVersion,
    BadProfile,
    BadType,
    PayloadTooLarge,
    AuthKeyMissing,
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            EncodeError::BadVersion => "unsupported protocol version",
            EncodeError::BadProfile => "unknown profile",
            EncodeError::BadType => "unknown frame type",
            EncodeError::PayloadTooLarge => "payload exceeds LEN limit",
            EncodeError::AuthKeyMissing => "AUTH frame requires key",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    NeedMore,
    BadSync,
    BadLength,
    BadVersion,
    BadProfile,
    BadType,
    BadTrailer,
    BadCrc,
    BadAuth,
}

impl DecodeError {
    pub fn label(self) -> &'static str {
        match self {
            DecodeError::NeedMore => "NEED_MORE",
            DecodeError::BadSync => "BAD_SYNC",
            DecodeError::BadLength => "BAD_LENGTH",
            DecodeError::BadVersion => "BAD_VERSION",
            DecodeError::BadProfile => "BAD_PROFILE",
            DecodeError::BadType => "BAD_TYPE",
            DecodeError::BadTrailer => "BAD_TRAILER",
            DecodeError::BadCrc => "BAD_CRC",
            DecodeError::BadAuth => "BAD_AUTH",
        }
    }
}

impl Frame {
    pub fn new(frame_type: u8) -> Self {
        Frame {
            frame_type,
            ..Default::default()
        }
    }

    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    pub fn seq(mut self, seq: u16) -> Self {
        self.seq = seq;
        self
    }

    pub fn txn(mut self, txn: u16) -> Self {
        self.txn = txn;
        self
    }

    pub fn route(mut self, src: Did, dst: Did) -> Self {
        self.src = src;
        self.dst = dst;
        self
    }

    pub fn group(mut self, group: u16) -> Self {
        self.group = group;
        self
    }

    pub fn at_us(mut self, ts_us: u64) -> Self {
        self.ts_us = ts_us;
        self
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        self.encode_with_key(None)
    }

    pub fn encode_with_key(&self, key: Option<&[u8]>) -> Result<Vec<u8>, EncodeError> {
        if self.ver >> 4 != PROTO_MAJOR {
            return Err(EncodeError::BadVersion);
        }
        if self.prof > 1 {
            return Err(EncodeError::BadProfile);
        }
        if !(ftype::DISCOVER..=ftype::MAX_TYPE).contains(&self.frame_type) {
            return Err(EncodeError::BadType);
        }
        let auth = self.flags & FLAG_AUTH != 0;
        let limit = if auth { MAX_AUTH_PAYLOAD } else { MAX_PAYLOAD };
        if self.payload.len() > limit {
            return Err(EncodeError::PayloadTooLarge);
        }

        let tag_len = if auth { AUTH_TAG_LEN } else { 0 };
        let mut out = Vec::with_capacity(HDR_LEN + self.payload.len() + tag_len + TRAILER_LEN);
        out.extend_from_slice(&SYNC);
        out.push(self.ver);
        out.push(self.prof);
        out.push(self.flags);
        out.push(self.frame_type);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.txn.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.src.0);
        out.extend_from_slice(&self.dst.0);
        out.extend_from_slice(&self.group.to_be_bytes());
        out.extend_from_slice(&((self.ts_us >> 16) as u32).to_be_bytes());
        out.extend_from_slice(&((self.ts_us & 0xFFFF) as u16).to_be_bytes());
        out.extend_from_slice(&self.payload);

        if auth {
            let key = key.ok_or(EncodeError::AuthKeyMissing)?;
            let mac = hmac_sha256(key, &out);
            out.extend_from_slice(&mac[..AUTH_TAG_LEN]);
        }
        let crc = crc16(&out);
        out.extend_from_slice(&crc.to_be_bytes());
        out.extend_from_slice(&TRAILER);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<(Frame, usize), DecodeError> {
        Frame::decode_with_key(input, None)
    }

    pub fn decode_with_key(
        input: &[u8],
        key: Option<&[u8]>,
    ) -> Result<(Frame, usize), DecodeError> {
        if input.is_empty() {
            return Err(DecodeError::NeedMore);
        }
        if input[0] != SYNC[0] {
            return Err(DecodeError::BadSync);
        }
        if input.len() == 1 {
            return Err(DecodeError::NeedMore);
        }
        if input[1] != SYNC[1] {
            return Err(DecodeError::BadSync);
        }
        if input.len() < HDR_LEN {
            return Err(DecodeError::NeedMore);
        }
        if input[2] >> 4 != PROTO_MAJOR {
            return Err(DecodeError::BadVersion);
        }
        if input[3] > 1 {
            return Err(DecodeError::BadProfile);
        }
        if !(ftype::DISCOVER..=ftype::MAX_TYPE).contains(&input[5]) {
            return Err(DecodeError::BadType);
        }
        let payload_len = u16::from_be_bytes([input[10], input[11]]) as usize;
        let auth = input[4] & FLAG_AUTH != 0;
        let limit = if auth { MAX_AUTH_PAYLOAD } else { MAX_PAYLOAD };
        if payload_len > limit {
            return Err(DecodeError::BadLength);
        }
        let tag_len = if auth { AUTH_TAG_LEN } else { 0 };
        let total = HDR_LEN + payload_len + tag_len + TRAILER_LEN;
        if input.len() < total {
            return Err(DecodeError::NeedMore);
        }
        if input[total - 2] != TRAILER[0] || input[total - 1] != TRAILER[1] {
            return Err(DecodeError::BadTrailer);
        }
        let crc_at = total - TRAILER_LEN;
        let want_crc = u16::from_be_bytes([input[crc_at], input[crc_at + 1]]);
        if crc16(&input[..crc_at]) != want_crc {
            return Err(DecodeError::BadCrc);
        }
        let mut auth_tag = [0u8; AUTH_TAG_LEN];
        if auth {
            let key = key.ok_or(DecodeError::BadAuth)?;
            let mac = hmac_sha256(key, &input[..HDR_LEN + payload_len]);
            auth_tag.copy_from_slice(&input[HDR_LEN + payload_len..HDR_LEN + payload_len + AUTH_TAG_LEN]);
            if auth_tag != mac[..AUTH_TAG_LEN] {
                return Err(DecodeError::BadAuth);
            }
        }
        let mut src = [0u8; 8];
        src.copy_from_slice(&input[12..20]);
        let mut dst = [0u8; 8];
        dst.copy_from_slice(&input[20..28]);
        let ts_us = ((u32::from_be_bytes([input[30], input[31], input[32], input[33]]) as u64) << 16)
            | u16::from_be_bytes([input[34], input[35]]) as u64;
        let frame = Frame {
            ver: input[2],
            prof: input[3],
            flags: input[4],
            frame_type: input[5],
            seq: u16::from_be_bytes([input[6], input[7]]),
            txn: u16::from_be_bytes([input[8], input[9]]),
            src: Did(src),
            dst: Did(dst),
            group: u16::from_be_bytes([input[28], input[29]]),
            ts_us,
            payload: input[HDR_LEN..HDR_LEN + payload_len].to_vec(),
            auth_tag,
        };
        Ok((frame, total))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    Frame(Frame),
    Bad(DecodeError),
}

/// 增量流解析器：处理粘包/拆包，并在坏帧处逐字节重同步。
pub struct StreamParser {
    buf: Vec<u8>,
    key: Option<Vec<u8>>,
    pub bad_frames: u64,
    pub good_frames: u64,
}

impl StreamParser {
    pub fn new(key: Option<Vec<u8>>) -> Self {
        StreamParser {
            buf: Vec::new(),
            key,
            bad_frames: 0,
            good_frames: 0,
        }
    }

    pub fn feed(&mut self, data: &[u8]) -> Vec<StreamEvent> {
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            // 丢弃 SYNC 之前的噪声，但保留尾部可能构成 SYNC 的 0xA5。
            if let Some(pos) = find_sync(&self.buf) {
                if pos > 0 {
                    self.buf.drain(..pos);
                    self.bad_frames += 1;
                    out.push(StreamEvent::Bad(DecodeError::BadSync));
                }
            } else {
                // 没有完整 SYNC：保留末尾单独的 0xA5（可能是下一帧的前半），其余丢弃。
                let keep = usize::from(self.buf.last().copied() == Some(SYNC[0]));
                let drop = self.buf.len().saturating_sub(keep);
                if drop > 0 {
                    self.buf.drain(..drop);
                    self.bad_frames += 1;
                    out.push(StreamEvent::Bad(DecodeError::BadSync));
                }
                break;
            }

            match Frame::decode_with_key(&self.buf, self.key.as_deref()) {
                Ok((frame, consumed)) => {
                    self.buf.drain(..consumed);
                    self.good_frames += 1;
                    out.push(StreamEvent::Frame(frame));
                }
                Err(DecodeError::NeedMore) => break,
                Err(e) => {
                    self.bad_frames += 1;
                    out.push(StreamEvent::Bad(e));
                    // 丢弃当前 SYNC 的第一个字节，避免重叠 SYNC 被吞掉。
                    self.buf.drain(..1);
                }
            }
        }
        out
    }

    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
}

fn find_sync(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == SYNC)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Frame {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0, 1, 0, 0x33, 0, 2, 0x00, 0x07]);
        payload.extend_from_slice(&[0, 2, 0, 0x37, 0, 2, b'h', b'i']);
        Frame::new(ftype::DISCOVER)
            .seq(1)
            .txn(0x1234)
            .route(Did::from_u64(0x0102030405060708), Did::broadcast())
            .group(7)
            .at_us(0x00010203040506)
            .with_payload(payload)
    }

    #[test]
    fn golden_plain_frame_matches_python_model() {
        let wire = sample().encode().unwrap();
        assert_eq!(
            wire,
            hex("A5A50B0000010001123400100102030405060708FFFFFFFFFFFFFFFF0007010203040506000100330002000700020037000268694DCD5AA5")
        );
        let (back, used) = Frame::decode(&wire).unwrap();
        assert_eq!(used, wire.len());
        assert_eq!(back, sample());
    }

    #[test]
    fn golden_auth_frame_matches_python_model() {
        let frame = Frame {
            flags: FLAG_AUTH,
            ..Frame::new(ftype::HELLO)
                .seq(0x00FF)
                .txn(2)
                .route(Did::from_u64(1), Did::from_u64(2))
                .with_payload(vec![1, 2, 3])
        };
        let wire = frame.encode_with_key(Some(b"idcell-key")).unwrap();
        assert_eq!(
            wire,
            hex("A5A50B00200200FF00020003000000000000000100000000000000020000000000000000010203322E5F2F059749BDE96D66A6ECFECF38B0A95AA5")
        );
        let (back, _) = Frame::decode_with_key(&wire, Some(b"idcell-key")).unwrap();
        let mut tag = [0u8; AUTH_TAG_LEN];
        tag.copy_from_slice(&wire[39..55]);
        assert_eq!(back.auth_tag, tag);
        assert!(matches!(
            Frame::decode_with_key(&wire, Some(b"wrong-key")),
            Err(DecodeError::BadAuth)
        ));
    }

    #[test]
    fn stream_handles_fragmentation_and_garbage() {
        let wire = sample().encode().unwrap();
        let mut parser = StreamParser::new(None);
        let events = parser.feed(&wire[..5]);
        assert!(events.is_empty());
        let mut events = parser.feed(&wire[5..]);
        assert_eq!(events.len(), 1);
        assert!(matches!(events.pop(), Some(StreamEvent::Frame(_))));

        let mut noisy = vec![0x00, 0x12];
        noisy.extend_from_slice(&wire);
        let mut parser = StreamParser::new(None);
        let events = parser.feed(&noisy);
        assert!(events.iter().any(|e| matches!(e, StreamEvent::Frame(_))));
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
