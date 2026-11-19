//! TLV 编解码：IDX(2) SUB(1) TYPE(1) LEN(2) VALUE(LEN)，全大端。

use crate::consts::TLV_HDR_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    pub idx: u16,
    pub sub: u8,
    pub typ: u8,
    pub value: Vec<u8>,
}

impl Tlv {
    pub fn new(idx: u16, sub: u8, typ: u8, value: Vec<u8>) -> Self {
        Tlv { idx, sub, typ, value }
    }

    pub fn empty(typ: u8) -> Self {
        Tlv {
            idx: 0,
            sub: 0,
            typ,
            value: Vec::new(),
        }
    }

    pub fn as_u8(&self) -> Option<u8> {
        self.value.first().copied()
    }

    pub fn as_u16(&self) -> Option<u16> {
        (self.value.len() >= 2).then(|| u16::from_be_bytes([self.value[0], self.value[1]]))
    }

    pub fn as_u32(&self) -> Option<u32> {
        (self.value.len() >= 4).then(|| {
            u32::from_be_bytes([
                self.value[0],
                self.value[1],
                self.value[2],
                self.value[3],
            ])
        })
    }

    pub fn as_u64(&self) -> Option<u64> {
        (self.value.len() >= 8).then(|| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&self.value[..8]);
            u64::from_be_bytes(b)
        })
    }

    pub fn as_f64(&self) -> Option<f64> {
        self.as_u64().map(f64::from_bits)
    }

    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.value).ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlvError {
    Truncated,
    TooLarge,
}

#[derive(Debug, Clone, Default)]
pub struct TlvWriter {
    buf: Vec<u8>,
}

impl TlvWriter {
    pub fn new() -> Self {
        TlvWriter { buf: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        TlvWriter {
            buf: Vec::with_capacity(cap),
        }
    }

    pub fn raw_put(&mut self, idx: u16, sub: u8, typ: u8, value: &[u8]) -> Result<(), TlvError> {
        if value.len() > u16::MAX as usize {
            return Err(TlvError::TooLarge);
        }
        self.buf.extend_from_slice(&idx.to_be_bytes());
        self.buf.push(sub);
        self.buf.push(typ);
        self.buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
        self.buf.extend_from_slice(value);
        Ok(())
    }

    pub fn put_u8(&mut self, idx: u16, sub: u8, typ: u8, v: u8) {
        let _ = self.raw_put(idx, sub, typ, &[v]);
    }

    pub fn put_u16(&mut self, idx: u16, sub: u8, typ: u8, v: u16) {
        let _ = self.raw_put(idx, sub, typ, &v.to_be_bytes());
    }

    pub fn put_u32(&mut self, idx: u16, sub: u8, typ: u8, v: u32) {
        let _ = self.raw_put(idx, sub, typ, &v.to_be_bytes());
    }

    pub fn put_u64(&mut self, idx: u16, sub: u8, typ: u8, v: u64) {
        let _ = self.raw_put(idx, sub, typ, &v.to_be_bytes());
    }

    pub fn put_f64(&mut self, idx: u16, sub: u8, typ: u8, v: f64) {
        let _ = self.raw_put(idx, sub, typ, &v.to_bits().to_be_bytes());
    }

    pub fn put_str(&mut self, idx: u16, sub: u8, typ: u8, s: &str) {
        let _ = self.raw_put(idx, sub, typ, s.as_bytes());
    }

    /// 顶层字段：idx=0、sub=0，贴合描述符/控制载荷的既有编码。
    pub fn field_u8(&mut self, typ: u8, v: u8) {
        self.put_u8(0, 0, typ, v);
    }

    pub fn field_u16(&mut self, typ: u8, v: u16) {
        self.put_u16(0, 0, typ, v);
    }

    pub fn field_u32(&mut self, typ: u8, v: u32) {
        self.put_u32(0, 0, typ, v);
    }

    pub fn field_u64(&mut self, typ: u8, v: u64) {
        self.put_u64(0, 0, typ, v);
    }

    pub fn field_f64(&mut self, typ: u8, v: f64) {
        self.put_f64(0, 0, typ, v);
    }

    pub fn field_str(&mut self, typ: u8, s: &str) {
        self.put_str(0, 0, typ, s);
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

pub fn decode_tlvs(buf: &[u8]) -> Result<Vec<Tlv>, TlvError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < buf.len() {
        if pos + TLV_HDR_LEN > buf.len() {
            return Err(TlvError::Truncated);
        }
        let idx = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let sub = buf[pos + 2];
        let typ = buf[pos + 3];
        let len = u16::from_be_bytes([buf[pos + 4], buf[pos + 5]]) as usize;
        let start = pos + TLV_HDR_LEN;
        if start + len > buf.len() {
            return Err(TlvError::Truncated);
        }
        out.push(Tlv {
            idx,
            sub,
            typ,
            value: buf[start..start + len].to_vec(),
        });
        pos = start + len;
    }
    Ok(out)
}

pub fn encode_tlvs(items: &[Tlv]) -> Vec<u8> {
    let mut w = TlvWriter::with_capacity(items.iter().map(|t| t.value.len() + 6).sum());
    for t in items {
        let _ = w.raw_put(t.idx, t.sub, t.typ, &t.value);
    }
    w.finish()
}

pub fn find<'a>(tlvs: &'a [Tlv], typ: u8) -> Option<&'a Tlv> {
    tlvs.iter().find(|t| t.typ == typ)
}

pub fn find_idx<'a>(tlvs: &'a [Tlv], idx: u16, sub: u8) -> Option<&'a Tlv> {
    tlvs.iter().find(|t| t.idx == idx && t.sub == sub)
}

/// 未知 critical TLV（0x80..=0xBF）出现即拒绝（§09.1）。
pub fn has_unknown_critical(tlvs: &[Tlv]) -> bool {
    tlvs.iter().any(|t| {
        let t = t.typ;
        (crate::consts::TLV_CRITICAL_MIN..=crate::consts::TLV_CRITICAL_MAX).contains(&t)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut w = TlvWriter::new();
        w.put_u16(0x0001, 0, 0x33, 7);
        w.put_str(0, 0, 0x37, "hello");
        w.field_u32(0x39, 0xDEADBEEF);
        let bytes = w.finish();
        let items = decode_tlvs(&bytes).unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].as_u16(), Some(7));
        assert_eq!(items[1].as_str(), Some("hello"));
        assert_eq!(items[2].as_u32(), Some(0xDEADBEEF));
    }

    #[test]
    fn truncated_is_error() {
        assert_eq!(decode_tlvs(&[0, 0, 0]), Err(TlvError::Truncated));
    }
}
