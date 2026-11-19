//! 能力描述符与需求描述的 TLV 序列化（与 `idcell_desc.c` 字段顺序一致）。

use crate::consts::{cap_field, req_field};
use crate::tlv::{decode_tlvs, Tlv, TlvError, TlvWriter};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypePair {
    pub dtype: u8,
    pub scale_exp: u8,
}

impl TypePair {
    pub fn new(dtype: u8, scale_exp: u8) -> Self {
        TypePair { dtype, scale_exp }
    }

    pub fn label(&self) -> String {
        format!("{}×10^-{}", crate::consts::dtype::name(self.dtype), self.scale_exp)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Capability {
    pub index: u16,
    pub sub: u8,
    pub label: String,
    /// 0=state 1=event 2=command
    pub kind: u8,
    /// 1=r 2=w 3=rw
    pub dir: u8,
    pub perm: u8,
    pub qty: u8,
    pub unit: String,
    pub accept_units: Vec<String>,
    /// 0=T0 1=T1 2=T2 3=T3 4=T4
    pub conv_class: u8,
    pub dtype: u8,
    pub scale_exp: u8,
    pub accept_types: Vec<TypePair>,
    pub range: (f64, f64),
    pub precision: f64,
    pub frame_ref: String,
    pub invertible: bool,
    pub t_prod_ms: u32,
    pub stale_ms: u32,
    pub load_cap: u32,
    pub trigger: u8,
    pub hold_semantics: u8,
    pub fail_action: u8,
    pub provenance: u8,
    pub escalate: String,
    pub deps: Vec<u16>,
}

impl Default for Capability {
    fn default() -> Self {
        Capability {
            index: 1,
            sub: 0,
            label: String::new(),
            kind: 0,
            dir: 1,
            perm: 0,
            qty: 0,
            unit: String::new(),
            accept_units: Vec::new(),
            conv_class: 1,
            dtype: 8,
            scale_exp: 0,
            accept_types: Vec::new(),
            range: (f64::MIN, f64::MAX),
            precision: 0.0,
            frame_ref: String::new(),
            invertible: false,
            t_prod_ms: 100,
            stale_ms: 1000,
            load_cap: 0,
            trigger: 0,
            hold_semantics: 0,
            fail_action: 0,
            provenance: 0,
            escalate: String::new(),
            deps: Vec::new(),
        }
    }
}

impl Capability {
    pub fn readable(&self) -> bool {
        self.dir & 1 != 0
    }

    pub fn writable(&self) -> bool {
        self.dir & 2 != 0
    }

    pub fn type_pair(&self) -> TypePair {
        TypePair::new(self.dtype, self.scale_exp)
    }

    fn write_public(&self) -> TlvWriter {
        let mut w = TlvWriter::new();
        w.field_str(cap_field::LABEL, &self.label);
        w.field_u8(cap_field::KIND, self.kind);
        w.field_u8(cap_field::DIR, self.dir);
        w.field_u8(cap_field::DIM, self.qty);
        w.field_str(cap_field::UNIT, &self.unit);
        for u in &self.accept_units {
            w.field_str(cap_field::ACCEPT, u);
        }
        w.field_u8(cap_field::CONV, self.conv_class);
        w.field_u8(cap_field::DTYPE, self.dtype);
        w.field_u8(cap_field::SCALE, self.scale_exp);
        for t in &self.accept_types {
            let _ = w.raw_put(0, 0, cap_field::ACCEPT_T, &[t.dtype, t.scale_exp]);
        }
        w.field_u32(cap_field::MINSYNC, self.t_prod_ms);
        w.field_u32(cap_field::STALE, self.stale_ms);
        w.field_u32(cap_field::LOADCAP, self.load_cap);
        w.field_u8(cap_field::TRIGGER, self.trigger);
        w
    }

    /// 公共子集：只含发现/匹配所需字段，严禁范围、授权策略与 schema 集合。
    pub fn encode_public(&self) -> Vec<u8> {
        self.write_public().finish()
    }

    /// 完整描述符（绑定后按需返回）。
    pub fn encode_full(&self) -> Vec<u8> {
        let mut w = TlvWriter::new();
        w.field_str(cap_field::LABEL, &self.label);
        w.field_u8(cap_field::KIND, self.kind);
        w.field_u8(cap_field::DIR, self.dir);
        w.field_u8(cap_field::PERM, self.perm);
        w.field_u8(cap_field::DIM, self.qty);
        w.field_str(cap_field::UNIT, &self.unit);
        for u in &self.accept_units {
            w.field_str(cap_field::ACCEPT, u);
        }
        w.field_u8(cap_field::CONV, self.conv_class);
        w.field_u8(cap_field::DTYPE, self.dtype);
        w.field_u8(cap_field::SCALE, self.scale_exp);
        for t in &self.accept_types {
            let _ = w.raw_put(0, 0, cap_field::ACCEPT_T, &[t.dtype, t.scale_exp]);
        }
        w.field_f64(cap_field::RANGE, self.range.0);
        w.field_f64(cap_field::RANGE, self.range.1);
        w.field_f64(cap_field::PRECISION, self.precision);
        w.field_str(cap_field::FRAME, &self.frame_ref);
        w.field_u8(cap_field::INVERT, u8::from(self.invertible));
        w.field_u32(cap_field::MINSYNC, self.t_prod_ms);
        w.field_u32(cap_field::STALE, self.stale_ms);
        w.field_u32(cap_field::LOADCAP, self.load_cap);
        w.field_u8(cap_field::TRIGGER, self.trigger);
        w.field_u8(cap_field::HOLD, self.hold_semantics);
        w.field_u8(cap_field::FAIL, self.fail_action);
        w.field_u8(cap_field::PROV, self.provenance);
        w.field_str(cap_field::ESCALATE, &self.escalate);
        for d in &self.deps {
            w.field_u16(cap_field::DEPS, *d);
        }
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Capability, TlvError> {
        let tlvs = decode_tlvs(bytes)?;
        let mut c = Capability {
            accept_units: Vec::new(),
            accept_types: Vec::new(),
            deps: Vec::new(),
            range: (f64::MIN, f64::MAX),
            ..Default::default()
        };
        let mut range_seen = 0;
        for t in &tlvs {
            match t.typ {
                cap_field::LABEL => c.label = t.as_str().unwrap_or("").to_string(),
                cap_field::KIND => c.kind = t.as_u8().unwrap_or(0),
                cap_field::DIR => c.dir = t.as_u8().unwrap_or(1),
                cap_field::PERM => c.perm = t.as_u8().unwrap_or(0),
                cap_field::DIM => c.qty = t.as_u8().unwrap_or(0),
                cap_field::UNIT => c.unit = t.as_str().unwrap_or("").to_string(),
                cap_field::ACCEPT => {
                    if let Some(s) = t.as_str() {
                        c.accept_units.push(s.to_string());
                    }
                }
                cap_field::CONV => c.conv_class = t.as_u8().unwrap_or(1),
                cap_field::DTYPE => c.dtype = t.as_u8().unwrap_or(8),
                cap_field::SCALE => c.scale_exp = t.as_u8().unwrap_or(0),
                cap_field::ACCEPT_T => {
                    if t.value.len() >= 2 {
                        c.accept_types.push(TypePair::new(t.value[0], t.value[1]));
                    }
                }
                cap_field::RANGE => {
                    if let Some(v) = t.as_f64() {
                        if range_seen == 0 {
                            c.range.0 = v;
                        } else {
                            c.range.1 = v;
                        }
                        range_seen += 1;
                    }
                }
                cap_field::PRECISION => c.precision = t.as_f64().unwrap_or(0.0),
                cap_field::FRAME => c.frame_ref = t.as_str().unwrap_or("").to_string(),
                cap_field::INVERT => c.invertible = t.as_u8().unwrap_or(0) != 0,
                cap_field::MINSYNC => c.t_prod_ms = t.as_u32().unwrap_or(100),
                cap_field::STALE => c.stale_ms = t.as_u32().unwrap_or(1000),
                cap_field::LOADCAP => c.load_cap = t.as_u32().unwrap_or(0),
                cap_field::TRIGGER => c.trigger = t.as_u8().unwrap_or(0),
                cap_field::HOLD => c.hold_semantics = t.as_u8().unwrap_or(0),
                cap_field::FAIL => c.fail_action = t.as_u8().unwrap_or(0),
                cap_field::PROV => c.provenance = t.as_u8().unwrap_or(0),
                cap_field::ESCALATE => c.escalate = t.as_str().unwrap_or("").to_string(),
                cap_field::DEPS => {
                    if let Some(v) = t.as_u16() {
                        c.deps.push(v);
                    }
                }
                _ => {}
            }
        }
        Ok(c)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Requirement {
    pub label: String,
    pub qty: u8,
    pub unit: String,
    pub accept_units: Vec<String>,
    pub accept_types: Vec<TypePair>,
    pub perm: u8,
    pub index: Option<u16>,
    pub want_ms: u32,
    pub stale_ms: u32,
    pub range: (f64, f64),
    pub kind: u8,
}

impl Default for Requirement {
    fn default() -> Self {
        Requirement {
            label: String::new(),
            qty: 0,
            unit: String::new(),
            accept_units: Vec::new(),
            accept_types: Vec::new(),
            perm: 0,
            index: None,
            want_ms: 50,
            stale_ms: 500,
            range: (f64::MIN, f64::MAX),
            kind: 0,
        }
    }
}

impl Requirement {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = TlvWriter::new();
        w.field_str(req_field::LABEL, &self.label);
        w.field_u8(req_field::DIM, self.qty);
        w.field_str(req_field::UNIT, &self.unit);
        for u in &self.accept_units {
            w.field_str(req_field::ACCEPT, u);
        }
        for t in &self.accept_types {
            let _ = w.raw_put(0, 0, req_field::ACCEPT_T, &[t.dtype, t.scale_exp]);
        }
        w.field_u8(req_field::PERM, self.perm);
        w.field_u16(req_field::INDEX, self.index.unwrap_or(crate::consts::INDEX_ANY));
        w.field_u32(req_field::WANT, self.want_ms);
        w.field_u32(req_field::STALE, self.stale_ms);
        w.field_f64(req_field::RANGE, self.range.0);
        w.field_f64(req_field::RANGE, self.range.1);
        w.field_u8(req_field::KIND, self.kind);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Requirement, TlvError> {
        let tlvs: Vec<Tlv> = decode_tlvs(bytes)?;
        let mut r = Requirement {
            accept_units: Vec::new(),
            accept_types: Vec::new(),
            range: (f64::MIN, f64::MAX),
            ..Default::default()
        };
        let mut range_seen = 0;
        for t in &tlvs {
            match t.typ {
                req_field::LABEL => r.label = t.as_str().unwrap_or("").to_string(),
                req_field::DIM => r.qty = t.as_u8().unwrap_or(0),
                req_field::UNIT => r.unit = t.as_str().unwrap_or("").to_string(),
                req_field::ACCEPT => {
                    if let Some(s) = t.as_str() {
                        r.accept_units.push(s.to_string());
                    }
                }
                req_field::ACCEPT_T => {
                    if t.value.len() >= 2 {
                        r.accept_types.push(TypePair::new(t.value[0], t.value[1]));
                    }
                }
                req_field::PERM => r.perm = t.as_u8().unwrap_or(0),
                req_field::INDEX => {
                    let idx = t.as_u16().unwrap_or(crate::consts::INDEX_ANY);
                    r.index = if idx == crate::consts::INDEX_ANY {
                        None
                    } else {
                        Some(idx)
                    };
                }
                req_field::WANT => r.want_ms = t.as_u32().unwrap_or(50),
                req_field::STALE => r.stale_ms = t.as_u32().unwrap_or(500),
                req_field::RANGE => {
                    if let Some(v) = t.as_f64() {
                        if range_seen == 0 {
                            r.range.0 = v;
                        } else {
                            r.range.1 = v;
                        }
                        range_seen += 1;
                    }
                }
                req_field::KIND => r.kind = t.as_u8().unwrap_or(0),
                _ => {}
            }
        }
        Ok(r)
    }
}

/// 匹配判定：量种/单位/读写方向/权限/量程/值类型全部满足才算候选。
pub fn matches(requirement: &Requirement, cap: &Capability) -> Result<(), crate::errors::ErrCode> {
    use crate::errors::ErrCode;
    if requirement.qty != cap.qty {
        return Err(ErrCode::NoMatch);
    }
    if !cap.readable() {
        return Err(ErrCode::NoMatch);
    }
    if requirement.perm > cap.perm {
        return Err(ErrCode::Perm);
    }
    let unit_ok = cap.unit == requirement.unit
        || cap.accept_units.iter().any(|u| u == &requirement.unit)
        || requirement.accept_units.iter().any(|u| u == &cap.unit);
    if !unit_ok {
        return Err(ErrCode::Unit);
    }
    if requirement.range.0 > requirement.range.1 {
        return Err(ErrCode::Range);
    }
    let covers = cap.range.0 <= requirement.range.0 && cap.range.1 >= requirement.range.1;
    if !covers {
        return Err(ErrCode::Range);
    }
    if !requirement.accept_types.is_empty()
        && !requirement
            .accept_types
            .iter()
            .any(|t| t.dtype == cap.dtype && t.scale_exp <= cap.scale_exp)
    {
        return Err(ErrCode::Conv);
    }
    Ok(())
}

/// 查询选择器：按能力点索引与子索引筛选，支持通配与区间。
///
/// 文本形式（与 Zenoh 的 key selector 同思路，但收敛到点模型）：
///   `*`        —— 全部点
///   `3`        —— 索引 3 的任意子索引
///   `1-5`      —— 索引 [1,5] 的任意子索引
///   `3/2`      —— 索引 3、子索引 2
///   `1-5/0`    —— 索引 [1,5]、子索引 0
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selector {
    pub lo: u16,
    pub hi: u16,
    pub sub: Option<u8>,
}

impl Selector {
    pub fn all() -> Selector {
        Selector {
            lo: 0,
            hi: u16::MAX,
            sub: None,
        }
    }

    pub fn parse(text: &str) -> Option<Selector> {
        let s = text.trim();
        if s.is_empty() || s == "*" {
            return Some(Selector::all());
        }
        let (range, sub) = match s.split_once('/') {
            Some((r, sb)) => (r.trim(), Some(sb.trim().parse::<u8>().ok()?)),
            None => (s, None),
        };
        let (lo, hi) = match range.split_once('-') {
            Some((a, b)) => (
                a.trim().parse::<u16>().ok()?,
                b.trim().parse::<u16>().ok()?,
            ),
            None => {
                let v = range.trim().parse::<u16>().ok()?;
                (v, v)
            }
        };
        Some(Selector {
            lo: lo.min(hi),
            hi: lo.max(hi),
            sub,
        })
    }

    pub fn matches(&self, index: u16, sub: u8) -> bool {
        index >= self.lo && index <= self.hi && self.sub.map_or(true, |s| s == sub)
    }

    pub fn as_text(&self) -> String {
        let range = if self.lo == self.hi {
            self.lo.to_string()
        } else {
            format!("{}-{}", self.lo, self.hi)
        };
        match self.sub {
            Some(s) => format!("{range}/{s}"),
            None => {
                if self.lo == 0 && self.hi == u16::MAX {
                    "*".to_string()
                } else {
                    range
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_variants() {
        let all = Selector::parse("*").unwrap();
        assert!(all.matches(0, 0) && all.matches(999, 255));

        let one = Selector::parse("3").unwrap();
        assert!(one.matches(3, 0) && one.matches(3, 7));
        assert!(!one.matches(2, 0));

        let range = Selector::parse("1-5").unwrap();
        assert!(range.matches(1, 0) && range.matches(5, 9));
        assert!(!range.matches(6, 0));

        let point = Selector::parse("3/2").unwrap();
        assert!(point.matches(3, 2));
        assert!(!point.matches(3, 0));

        assert_eq!(Selector::parse("2-4/1").unwrap().as_text(), "2-4/1");
        assert!(Selector::parse("abc").is_none());
    }

    #[test]
    fn capability_roundtrip() {
        let cap = Capability {
            index: 3,
            label: "夹持力".into(),
            qty: 9,
            unit: "N".into(),
            range: (-200.0, 200.0),
            dtype: 4,
            scale_exp: 3,
            accept_types: vec![TypePair::new(4, 3)],
            ..Default::default()
        };
        let back = Capability::decode(&cap.encode_full()).unwrap();
        assert_eq!(back.label, cap.label);
        assert_eq!(back.qty, 9);
        assert_eq!(back.range, (-200.0, 200.0));
        assert_eq!(back.type_pair(), TypePair::new(4, 3));
        let public = Capability::decode(&cap.encode_public()).unwrap();
        assert_eq!(public.range, (f64::MIN, f64::MAX));
        assert_eq!(public.perm, 0);
    }

    #[test]
    fn requirement_roundtrip() {
        let req = Requirement {
            label: "力".into(),
            qty: 9,
            unit: "N".into(),
            index: Some(3),
            want_ms: 20,
            stale_ms: 100,
            range: (-50.0, 50.0),
            ..Default::default()
        };
        let back = Requirement::decode(&req.encode()).unwrap();
        assert_eq!(back.index, Some(3));
        assert_eq!(back.want_ms, 20);
        assert_eq!(back.range, (-50.0, 50.0));
    }
}
