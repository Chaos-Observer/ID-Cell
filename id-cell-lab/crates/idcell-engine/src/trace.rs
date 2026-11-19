//! 结构化 trace（JSONL）与 JSON 转义。

#[derive(Debug, Clone, Default)]
pub struct TraceEntry {
    pub t_ms: u64,
    pub kind: String,
    pub from: String,
    pub to: String,
    pub ftype: String,
    pub seq: u16,
    pub detail: String,
}

impl TraceEntry {
    pub fn new(t_ms: u64, kind: &str, from: &str, to: &str, ftype: &str, detail: String) -> Self {
        TraceEntry {
            t_ms,
            kind: kind.to_string(),
            from: from.to_string(),
            to: to.to_string(),
            ftype: ftype.to_string(),
            seq: 0,
            detail,
        }
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"t\":{},\"kind\":\"{}\",\"from\":\"{}\",\"to\":\"{}\",\"type\":\"{}\",\"seq\":{},\"detail\":\"{}\"}}",
            self.t_ms,
            json_escape(&self.kind),
            json_escape(&self.from),
            json_escape(&self.to),
            json_escape(&self.ftype),
            self.seq,
            json_escape(&self.detail)
        )
    }
}

#[derive(Debug, Clone)]
pub struct TraceLog {
    entries: Vec<TraceEntry>,
    cap: usize,
    pub total: u64,
}

impl TraceLog {
    pub fn new(cap: usize) -> Self {
        TraceLog {
            entries: Vec::with_capacity(cap.min(4096)),
            cap,
            total: 0,
        }
    }

    pub fn push(&mut self, entry: TraceEntry) {
        self.total += 1;
        if self.cap == 0 {
            return;
        }
        if self.entries.len() >= self.cap {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    pub fn entries(&self) -> &[TraceEntry] {
        &self.entries
    }

    pub fn recent(&self, n: usize) -> &[TraceEntry] {
        let start = self.entries.len().saturating_sub(n);
        &self.entries[start..]
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.total = 0;
    }
}

pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub fn json_num(v: f64) -> String {
    if v.is_finite() {
        format!("{v}")
    } else {
        "null".to_string()
    }
}
