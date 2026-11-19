//! 极简 JSON 解析器（零依赖），满足场景文件与 Web API 需要。

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(items) => items.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Number(v) => Some(*v),
            Json::String(s) => s.parse().ok(),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.as_f64().map(|v| v.max(0.0) as u64)
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            Json::Number(v) => Some(*v != 0.0),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(v) => Some(v),
            _ => None,
        }
    }

    pub fn str_field(&self, key: &str) -> Option<String> {
        self.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
    }

    pub fn f64_field(&self, key: &str) -> Option<f64> {
        self.get(key).and_then(|v| v.as_f64())
    }

    pub fn u64_field(&self, key: &str) -> Option<u64> {
        self.get(key).and_then(|v| v.as_u64())
    }

    pub fn bool_field(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(|v| v.as_bool())
    }

    pub fn array_field(&self, key: &str) -> Option<&[Json]> {
        self.get(key).and_then(|v| v.as_array())
    }
}

pub fn parse(text: &str) -> Result<Json, String> {
    // 容忍 Windows 编辑器写入的 UTF-8 BOM
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut p = Parser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    p.skip_ws();
    let v = p.parse_value()?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(format!("JSON 尾部有多余内容（位置 {}）", p.pos));
    }
    Ok(v)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), String> {
        if self.bump() == Some(b) {
            Ok(())
        } else {
            Err(format!("期望字符 '{}'（位置 {}）", b as char, self.pos))
        }
    }

    fn parse_value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        match self.peek() {
            None => Err("JSON 意外结束".into()),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Json::String(self.parse_string()?)),
            Some(b't') => {
                self.literal("true")?;
                Ok(Json::Bool(true))
            }
            Some(b'f') => {
                self.literal("false")?;
                Ok(Json::Bool(false))
            }
            Some(b'n') => {
                self.literal("null")?;
                Ok(Json::Null)
            }
            Some(c) if c == b'-' || c.is_ascii_digit() => self.parse_number(),
            Some(c) => Err(format!("非法 JSON 字符 '{}'（位置 {}）", c as char, self.pos)),
        }
    }

    fn literal(&mut self, s: &str) -> Result<(), String> {
        if self.bytes[self.pos..].starts_with(s.as_bytes()) {
            self.pos += s.len();
            Ok(())
        } else {
            Err(format!("非法字面量（位置 {}）", self.pos))
        }
    }

    fn parse_object(&mut self) -> Result<Json, String> {
        self.expect(b'{')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Object(items));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            let value = self.parse_value()?;
            items.push((key, value));
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b'}') => break,
                _ => return Err(format!("对象缺少 , 或 }}（位置 {}）", self.pos)),
            }
        }
        Ok(Json::Object(items))
    }

    fn parse_array(&mut self) -> Result<Json, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            let value = self.parse_value()?;
            items.push(value);
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b']') => break,
                _ => return Err(format!("数组缺少 , 或 ]（位置 {}）", self.pos)),
            }
        }
        Ok(Json::Array(items))
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            match self.bump() {
                None => return Err("字符串未闭合".into()),
                Some(b'"') => break,
                Some(b'\\') => match self.bump() {
                    Some(b'"') => out.push('"'),
                    Some(b'\\') => out.push('\\'),
                    Some(b'/') => out.push('/'),
                    Some(b'b') => out.push('\u{8}'),
                    Some(b'f') => out.push('\u{c}'),
                    Some(b'n') => out.push('\n'),
                    Some(b'r') => out.push('\r'),
                    Some(b't') => out.push('\t'),
                    Some(b'u') => {
                        let cp = self.parse_hex4()?;
                        if (0xD800..0xDC00).contains(&cp) {
                            // 代理对
                            if self.bump() == Some(b'\\') && self.bump() == Some(b'u') {
                                let low = self.parse_hex4()?;
                                let full =
                                    0x10000 + ((cp - 0xD800) << 10) + (low.wrapping_sub(0xDC00));
                                if let Some(c) = char::from_u32(full) {
                                    out.push(c);
                                }
                            }
                        } else if let Some(c) = char::from_u32(cp) {
                            out.push(c);
                        }
                    }
                    _ => return Err("非法转义".into()),
                },
                Some(b) if b < 0x80 => out.push(b as char),
                Some(_) => {
                    // UTF-8 多字节：回退并按字符解析
                    self.pos -= 1;
                    let rest = std::str::from_utf8(&self.bytes[self.pos..])
                        .map_err(|_| "UTF-8 解码失败".to_string())?;
                    let c = rest.chars().next().ok_or("字符串为空")?;
                    out.push(c);
                    self.pos += c.len_utf8();
                }
            }
        }
        Ok(out)
    }

    fn parse_hex4(&mut self) -> Result<u32, String> {
        let mut v = 0u32;
        for _ in 0..4 {
            let b = self.bump().ok_or("\\u 转义不完整")?;
            let digit = (b as char).to_digit(16).ok_or("\\u 转义非十六进制")?;
            v = v * 16 + digit;
        }
        Ok(v)
    }

    fn parse_number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || c == b'.' || c == b'e' || c == b'E' || c == b'+' || c == b'-' {
                self.pos += 1;
            } else {
                break;
            }
        }
        let s = std::str::from_utf8(&self.bytes[start..self.pos]).unwrap_or("");
        s.parse::<f64>()
            .map(Json::Number)
            .map_err(|_| format!("非法数字 '{s}'"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nested() {
        let v = parse(r#"{"a":[1,2,{"b":"x\ny"}],"c":true}"#).unwrap();
        assert_eq!(v.get("c").and_then(|x| x.as_bool()), Some(true));
        assert_eq!(v.array_field("a").unwrap().len(), 3);
    }

    #[test]
    fn rejects_trailing() {
        assert!(parse("{} x").is_err());
    }
}
