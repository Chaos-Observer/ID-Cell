//! 值载荷编解码（§24.4）：帧内不出现无类型裸浮点，整数按 scale 定点编码。

use crate::consts::dtype;

fn pow10(scale: u8) -> f64 {
    10f64.powi(-(scale as i32))
}

pub fn encode_value(dt: u8, scale: u8, v: f64) -> Vec<u8> {
    let s = pow10(scale);
    match dt {
        dtype::BOOL => vec![u8::from(v != 0.0)],
        dtype::I8 => {
            let raw = (v / s).round().clamp(-128.0, 127.0) as i8;
            vec![raw as u8]
        }
        dtype::U8 => {
            let raw = (v / s).round().clamp(0.0, 255.0) as u8;
            vec![raw]
        }
        dtype::I16 => {
            let raw = (v / s).round().clamp(-32768.0, 32767.0) as i16;
            raw.to_be_bytes().to_vec()
        }
        dtype::U16 => {
            let raw = (v / s).round().clamp(0.0, 65535.0) as u16;
            raw.to_be_bytes().to_vec()
        }
        dtype::I32 => {
            let raw = (v / s).round().clamp(-2147483648.0, 2147483647.0) as i32;
            raw.to_be_bytes().to_vec()
        }
        dtype::U32 => {
            let raw = (v / s).round().clamp(0.0, 4294967295.0) as u32;
            raw.to_be_bytes().to_vec()
        }
        dtype::I64 => {
            let raw = (v / s).round() as i64;
            raw.to_be_bytes().to_vec()
        }
        dtype::U64 => {
            let raw = (v / s).round().max(0.0) as u64;
            raw.to_be_bytes().to_vec()
        }
        dtype::F32 => (v as f32).to_bits().to_be_bytes().to_vec(),
        dtype::F64 => v.to_bits().to_be_bytes().to_vec(),
        dtype::STRING => format!("{}", v).into_bytes(),
        dtype::BYTES => v.to_be_bytes().to_vec(),
        _ => v.to_bits().to_be_bytes().to_vec(),
    }
}

pub fn decode_value(dt: u8, scale: u8, b: &[u8]) -> Option<f64> {
    let s = pow10(scale);
    match dt {
        dtype::BOOL => b.first().map(|v| f64::from(*v != 0)),
        dtype::I8 => b.first().map(|v| (*v as i8) as f64 * s),
        dtype::U8 => b.first().map(|v| *v as f64 * s),
        dtype::I16 => (b.len() >= 2).then(|| i16::from_be_bytes([b[0], b[1]]) as f64 * s),
        dtype::U16 => (b.len() >= 2).then(|| u16::from_be_bytes([b[0], b[1]]) as f64 * s),
        dtype::I32 => (b.len() >= 4).then(|| {
            i32::from_be_bytes([b[0], b[1], b[2], b[3]]) as f64 * s
        }),
        dtype::U32 => (b.len() >= 4).then(|| {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as f64 * s
        }),
        dtype::I64 => (b.len() >= 8).then(|| {
            let mut x = [0u8; 8];
            x.copy_from_slice(&b[..8]);
            i64::from_be_bytes(x) as f64 * s
        }),
        dtype::U64 => (b.len() >= 8).then(|| {
            let mut x = [0u8; 8];
            x.copy_from_slice(&b[..8]);
            u64::from_be_bytes(x) as f64 * s
        }),
        dtype::F32 => (b.len() >= 4).then(|| {
            f32::from_bits(u32::from_be_bytes([b[0], b[1], b[2], b[3]])) as f64
        }),
        dtype::F64 | dtype::STRING | dtype::BYTES => (b.len() >= 8).then(|| {
            let mut x = [0u8; 8];
            x.copy_from_slice(&b[..8]);
            f64::from_bits(u64::from_be_bytes(x))
        }),
        _ => (b.len() >= 8).then(|| {
            let mut x = [0u8; 8];
            x.copy_from_slice(&b[..8]);
            f64::from_bits(u64::from_be_bytes(x))
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::dtype;

    #[test]
    fn int_roundtrip_with_scale() {
        let b = encode_value(dtype::I32, 3, 12.3456);
        assert_eq!(b.len(), 4);
        let v = decode_value(dtype::I32, 3, &b).unwrap();
        // 12.3456 按 3 位小数四舍五入到 12.346
        assert!((v - 12.346).abs() < 1e-9);
    }

    #[test]
    fn bool_roundtrip() {
        assert_eq!(decode_value(dtype::BOOL, 0, &encode_value(dtype::BOOL, 0, 2.0)), Some(1.0));
    }
}
