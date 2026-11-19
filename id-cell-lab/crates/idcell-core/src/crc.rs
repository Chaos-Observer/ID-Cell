//! CRC-16/CCITT-FALSE：poly=0x1021, init=0xFFFF, refin=false, refout=false,
//! xorout=0x0000（与 C 参考实现一致）。

pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// 逐位实现的查表版本，供高吞吐场景使用；结果必须与 `crc16` 完全一致。
pub fn crc16_fast(data: &[u8]) -> u16 {
    static TABLE: [u16; 256] = build_table();
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc = (crc << 8) ^ TABLE[(((crc >> 8) as u8) ^ b) as usize];
    }
    crc
}

const fn build_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = (i as u16) << 8;
        let mut b = 0;
        while b < 8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
            b += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_check_value() {
        // CRC-16/CCITT-FALSE("123456789") = 0x29B1
        assert_eq!(crc16(b"123456789"), 0x29B1);
        assert_eq!(crc16_fast(b"123456789"), 0x29B1);
    }

    #[test]
    fn fast_matches_bitwise() {
        let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        assert_eq!(crc16(&data), crc16_fast(&data));
    }
}
