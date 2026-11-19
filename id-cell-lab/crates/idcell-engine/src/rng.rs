//! 确定性伪随机数（PCG32），保证同一 seed 的场景可复现。

#[derive(Debug, Clone)]
pub struct Rng {
    state: u64,
    inc: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        let mut r = Rng {
            state: seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407),
            inc: 0xda3e39cb94b95bdb,
        };
        r.next_u32();
        r
    }

    pub fn next_u32(&mut self) -> u32 {
        let old = self.state;
        self.state = old
            .wrapping_mul(6364136223846793005)
            .wrapping_add(self.inc);
        let xorshifted = (((old >> 18) ^ old) >> 27) as u32;
        let rot = (old >> 59) as u32;
        xorshifted.rotate_right(rot)
    }

    pub fn next_f64(&mut self) -> f64 {
        (self.next_u32() as f64) / (u32::MAX as f64 + 1.0)
    }

    /// 闭区间 [lo, hi]。
    pub fn range_u32(&mut self, lo: u32, hi: u32) -> u32 {
        if hi <= lo {
            return lo;
        }
        lo + (self.next_u32() % (hi - lo + 1))
    }

    /// ppm 概率命中。
    pub fn chance_ppm(&mut self, ppm: u32) -> bool {
        ppm > 0 && self.next_u32() % 1_000_000 < ppm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u32(), b.next_u32());
        }
    }
}
