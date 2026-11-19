//! 单位换算：量种优先（FR-082），量种不同绝不换算。

use crate::consts::qty;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvError {
    /// 量种不同，禁止换算。
    QtyMismatch,
    /// 未知或不支持的单位。
    Unit,
    /// 需要参考条件（T3）。
    MissingContext,
    /// 有损不可逆（T4）。
    Lossy,
}

impl std::fmt::Display for ConvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ConvError::QtyMismatch => "E_UNIT: 量种不同，禁止换算",
            ConvError::Unit => "E_UNIT: 未知单位",
            ConvError::MissingContext => "E_CTX: 缺参考条件",
            ConvError::Lossy => "E_CONV: 有损不可逆",
        };
        f.write_str(s)
    }
}

/// (单位码, 到基准单位的比例, 偏移)。基准单位见 `base_unit`。
fn unit_factor(q: u8, unit: &str) -> Option<(f64, f64)> {
    let u = unit.trim();
    let table: &[(&str, f64, f64)] = match q {
        qty::RATIO => &[("1", 1.0, 0.0), ("%", 0.01, 0.0), ("ppm", 1e-6, 0.0)],
        qty::LENGTH => &[
            ("m", 1.0, 0.0),
            ("mm", 1e-3, 0.0),
            ("cm", 1e-2, 0.0),
            ("km", 1e3, 0.0),
            ("um", 1e-6, 0.0),
            ("in", 0.0254, 0.0),
        ],
        qty::ANGLE => &[("rad", 1.0, 0.0), ("mrad", 1e-3, 0.0), ("deg", std::f64::consts::PI / 180.0, 0.0)],
        qty::MASS => &[("kg", 1.0, 0.0), ("g", 1e-3, 0.0), ("mg", 1e-6, 0.0)],
        qty::TIME => &[("s", 1.0, 0.0), ("ms", 1e-3, 0.0), ("us", 1e-6, 0.0), ("min", 60.0, 0.0)],
        qty::TEMPERATURE => &[("K", 1.0, 0.0), ("Cel", 1.0, 273.15)],
        qty::CURRENT => &[("A", 1.0, 0.0), ("mA", 1e-3, 0.0), ("uA", 1e-6, 0.0)],
        qty::CHARGE => &[("C", 1.0, 0.0), ("mC", 1e-3, 0.0)],
        qty::FORCE => &[("N", 1.0, 0.0), ("mN", 1e-3, 0.0), ("kN", 1e3, 0.0)],
        qty::TORQUE => &[("N.m", 1.0, 0.0), ("Nmm", 1e-3, 0.0)],
        qty::PRESSURE => &[("Pa", 1.0, 0.0), ("kPa", 1e3, 0.0), ("MPa", 1e6, 0.0), ("bar", 1e5, 0.0)],
        qty::VELOCITY => &[("m/s", 1.0, 0.0), ("mm/s", 1e-3, 0.0)],
        qty::ACCELERATION => &[("m/s2", 1.0, 0.0), ("mm/s2", 1e-3, 0.0)],
        qty::ENERGY => &[("J", 1.0, 0.0), ("kJ", 1e3, 0.0)],
        qty::POWER => &[("W", 1.0, 0.0), ("mW", 1e-3, 0.0), ("kW", 1e3, 0.0)],
        qty::VOLTAGE => &[("V", 1.0, 0.0), ("mV", 1e-3, 0.0), ("kV", 1e3, 0.0)],
        qty::RESISTANCE => &[("Ohm", 1.0, 0.0), ("kOhm", 1e3, 0.0)],
        qty::CAPACITANCE => &[("F", 1.0, 0.0), ("mF", 1e-3, 0.0), ("uF", 1e-6, 0.0), ("nF", 1e-9, 0.0)],
        qty::INDUCTANCE => &[("H", 1.0, 0.0), ("mH", 1e-3, 0.0), ("uH", 1e-6, 0.0)],
        qty::FREQUENCY => &[("Hz", 1.0, 0.0), ("kHz", 1e3, 0.0), ("MHz", 1e6, 0.0)],
        qty::DATACOUNT => &[("By", 1.0, 0.0), ("kBy", 1e3, 0.0), ("MBy", 1e6, 0.0)],
        qty::LUMINOSITY => &[("cd", 1.0, 0.0)],
        qty::MAGFLUX => &[("Wb", 1.0, 0.0)],
        qty::MAGDENS => &[("T", 1.0, 0.0)],
        _ => &[],
    };
    table
        .iter()
        .find(|(name, _, _)| *name == u)
        .map(|(_, f, o)| (*f, *o))
}

/// 同一量种内的换算。量种不同直接拒绝（FR-082）。
pub fn convert(from_qty: u8, to_qty: u8, from_unit: &str, to_unit: &str, v: f64) -> Result<f64, ConvError> {
    if from_qty != to_qty {
        return Err(ConvError::QtyMismatch);
    }
    if from_unit == to_unit {
        return Ok(v);
    }
    let (ff, fo) = unit_factor(from_qty, from_unit).ok_or(ConvError::Unit)?;
    let (tf, to) = unit_factor(to_qty, to_unit).ok_or(ConvError::Unit)?;
    if ff <= 0.0 || tf <= 0.0 {
        return Err(ConvError::Unit);
    }
    Ok(((v * ff + fo) - to) / tf)
}

/// 自动换算等级：T1 纯比例、T2 比例+偏移；T0/T3/T4 不在自动换算范围。
pub fn conv_class(from_qty: u8, to_qty: u8, from_unit: &str, to_unit: &str) -> u8 {
    if from_qty != to_qty {
        return 0;
    }
    if from_unit == to_unit {
        return 1;
    }
    match (unit_factor(from_qty, from_unit), unit_factor(to_qty, to_unit)) {
        (Some((_, fo)), Some((_, to))) => {
            if fo == 0.0 && to == 0.0 {
                1
            } else {
                2
            }
        }
        _ => 0,
    }
}

pub fn base_unit(q: u8) -> &'static str {
    match q {
        qty::RATIO => "1",
        qty::LENGTH => "m",
        qty::ANGLE => "rad",
        qty::MASS => "kg",
        qty::TIME => "s",
        qty::TEMPERATURE => "K",
        qty::CURRENT => "A",
        qty::CHARGE => "C",
        qty::LUMINOSITY => "cd",
        qty::FORCE => "N",
        qty::TORQUE => "N.m",
        qty::PRESSURE => "Pa",
        qty::VELOCITY => "m/s",
        qty::ACCELERATION => "m/s2",
        qty::ENERGY => "J",
        qty::POWER => "W",
        qty::VOLTAGE => "V",
        qty::RESISTANCE => "Ohm",
        qty::CAPACITANCE => "F",
        qty::INDUCTANCE => "H",
        qty::FREQUENCY => "Hz",
        qty::MAGFLUX => "Wb",
        qty::MAGDENS => "T",
        qty::DATACOUNT => "By",
        _ => "1",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn force_units() {
        assert!((convert(qty::FORCE, qty::FORCE, "N", "mN", 1.5).unwrap() - 1500.0).abs() < 1e-9);
        assert!((convert(qty::FORCE, qty::FORCE, "kN", "N", 2.0).unwrap() - 2000.0).abs() < 1e-9);
    }

    #[test]
    fn different_qty_is_rejected() {
        assert_eq!(
            convert(qty::FORCE, qty::TORQUE, "N", "N.m", 1.0),
            Err(ConvError::QtyMismatch)
        );
    }

    #[test]
    fn temperature_offset() {
        assert!((convert(qty::TEMPERATURE, qty::TEMPERATURE, "Cel", "K", 0.0).unwrap() - 273.15).abs() < 1e-9);
    }
}
