//! 协议错误码（`idcell.h` 枚举值 0..=18）。

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ErrCode {
    Ok = 0,
    NoDev = 1,
    Ver = 2,
    Crc = 3,
    NoMatch = 4,
    Conv = 5,
    Negotiate = 6,
    Perm = 7,
    Unsafe = 8,
    Lease = 9,
    Range = 10,
    Unit = 11,
    Ctx = 12,
    IdConflict = 13,
    Scope = 14,
    Unavailable = 15,
    Duplicate = 16,
    Asleep = 17,
    RxOff = 18,
    State = 19,
}

impl ErrCode {
    pub fn from_u8(v: u8) -> ErrCode {
        match v {
            0 => ErrCode::Ok,
            1 => ErrCode::NoDev,
            2 => ErrCode::Ver,
            3 => ErrCode::Crc,
            4 => ErrCode::NoMatch,
            5 => ErrCode::Conv,
            6 => ErrCode::Negotiate,
            7 => ErrCode::Perm,
            8 => ErrCode::Unsafe,
            9 => ErrCode::Lease,
            10 => ErrCode::Range,
            11 => ErrCode::Unit,
            12 => ErrCode::Ctx,
            13 => ErrCode::IdConflict,
            14 => ErrCode::Scope,
            15 => ErrCode::Unavailable,
            16 => ErrCode::Duplicate,
            17 => ErrCode::Asleep,
            18 => ErrCode::RxOff,
            _ => ErrCode::State,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            ErrCode::Ok => "OK",
            ErrCode::NoDev => "E_NODEV",
            ErrCode::Ver => "E_VER",
            ErrCode::Crc => "E_CRC",
            ErrCode::NoMatch => "E_NOMATCH",
            ErrCode::Conv => "E_CONV",
            ErrCode::Negotiate => "E_NEGOTIATE",
            ErrCode::Perm => "E_PERM",
            ErrCode::Unsafe => "E_UNSAFE",
            ErrCode::Lease => "E_LEASE",
            ErrCode::Range => "E_RANGE",
            ErrCode::Unit => "E_UNIT",
            ErrCode::Ctx => "E_CTX",
            ErrCode::IdConflict => "E_IDCONFLICT",
            ErrCode::Scope => "E_SCOPE",
            ErrCode::Unavailable => "E_UNAVAILABLE",
            ErrCode::Duplicate => "E_DUPLICATE",
            ErrCode::Asleep => "E_ASLEEP",
            ErrCode::RxOff => "E_RX_OFF",
            ErrCode::State => "E_STATE",
        }
    }

    /// 不匹配类可带候选值重试；拒绝类重试无意义。
    pub fn retryable(self) -> bool {
        matches!(self, ErrCode::NoMatch | ErrCode::Negotiate | ErrCode::Lease)
    }

    /// 拒绝类：安全策略、权限、状态一类的确定性拒绝。
    pub fn is_reject(self) -> bool {
        !self.retryable() && self != ErrCode::Ok
    }
}

impl std::fmt::Display for ErrCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}
