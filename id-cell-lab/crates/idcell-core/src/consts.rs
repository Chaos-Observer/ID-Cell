//! 协议常量（与 `include/idcell.h`、`src/idcell_internal.h` 对齐）。

pub const SYNC: [u8; 2] = [0xA5, 0xA5];
pub const TRAILER: [u8; 2] = [0x5A, 0xA5];
pub const PROTO_VER_BYTE: u8 = 0x0B;
pub const PROTO_MAJOR: u8 = 0;
pub const HDR_LEN: usize = 36;
pub const AUTH_TAG_LEN: usize = 16;
pub const TRAILER_LEN: usize = 4;
pub const MAX_FRAME: usize = 1500;
pub const MAX_PAYLOAD: usize = MAX_FRAME - HDR_LEN - TRAILER_LEN; // 1460
pub const MAX_AUTH_PAYLOAD: usize = MAX_PAYLOAD - AUTH_TAG_LEN; // 1444
pub const TLV_HDR_LEN: usize = 6;
pub const TLV_CRITICAL_MIN: u8 = 0x80;
pub const TLV_CRITICAL_MAX: u8 = 0xBF;

// 帧标志
pub const FLAG_ENCRYPT: u8 = 0x01;
pub const FLAG_COMPRESS: u8 = 0x02;
pub const FLAG_FRAGMENT: u8 = 0x04;
pub const FLAG_NEEDACK: u8 = 0x08;
pub const FLAG_PREEMPT: u8 = 0x10;
pub const FLAG_AUTH: u8 = 0x20;

// 帧类型
pub mod ftype {
    pub const DISCOVER: u8 = 0x01;
    pub const HELLO: u8 = 0x02;
    pub const MATCH: u8 = 0x03;
    pub const NEGOTIATE: u8 = 0x04;
    pub const RENEGOTIATE: u8 = 0x05;
    pub const AUTH: u8 = 0x06;
    pub const BIND: u8 = 0x07;
    pub const READ: u8 = 0x08;
    pub const WRITE: u8 = 0x09;
    pub const SUBSCRIBE: u8 = 0x0A;
    pub const UNSUB: u8 = 0x0B;
    pub const EVENT: u8 = 0x0C;
    pub const CMD: u8 = 0x0D;
    pub const ACK: u8 = 0x0E;
    pub const DONE: u8 = 0x0F;
    pub const LEASE: u8 = 0x10;
    pub const PREEMPT: u8 = 0x11;
    pub const GROUP: u8 = 0x12;
    pub const HEARTBEAT: u8 = 0x13;
    pub const OFFLINE: u8 = 0x14;
    pub const STALE: u8 = 0x15;
    pub const CONFIG: u8 = 0x16;
    pub const PROVISION: u8 = 0x17;
    pub const ERROR: u8 = 0x18;
    /// 查询请求：按选择器向多提供者索取当前值（Zenoh 风格 query）。
    pub const QUERY: u8 = 0x19;
    /// 查询应答：一个提供者对一个匹配点的单条回复。
    pub const REPLY: u8 = 0x1A;
    /// 应答结束：一个提供者声明本次查询的回复已全部发出。
    pub const REPLY_END: u8 = 0x1B;

    /// 当前协议允许的最大帧类型字节（编解码校验用）。
    pub const MAX_TYPE: u8 = REPLY_END;

    pub fn name(t: u8) -> &'static str {
        match t {
            0x01 => "DISCOVER",
            0x02 => "HELLO",
            0x03 => "MATCH",
            0x04 => "NEGOTIATE",
            0x05 => "RENEGOTIATE",
            0x06 => "AUTH",
            0x07 => "BIND",
            0x08 => "READ",
            0x09 => "WRITE",
            0x0A => "SUBSCRIBE",
            0x0B => "UNSUB",
            0x0C => "EVENT",
            0x0D => "CMD",
            0x0E => "ACK",
            0x0F => "DONE",
            0x10 => "LEASE",
            0x11 => "PREEMPT",
            0x12 => "GROUP",
            0x13 => "HEARTBEAT",
            0x14 => "OFFLINE",
            0x15 => "STALE",
            0x16 => "CONFIG",
            0x17 => "PROVISION",
            0x18 => "ERROR",
            0x19 => "QUERY",
            0x1A => "REPLY",
            0x1B => "REPLY_END",
            _ => "UNKNOWN",
        }
    }
}

// 载荷 TLV 类型（内部头文件 0x20..0x5B）
pub mod tlv_type {
    pub const CAP_DESC: u8 = 0x20;
    pub const REQ_DESC: u8 = 0x21;
    pub const MATCH_RES: u8 = 0x22;
    pub const NEG_RESULT: u8 = 0x23;
    pub const CONTRACT: u8 = 0x24;
    pub const ERR_BODY: u8 = 0x25;
    pub const AUTH_PROOF: u8 = 0x26;
    pub const NONCE: u8 = 0x27;
    pub const VALUE: u8 = 0x28;
    pub const INTENT: u8 = 0x29;
    pub const OWNER: u8 = 0x2A;
    pub const SUMMARY: u8 = 0x2B;
    pub const DESC_VER: u8 = 0x2C;
    pub const DESC_CRC: u8 = 0x2D;
    pub const ARB: u8 = 0x2E;
    pub const TTL: u8 = 0x2F;
    pub const TPUB: u8 = 0x30;
    pub const UNIT: u8 = 0x31;
    pub const PERM: u8 = 0x32;
    pub const INDEX: u8 = 0x33;
    pub const RESULT: u8 = 0x34;
    pub const PROV: u8 = 0x35;
    pub const BIND_ID: u8 = 0x36;
    pub const STR: u8 = 0x37;
    pub const U8: u8 = 0x38;
    pub const U32: u8 = 0x39;
    pub const F64: u8 = 0x3A;
    pub const STALE: u8 = 0x3B;
    pub const QUALITY: u8 = 0x3C;
    pub const BIND_PHASE: u8 = 0x3D;
    pub const SESSION_ID: u8 = 0x3E;
    pub const GRANT_EPOCH: u8 = 0x3F;
    pub const SCHEMA_ID: u8 = 0x40;
    pub const SCHEMA_REF: u8 = 0x41;
    pub const COMMAND_ID: u8 = 0x42;
    pub const VALID_FOR: u8 = 0x43;
    pub const AUTHORITY_ID: u8 = 0x44;
    pub const AUTHORITY_EPOCH: u8 = 0x45;
    pub const MEMBER_EPOCH: u8 = 0x46;
    /// 重连复用的旧绑定号（请与 `idcell_internal.h` 的 OLD_BINDING 对齐）。
    pub const OLD_BINDING: u8 = 0x49;
    /// 重连复用的旧会话号：仅用于校验，实际写入会话 MUST 使用新 session_id。
    pub const OLD_SESSION: u8 = 0x4A;
    /// 重连复用的旧授权纪元（只读校验，不恢复旧权限）。
    pub const OLD_GRANT: u8 = 0x4B;
    pub const MESSAGE: u8 = 0x4C;
    pub const ROLE: u8 = 0x4D;
    pub const ORIGINATOR: u8 = 0x4E;
    pub const QUERY_ID: u8 = 0x4F;
    pub const SCOPE: u8 = 0x50;
    pub const HOP_LIMIT: u8 = 0x51;
    pub const QUERY: u8 = 0x52;
    pub const CHECKIN: u8 = 0x53;
    pub const TARGET: u8 = 0x58;
    /// 查询选择器（文本：`*` / `N` / `N-M` / `N/S` / `N-M/S`）。
    pub const SELECTOR: u8 = 0x59;
    /// 应答目标（查询发起方 DID，中继场景用于回程定位）。
    pub const REPLY_TO: u8 = 0x5A;
    /// 本提供者本次查询的回复总数（REPLY/REPLY_END 携带）。
    pub const REPLY_COUNT: u8 = 0x5B;
    /// 特性位图（u32），HELLO/NEGOTIATE 中声明 QUERY/RELAY 等能力。
    pub const FEATURES: u8 = 0x5C;
    /// 已用跳数（每经过一个中继 +1）。
    pub const HOP_COUNT: u8 = 0x5D;
    /// 查询模式：0=first（只取首个响应），1=all（聚合所有提供者）。
    pub const QUERY_MODE: u8 = 0x5E;
    /// 应答中的能力点标签，便于发起方在无契约时展示。
    pub const LABEL: u8 = 0x5F;
    /// 实验室扩展：HELLO 命中公共描述缓存（1=复用缓存，未携带 CAP_DESC）。
    pub const RESUMED: u8 = 0x60;
    /// 实验室扩展：命令预计执行时长（ms），用于仿真 CMD→ACK→DONE 三段语义。
    pub const EXEC_MS: u8 = 0x61;
    /// 实验室扩展：命令执行结果开关（1=执行失败），用于验证 DONE 必须携带失败原因。
    pub const EXEC_FAIL: u8 = 0x62;
    /// 实验室扩展：描述符分片序号（0 起）。
    pub const DESC_FRAG_IDX: u8 = 0x63;
    /// 实验室扩展：描述符分片总数；缺省表示本次 HELLO 为未分片的完整视图。
    pub const DESC_FRAG_TOTAL: u8 = 0x64;
    /// 组播组号（u16/u32 大端）。
    pub const GROUP_ID: u8 = 0x7A;
    /// 组声明响应模式：0=不要求响应，1=要求响应（可靠组播）。
    pub const RESPONSE_MODE: u8 = 0x7B;
    /// 组声明响应超时（ms）。
    pub const RESPONSE_TIMEOUT: u8 = 0x7C;
    /// 组声明期望成员数（可靠组播缺少即拒绝）。
    pub const EXPECTED_MEMBERS: u8 = 0x7D;
    /// 组成员关系纪元（可靠组播缺少即拒绝）。
    pub const GROUP_EPOCH: u8 = 0x7E;
    /// 组缺席成员数（发送方超时后本地判定）。
    pub const MISSING_MEMBERS: u8 = 0x7F;
    /// 与描述符字段同码，用于契约协商中的值类型/缩放。
    pub const DTYPE: u8 = 0x55;
    pub const SCALE: u8 = 0x56;
}

// 描述符字段类型
pub mod cap_field {
    pub const LABEL: u8 = 0x40;
    pub const KIND: u8 = 0x41;
    pub const DIR: u8 = 0x42;
    pub const PERM: u8 = 0x43;
    pub const DIM: u8 = 0x44;
    pub const UNIT: u8 = 0x45;
    pub const ACCEPT: u8 = 0x46;
    pub const CONV: u8 = 0x47;
    pub const RANGE: u8 = 0x48;
    pub const PRECISION: u8 = 0x49;
    pub const FRAME: u8 = 0x4A;
    pub const INVERT: u8 = 0x4B;
    pub const MINSYNC: u8 = 0x4C;
    pub const STALE: u8 = 0x4D;
    pub const LOADCAP: u8 = 0x4E;
    pub const TRIGGER: u8 = 0x4F;
    pub const HOLD: u8 = 0x50;
    pub const FAIL: u8 = 0x51;
    pub const PROV: u8 = 0x52;
    pub const ESCALATE: u8 = 0x53;
    pub const DEPS: u8 = 0x54;
    pub const DTYPE: u8 = 0x55;
    pub const SCALE: u8 = 0x56;
    pub const ACCEPT_T: u8 = 0x57;
    pub const SCHEMA: u8 = 0x58;
}

pub mod req_field {
    pub const LABEL: u8 = 0x60;
    pub const DIM: u8 = 0x61;
    pub const UNIT: u8 = 0x62;
    pub const ACCEPT: u8 = 0x63;
    pub const PERM: u8 = 0x64;
    pub const INDEX: u8 = 0x65;
    pub const WANT: u8 = 0x66;
    pub const STALE: u8 = 0x67;
    pub const RANGE: u8 = 0x68;
    pub const KIND: u8 = 0x69;
    pub const ACCEPT_T: u8 = 0x6A;
    pub const SCHEMA: u8 = 0x6B;
}

pub mod err_field {
    pub const CODE: u8 = 0x70;
    pub const OBJECT: u8 = 0x71;
    pub const REQUIRED: u8 = 0x72;
    pub const CURRENT: u8 = 0x73;
    pub const REASON: u8 = 0x74;
    pub const RETRY: u8 = 0x75;
    pub const RANGE_LO: u8 = 0x76;
    pub const RANGE_HI: u8 = 0x77;
    pub const VALUE: u8 = 0x78;
    pub const INDEX: u8 = 0x79;
}

// 绑定阶段（两阶段提交）
pub mod bind_phase {
    pub const PREPARE: u8 = 1;
    pub const PREPARED: u8 = 2;
    pub const COMMIT: u8 = 3;
    pub const COMMITTED: u8 = 4;
    pub const ABORT: u8 = 5;
    pub const RELEASE: u8 = 6;
}

/// GROUP 帧语义（FR-070）：组声明、成员应答。
pub mod group_phase {
    /// 组播声明；可靠组播必须携带 group_epoch 与 expected_members。
    pub const DECLARE: u8 = 1;
    /// 成员应答（仅可靠组播要求）。
    pub const REPORT: u8 = 2;
}

/// 组播响应模式。
pub mod response_mode {
    /// 广播/普通组播：不要求响应，不承诺送达。
    pub const NONE: u8 = 0;
    /// 可靠组播：要求成员在 response_timeout 内应答。
    pub const REQUIRED: u8 = 1;
}

/// CONFIG 配置项的最低访问等级（FR-065）：配置项至少需要 P2。
pub const CONFIG_MIN_PERM: u8 = 2;

// 发现消息语义
pub const DISCOVER_ANNOUNCE: u8 = 1;
pub const DISCOVER_PROBE: u8 = 2;
pub const DISCOVER_RESPONSE: u8 = 3;

pub const ROLE_CAPABILITY: u8 = 1;
pub const ROLE_REQUIREMENT: u8 = 2;

/// 查询模式
pub mod query_mode {
    /// 收到首个应答即完成（低时延优先）。
    pub const FIRST: u8 = 0;
    /// 聚合所有提供者的应答，直到超时或全部 REPLY_END。
    pub const ALL: u8 = 1;

    pub fn name(m: u8) -> &'static str {
        match m {
            FIRST => "first",
            _ => "all",
        }
    }
}

/// 协议特性位（FEATURES TLV 的 u32 位图）。
pub mod feature {
    pub const QUERY: u32 = 1 << 0;
    pub const SELECTOR: u32 = 1 << 1;
    pub const RELAY: u32 = 1 << 2;
    pub const QUERY_AGGREGATE: u32 = 1 << 3;

    pub const ALL: u32 = QUERY | SELECTOR | RELAY | QUERY_AGGREGATE;

    pub fn list(bits: u32) -> String {
        let mut out = Vec::new();
        if bits & QUERY != 0 {
            out.push("query");
        }
        if bits & SELECTOR != 0 {
            out.push("selector");
        }
        if bits & RELAY != 0 {
            out.push("relay");
        }
        if bits & QUERY_AGGREGATE != 0 {
            out.push("aggregate");
        }
        out.join(",")
    }
}

// 量种（§24.2）
pub mod qty {
    pub const RATIO: u8 = 0;
    pub const LENGTH: u8 = 1;
    pub const ANGLE: u8 = 2;
    pub const MASS: u8 = 3;
    pub const TIME: u8 = 4;
    pub const TEMPERATURE: u8 = 5;
    pub const CURRENT: u8 = 6;
    pub const CHARGE: u8 = 7;
    pub const LUMINOSITY: u8 = 8;
    pub const FORCE: u8 = 9;
    pub const TORQUE: u8 = 10;
    pub const PRESSURE: u8 = 11;
    pub const VELOCITY: u8 = 12;
    pub const ACCELERATION: u8 = 13;
    pub const ENERGY: u8 = 14;
    pub const POWER: u8 = 15;
    pub const VOLTAGE: u8 = 16;
    pub const RESISTANCE: u8 = 17;
    pub const CAPACITANCE: u8 = 18;
    pub const INDUCTANCE: u8 = 19;
    pub const FREQUENCY: u8 = 20;
    pub const MAGFLUX: u8 = 21;
    pub const MAGDENS: u8 = 22;
    pub const DATACOUNT: u8 = 23;
    pub const COUNT: u8 = 24;

    pub fn name(q: u8) -> &'static str {
        match q {
            0 => "ratio",
            1 => "length",
            2 => "angle",
            3 => "mass",
            4 => "time",
            5 => "temperature",
            6 => "current",
            7 => "charge",
            8 => "luminosity",
            9 => "force",
            10 => "torque",
            11 => "pressure",
            12 => "velocity",
            13 => "acceleration",
            14 => "energy",
            15 => "power",
            16 => "voltage",
            17 => "resistance",
            18 => "capacitance",
            19 => "inductance",
            20 => "frequency",
            21 => "magflux",
            22 => "magdens",
            23 => "datacount",
            _ => "unknown",
        }
    }
}

// 值类型（§24.4）
pub mod dtype {
    pub const I8: u8 = 0;
    pub const U8: u8 = 1;
    pub const I16: u8 = 2;
    pub const U16: u8 = 3;
    pub const I32: u8 = 4;
    pub const U32: u8 = 5;
    pub const I64: u8 = 6;
    pub const U64: u8 = 7;
    pub const F32: u8 = 8;
    pub const F64: u8 = 9;
    pub const BOOL: u8 = 10;
    pub const STRING: u8 = 11;
    pub const BYTES: u8 = 12;

    pub fn name(d: u8) -> &'static str {
        match d {
            0 => "i8",
            1 => "u8",
            2 => "i16",
            3 => "u16",
            4 => "i32",
            5 => "u32",
            6 => "i64",
            7 => "u64",
            8 => "f32",
            9 => "f64",
            10 => "bool",
            11 => "string",
            12 => "bytes",
            _ => "?",
        }
    }
}

// 质量码（§24.5）
pub mod quality {
    pub const GOOD: u8 = 0;
    pub const UNCERTAIN: u8 = 1;
    pub const BAD: u8 = 2;
}

// 触发类型
pub mod trigger {
    pub const LEVEL: u8 = 0;
    pub const EDGE: u8 = 1;
    pub const BOTH: u8 = 2;
}

// 存在状态
pub mod presence {
    pub const ONLINE: u8 = 0;
    pub const ASLEEP: u8 = 1;
    pub const OFFLINE: u8 = 2;
}

pub const INDEX_ANY: u16 = 0xFFFF;
pub const BROADCAST: [u8; 8] = [0xFF; 8];

pub fn type_name(t: u8) -> &'static str {
    ftype::name(t)
}
