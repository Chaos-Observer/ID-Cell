//! ID-CELL 协议核心库（零外部依赖）。
//!
//! 帧层与 C 参考实现 `id-cell-refimpl` 字节兼容：
//!   SYNC(2) VER(1) PROF(1) FLAGS(1) TYPE(1) SEQ(2) TXN(2) LEN(2)
//!   SRC(8) DST(8) GROUP(2) TS(6) | PAYLOAD | AUTH_TAG(0/16) | CRC16(2) TRAILER(2)
//!
//! 所有多字节字段为大端序。

pub mod consts;
pub mod crc;
pub mod crypto;
pub mod desc;
pub mod errors;
pub mod frame;
pub mod tlv;
pub mod units;
pub mod value;

pub use consts::*;
pub use crc::crc16;
pub use crypto::hmac_sha256;
pub use desc::{Capability, Requirement, Selector, TypePair};
pub use errors::ErrCode;
pub use frame::{DecodeError, Did, Frame, StreamParser};
pub use tlv::{decode_tlvs, encode_tlvs, find, Tlv, TlvWriter};
pub use value::{decode_value, encode_value};
