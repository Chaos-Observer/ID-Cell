//! ID-CELL 仿真引擎。

pub mod device;
pub mod link;
pub mod rng;
pub mod trace;
pub mod world;

pub use device::{
    Action, Contract, Device, DeviceCounters, DeviceSpec, Lease, LogicKind, LogicRule, LogicState,
    PointSim, QueryReply, QuerySession, ReceivedValue, Role, RunMode, Session, Stage,
};
pub use link::{media_catalog_json, media_spec, Link, LinkConfig, MediaSpec, MEDIA_CATALOG};
pub use rng::Rng;
pub use trace::{json_escape, json_num, TraceEntry, TraceLog};
pub use world::{
    DeviceView, FrameView, LinkView, Metrics, QueryReplyView, QueryView, SessionView, Snapshot,
    ValueView, World, WorldConfig,
};
