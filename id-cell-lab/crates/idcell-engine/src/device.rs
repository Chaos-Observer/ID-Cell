//! 虚拟设备：能力/需求、六段管道状态机、运行期租约/心跳/发布/抢占。

use idcell_core::consts::{
    bind_phase, err_field, ftype, group_phase, query_mode, quality, response_mode, tlv_type,
    CONFIG_MIN_PERM, DISCOVER_PROBE, FLAG_COMPRESS, FLAG_ENCRYPT, FLAG_NEEDACK, ROLE_CAPABILITY,
    ROLE_REQUIREMENT,
};
use idcell_core::desc::{matches, matches_public};
use idcell_core::{
    crc16, decode_tlvs, decode_value, encode_value, hmac_sha256, Capability, Did, ErrCode, Frame,
    Requirement, Selector, TlvWriter,
};
use std::collections::{BTreeMap, BTreeSet};

pub const HEARTBEAT_MS: u64 = 1000;
pub const LINK_TIMEOUT_MS: u64 = 3000;
pub const DEFAULT_TTL_MS: u32 = 3000;
pub const DEFAULT_ARB: u32 = 1;
/// 查询未收到 REPLY_END 时的兜底超时。
pub const QUERY_TIMEOUT_MS: u64 = 800;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Consumer,
    Provider,
}

impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Role::Consumer => "consumer",
            Role::Provider => "provider",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Idle,
    HelloReceived,
    Matched,
    Negotiating,
    Authenticating,
    Authed,
    Binding,
    BindingPrepared,
    Active,
    Stale,
    Failed,
    Closed,
}

impl Stage {
    pub fn name(self) -> &'static str {
        match self {
            Stage::Idle => "idle",
            Stage::HelloReceived => "hello",
            Stage::Matched => "matched",
            Stage::Negotiating => "negotiating",
            Stage::Authenticating => "authenticating",
            Stage::Authed => "authed",
            Stage::Binding => "binding",
            Stage::BindingPrepared => "binding_prepared",
            Stage::Active => "active",
            Stage::Stale => "stale",
            Stage::Failed => "failed",
            Stage::Closed => "closed",
        }
    }

    pub fn is_pipeline_done(self) -> bool {
        matches!(self, Stage::Active | Stage::Stale)
    }
}

#[derive(Debug, Clone)]
pub struct PointSim {
    pub base: f64,
    pub amplitude: f64,
    pub period_ms: u64,
    pub noise: f64,
    pub phase: f64,
    pub seed: u64,
}

/// 控制器行为类型：在通用设备模型（接口链路 + 协议 + 点位）之上叠加的应用层。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicKind {
    /// 阈值联动：输入点与阈值比较，成立写 on 值，否则写 off 值。
    Threshold,
    /// 聚合计算：对若干输入点求 avg/sum/min/max/count，写入输出点。
    Aggregate,
}

/// 一条设备行为规则。既支持“算完写本地能力点”，也支持“直接控制远端执行器”。
#[derive(Debug, Clone)]
pub struct LogicRule {
    pub name: String,
    pub kind: LogicKind,
    /// 参与判断/计算的接收点 (index, sub)。
    pub sources: Vec<(u16, u8)>,
    /// 1 > 2 >= 3 < 4 <= 5 == 6 between
    pub op: u8,
    pub threshold: f64,
    pub threshold2: f64,
    pub on_value: f64,
    pub off_value: f64,
    /// 1 avg 2 sum 3 min 4 max 5 count
    pub agg: u8,
    /// 输出目标设备名；为空表示写本设备能力点。
    pub target: String,
    pub output: (u16, u8),
    /// 触发后的最短静默，防止抖振（0 表示不限制）。
    pub min_interval_ms: u64,
}

#[derive(Debug, Clone, Default)]
pub struct LogicState {
    pub last_ms: u64,
    pub last_out: Option<f64>,
}

impl Default for PointSim {
    fn default() -> Self {
        PointSim {
            base: 0.0,
            amplitude: 0.0,
            period_ms: 1000,
            noise: 0.0,
            phase: 0.0,
            seed: 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PointState {
    pub value: f64,
    pub ts_ms: u64,
    pub quality: u8,
}

#[derive(Debug, Clone)]
pub struct ReceivedValue {
    pub value: f64,
    pub quality: u8,
    pub prov: u8,
    pub received_ms: u64,
    pub stale: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Contract {
    pub binding_id: u32,
    pub session_id: u64,
    pub grant_epoch: u64,
    pub owner_token: u32,
    pub ttl_ms: u32,
    pub t_pub_ms: u32,
    pub arb: u32,
    pub index: u16,
    pub sub: u8,
    pub perm: u8,
    pub unit: String,
    pub dtype: u8,
    pub scale_exp: u8,
    pub stale_ms: u32,
}

#[derive(Debug, Clone, Default)]
pub struct BindingCache {
    pub binding_id: u32,
    pub desc_version: u32,
    pub desc_crc: u32,
    /// 上一次成功绑定的 session_id；重连时作为 OLD_SESSION 校验，绝不直接复用。
    pub session_id: u64,
    /// 上一次的授权纪元；重连只用于校验，新会话必须使用新纪元。
    pub grant_epoch: u64,
    pub index: u16,
    pub sub: u8,
}

/// 消费者缓存的公共描述视图（FR-006/FR-028）。
#[derive(Debug, Clone)]
pub struct DescCache {
    pub desc_version: u32,
    pub desc_crc: u32,
    pub caps: Vec<Capability>,
}

/// 描述符分片重组缓冲（FR-008/SEC-026）。
#[derive(Debug, Clone)]
pub struct FragBuffer {
    pub desc_version: u32,
    pub desc_crc: u32,
    pub total: usize,
    pub chunks: Vec<Option<Vec<u8>>>,
    pub deadline_ms: u64,
}

/// 单个分片载荷上限：留足 TLV/帧头余量，确保不超过 MAX_FRAME。
pub const DESC_FRAG_BYTES: usize = 512;
/// SEC-044：描述符整体上限 8 KB。
pub const DESC_MAX_BYTES: usize = 8192;
/// SEC-044：能力点条目上限 256。
pub const DESC_MAX_CAPS: usize = 256;
/// 分片重组等待上限；超时丢弃未取全的视图，禁止进入 MATCH。
pub const DESC_FRAG_TIMEOUT_MS: u64 = 1500;

/// 公共描述视图的版本与完整性摘要：双方 MUST 由同一字节序列算出。
fn descriptor_digest(caps: &[Capability]) -> (u32, u32) {
    let mut buf = Vec::new();
    for cap in caps {
        buf.extend_from_slice(&cap.index.to_be_bytes());
        buf.push(cap.sub);
        let enc = cap.encode_public();
        buf.extend_from_slice(&(enc.len() as u32).to_be_bytes());
        buf.extend_from_slice(&enc);
    }
    (1, crc16(&buf) as u32)
}

#[derive(Debug, Clone)]
pub struct Lease {
    pub peer: Did,
    pub token: u32,
    pub expires_ms: u64,
    pub index: u16,
    pub sub: u8,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub peer: Did,
    pub role: Role,
    pub stage: Stage,
    pub txn: u16,
    pub target: Option<(u16, u8)>,
    pub requirement: Option<Requirement>,
    pub peer_caps: Vec<Capability>,
    pub contract: Option<Contract>,
    pub owner_token: u32,
    pub last_rx_ms: u64,
    pub last_hb_ms: u64,
    pub last_pub_ms: u64,
    pub last_pub_ts: u64,
    pub last_update_ms: u64,
    pub retries: u32,
    pub next_retry_ms: u64,
    pub subscribed: bool,
    pub stale: bool,
    pub error: Option<ErrCode>,
    pub nonce: [u8; 16],
    pub bind_phase: u8,
    /// 本次会话是否复用了公共描述缓存（FR-028）。
    pub resumed: bool,
}

impl Session {
    pub fn new(peer: Did, role: Role, now: u64) -> Self {
        Session {
            peer,
            role,
            stage: Stage::Idle,
            txn: 0,
            target: None,
            requirement: None,
            peer_caps: Vec::new(),
            contract: None,
            owner_token: 0,
            last_rx_ms: now,
            last_hb_ms: now,
            last_pub_ms: 0,
            last_pub_ts: 0,
            last_update_ms: 0,
            retries: 0,
            next_retry_ms: 0,
            subscribed: false,
            stale: false,
            error: None,
            nonce: [0; 16],
            bind_phase: 0,
            resumed: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DeviceCounters {
    pub tx: u64,
    pub rx: u64,
    pub binds_ok: u64,
    pub binds_fail: u64,
    pub retries: u64,
    pub stale_events: u64,
    pub session_timeouts: u64,
    pub writes_ok: u64,
    pub writes_rejected: u64,
    pub events_rx: u64,
    pub asleep_drops: u64,
    /// 发起的查询数
    pub queries_sent: u64,
    /// 收到的 REPLY 条数
    pub replies_rx: u64,
    /// 作为提供者应答的查询数
    pub queries_answered: u64,
    /// 查询超时次数
    pub query_timeouts: u64,
    /// 未实现帧类型/未支持标志被拒绝的次数
    pub proto_rejects: u64,
    /// 断链重连时复用绑定与描述缓存的次数（FR-028）。
    pub resumes_ok: u64,
    /// 行为规则命中次数
    pub logic_fired: u64,
    /// 可靠组播轮次（完成或超时）
    pub group_rounds: u64,
    /// 全部期望成员按时应答
    pub group_ok: u64,
    /// 有成员缺席
    pub group_missing: u64,
    /// 组声明/组播被拒（缺 group_epoch/成员判据、纪元不匹配）
    pub group_rejects: u64,
    /// CONFIG 成功应用
    pub config_ok: u64,
    /// CONFIG 因权限不足被拒（E_PERM）
    pub config_rejects: u64,
    /// 已发出的 RENEGOTIATE 通知（提供方侧）
    pub reneg_sent: u64,
    /// 已接受并生效的 RENEGOTIATE（消费方侧，SEC-025 HMAC 校验通过）
    pub reneg_ok: u64,
    /// 已下发的 CMD（消费方）
    pub cmds_sent: u64,
    /// 已受理的 CMD（提供方，已回 ACK）
    pub commands_rx: u64,
    /// 收到的命令受理 ACK（消费方，FR-039 第一段）
    pub cmd_acks: u64,
    /// 已发出的 DONE（提供方，FR-039 第三段）
    pub done_sent: u64,
    /// 收到的 DONE（消费方）
    pub done_rx: u64,
    /// DONE 报告执行失败的次数（FR-039：失败必须在 DONE 中给出原因）
    pub done_errors: u64,
    /// CMD 被拒次数（不可执行/无有效租约/缺意图）
    pub cmd_rejects: u64,
    /// 已发出的描述符分片（提供方）
    pub desc_frag_tx: u64,
    /// 已收到的描述符分片（消费方）
    pub desc_frag_rx: u64,
    /// 描述符分片重组并通过整体校验的次数
    pub desc_reassemble_ok: u64,
    /// 描述符整体校验失败/分片非法（SEC-026）
    pub desc_crc_errors: u64,
    /// 描述符超出 8KB/256 点上限被明确拒绝（SEC-044）
    pub desc_oversize: u64,
    /// 已发出的链路级 ACK（NFR-026）
    pub link_ack_tx: u64,
    /// 因链路重传导致的重复帧被去重丢弃的次数
    pub dup_drops: u64,
    /// 已发起的入网/配网请求（消费方）
    pub provision_sent: u64,
    /// 执行器动作次数（含中途改目标）
    pub actuator_moves: u64,
    /// 设备状态机迁移次数
    pub state_changes: u64,
    /// 报警产生 / 复位次数
    pub alarms_raised: u64,
    pub alarms_cleared: u64,
    /// 入网完成次数（提供方受理 / 消费方应用各计一次）
    pub provision_ok: u64,
    /// 入网被拒（会话未 active、HMAC 失败、组号非法）
    pub provision_rejects: u64,
}

/// 单条查询应答（发起方聚合用）。
#[derive(Debug, Clone)]
pub struct QueryReply {
    pub from: Did,
    pub index: u16,
    pub sub: u8,
    pub label: String,
    pub value: f64,
    pub quality: u8,
    pub at_ms: u64,
}

/// 一次查询会话：发出 QUERY 后聚合多提供者的 REPLY。
#[derive(Debug, Clone)]
pub struct QuerySession {
    pub id: u32,
    pub selector: String,
    pub mode: u8,
    pub started_ms: u64,
    pub deadline_ms: u64,
    /// 已知的期望回复总数（各提供者 REPLY_COUNT 之和）。
    pub expected: u32,
    /// 已贡献过应答的提供者集合，用于累加 expected。
    pub providers: BTreeSet<Did>,
    pub replies: Vec<QueryReply>,
    /// 已收到 REPLY_END 的提供者数。
    pub ended: u32,
    pub done: bool,
}

/// 一轮可靠组播：预期成员、已应答成员与截止时刻（FR-070）。
#[derive(Debug, Clone)]
pub struct GroupRound {
    pub gid: u16,
    pub txn: u16,
    pub expected: BTreeSet<Did>,
    pub responders: BTreeSet<Did>,
    pub deadline_ms: u64,
    pub epoch: u32,
}

/// 已受理但尚未完成的命令（FR-039：ACK 表示受理，DONE 表示执行完成）。
#[derive(Debug, Clone)]
pub struct PendingCmd {
    pub peer: Did,
    pub txn: u16,
    pub command_id: u32,
    pub index: u16,
    pub sub: u8,
    pub due_ms: u64,
    pub fail: bool,
    pub reason: String,
}

/// 执行器物理模型：写入不是瞬时到位，而是按行程时间或变化速率逼近目标。
#[derive(Debug, Clone)]
pub struct Actuator {
    /// 全行程时间（ms），rate=0 时使用。
    pub travel_ms: u32,
    /// 变化速率（单位/秒），>0 时优先于 travel_ms。
    pub rate: f64,
    /// 最小保持接通时间（ms），防止频繁启停；0 表示不限制。
    pub min_on_ms: u64,
    /// 最小保持断开时间（ms）。
    pub min_off_ms: u64,
    /// 上电初始位置；None 表示沿用点位初值。
    pub initial: Option<f64>,
}

impl Default for Actuator {
    fn default() -> Self {
        Actuator {
            travel_ms: 0,
            rate: 0.0,
            min_on_ms: 0,
            min_off_ms: 0,
            initial: None,
        }
    }
}

/// 设备运行状态机：启动自检 → 就绪 → 运行；链路/电源异常时降级或故障。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    Boot,
    Ready,
    Run,
    Degraded,
    Fault,
}

impl DeviceState {
    pub fn name(self) -> &'static str {
        match self {
            DeviceState::Boot => "boot",
            DeviceState::Ready => "ready",
            DeviceState::Run => "run",
            DeviceState::Degraded => "degraded",
            DeviceState::Fault => "fault",
        }
    }
}

/// 执行器的运行时进度。
#[derive(Debug, Clone)]
pub struct ActState {
    pub target: f64,
    pub from: f64,
    pub start_ms: u64,
    pub end_ms: u64,
    /// 最近一次通断切换完成的时刻（用于最小保持时间）。
    pub last_switch_ms: u64,
}

/// 采集通道故障注入：卡值、失效、漂移、跳变。
#[derive(Debug, Clone)]
pub struct SensorFault {
    /// 1=卡值 2=失效 3=漂移 4=跳变
    pub mode: u8,
    /// 漂移速率（单位/秒）或跳变偏移量。
    pub value: f64,
    pub at_ms: u64,
    pub last_ms: u64,
    /// 漂移累计量。
    pub acc: f64,
}

/// 点位报警定义：高高/高/低/低低 + 死区 + 判定延时。
#[derive(Debug, Clone)]
pub struct AlarmDef {
    pub index: u16,
    pub sub: u8,
    pub hh: f64,
    pub h: f64,
    pub l: f64,
    pub ll: f64,
    /// 死区：回到阈值以内该幅度才复位，避免抖动。
    pub deadband: f64,
    /// 条件持续多久才确认报警（ms）。
    pub delay_ms: u64,
}

impl Default for AlarmDef {
    fn default() -> Self {
        AlarmDef {
            index: 1,
            sub: 0,
            hh: f64::INFINITY,
            h: f64::INFINITY,
            l: f64::NEG_INFINITY,
            ll: f64::NEG_INFINITY,
            deadband: 0.0,
            delay_ms: 0,
        }
    }
}

/// 报警等级：0=正常 1=低低 2=低 3=高 4=高高。
#[derive(Debug, Clone, Default)]
pub struct AlarmState {
    pub level: u8,
    /// 候选等级与起始时刻（延时判定用）。
    pub pending: u8,
    pub pending_since: u64,
    pub since_ms: u64,
}

#[derive(Debug, Clone)]
pub struct DeviceSpec {
    pub name: String,
    pub did: Did,
    pub caps: Vec<Capability>,
    pub reqs: Vec<Requirement>,
    pub key: Vec<u8>,
    pub group: u16,
    pub start_ms: u64,
    /// 启动自检时长（ms）：在此期间设备不发现、不发布、不应答。
    pub boot_ms: u32,
    pub sims: BTreeMap<(u16, u8), PointSim>,
    pub link_min_ms: u32,
    pub preempt: bool,
    /// 允许作为网关转发其它设备的帧（多跳中继）。
    pub relay: bool,
    /// 协议档：0=STD（默认），1=RT（实时）。写入帧头 PROF 字段。
    pub prof: u8,
    /// 共享总线主站：轮询窗口内只有主站能主动发起，从站需被点名后应答。
    pub bus_master: bool,
    /// 应用层行为规则（计算 / 数据使用）。
    pub rules: Vec<LogicRule>,
    /// 执行器物理模型：按能力点索引。
    pub actuators: BTreeMap<(u16, u8), Actuator>,
    /// 点位报警定义。
    pub alarms: Vec<AlarmDef>,
}

impl DeviceSpec {
    pub fn new(name: &str, did: Did) -> Self {
        DeviceSpec {
            name: name.to_string(),
            did,
            caps: Vec::new(),
            reqs: Vec::new(),
            key: b"idcell-lab-key".to_vec(),
            group: 0,
            start_ms: 0,
            boot_ms: 0,
            sims: BTreeMap::new(),
            link_min_ms: 1,
            preempt: false,
            relay: false,
            prof: 0,
            bus_master: false,
            rules: Vec::new(),
            actuators: BTreeMap::new(),
            alarms: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Action {
    Send { to: Did, frame: Frame },
    Trace {
        kind: &'static str,
        peer: Did,
        detail: String,
    },
    /// 规则命中后向远端设备下发写入（由 World 解析目标名并复用 WRITE 流程）。
    LogicWrite {
        target: String,
        index: u16,
        sub: u8,
        value: f64,
        intent: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    Consumer,
    Provider,
    Both,
}

pub struct Device {
    pub id: usize,
    pub name: String,
    pub did: Did,
    pub group: u16,
    pub key: Vec<u8>,
    pub caps: Vec<Capability>,
    pub reqs: Vec<Requirement>,
    pub link_min_ms: u32,
    pub start_ms: u64,
    pub awake: bool,
    pub rx_on: bool,
    pub presence: u8,
    pub publishing: bool,
    /// 设备电源：断电后停止一切收发、发布与定时行为，重新上电后恢复。
    pub powered: bool,
    pub seq: u16,
    pub txn: u16,
    pub counters: DeviceCounters,
    pub points: BTreeMap<(u16, u8), PointState>,
    pub sims: BTreeMap<(u16, u8), PointSim>,
    pub sessions: BTreeMap<Did, Session>,
    pub recv: BTreeMap<(u16, u8), ReceivedValue>,
    pub owner: Option<Lease>,
    pub next_token: u32,
    pub discovery_started: bool,
    pub last_discover_ms: u64,
    pub pending_preempt: Option<Did>,
    pub discover_seen: BTreeMap<Did, (u16, u64)>,
    pub mode: RunMode,
    pub preempt: bool,
    /// 网关中继能力（World 路由用它决定是否允许作为中间跳）。
    pub relay: bool,
    /// 协议档：0=STD，1=RT；写到出站帧头的 PROF 字节。
    pub prof: u8,
    /// 共享总线主站标记（World 的轮询仲裁使用）。
    pub bus_master: bool,
    /// 运行状态机与自检时长。
    pub state: DeviceState,
    pub state_since: u64,
    pub boot_ms: u32,
    /// 执行器模型与当前运动状态。
    pub actuators: BTreeMap<(u16, u8), Actuator>,
    pub act_states: BTreeMap<(u16, u8), ActState>,
    /// 采集通道故障注入。
    pub sensor_faults: BTreeMap<(u16, u8), SensorFault>,
    /// 报警定义与当前等级。
    pub alarms: Vec<AlarmDef>,
    pub alarm_states: BTreeMap<(u16, u8), AlarmState>,
    /// 应用层行为规则与运行状态（规则触发节流 / 上次输出）。
    pub rules: Vec<LogicRule>,
    pub logic_state: Vec<LogicState>,
    /// 本端发起的查询会话（以 QUERY_ID 为键）。
    pub queries: BTreeMap<u32, QuerySession>,
    pub next_query_id: u32,
    /// 公共描述视图版本与摘要（FR-006），HELLO/AUTH/NEGOTIATE 中保持一致。
    pub desc_version: u32,
    pub desc_crc: u32,
    /// 稳定绑定缓存：同一 peer/能力点在描述未变时复用 binding_id（FR-028）。
    pub bindings: BTreeMap<(Did, u16, u8), BindingCache>,
    /// 消费者缓存的公共描述视图，重连时跳过重复拉取（FR-028）。
    pub desc_cache: BTreeMap<Did, DescCache>,
    /// 描述符分片重组缓冲（FR-008）。
    pub desc_frag: BTreeMap<Did, FragBuffer>,
    /// 授权纪元计数器：每次绑定都递增，旧纪元不得恢复。
    pub grant_epoch: u64,
    /// 当前可靠组播轮次（None 表示没有等待成员的组声明）。
    pub group_pending: Option<GroupRound>,
    /// 本机成员关系纪元；组声明中的 group_epoch 必须与之一致。
    pub group_epoch: u32,
    /// 已受理、等待执行完成的命令（提供方侧）。
    pub pending_cmds: Vec<PendingCmd>,
    /// 命令编号计数器（COMMAND_ID）。
    pub next_cmd_id: u32,
    /// 控制面重复帧去重表：`(对端, TXN, 类型, 分片号)` → 首次处理时刻。
    /// 分片号参与键：同一 TXN 的多片 HELLO 是不同帧，不能被去重。
    pub dup_seen: BTreeMap<(Did, u16, u8, u8), u64>,
    /// 上一次处理该请求时的应答帧；重复请求只重放应答，不重复改变状态。
    pub dup_reply: BTreeMap<(Did, u16, u8, u8), Vec<(Did, Frame)>>,
}

impl Device {
    pub fn new(id: usize, spec: DeviceSpec, mode: RunMode) -> Self {
        let (desc_version, desc_crc) = descriptor_digest(&spec.caps);
        let mut points = BTreeMap::new();
        for cap in &spec.caps {
            // 可写点也要有点位状态，否则 WRITE 无处落地；初值取模拟量在 t=0 的值。
            let initial = spec
                .sims
                .get(&(cap.index, cap.sub))
                .map(|s| s.base + s.amplitude * s.phase.sin())
                .unwrap_or(0.0);
            points.insert(
                (cap.index, cap.sub),
                PointState {
                    value: initial,
                    ts_ms: 0,
                    quality: quality::GOOD,
                },
            );
        }
        // 执行器声明的初始位置覆盖点位初值（如阀门上电停在全关/全开）。
        for (key, act) in &spec.actuators {
            if let Some(v) = act.initial {
                if let Some(p) = points.get_mut(key) {
                    p.value = v;
                }
            }
        }
        Device {
            id,
            name: spec.name,
            did: spec.did,
            group: spec.group,
            key: spec.key,
            caps: spec.caps,
            reqs: spec.reqs,
            link_min_ms: spec.link_min_ms,
            start_ms: spec.start_ms,
            awake: true,
            rx_on: true,
            presence: 0,
            publishing: true,
            powered: true,
            seq: 0,
            txn: 0,
            counters: DeviceCounters::default(),
            points,
            sims: spec.sims,
            sessions: BTreeMap::new(),
            recv: BTreeMap::new(),
            owner: None,
            next_token: 0x4A11_0001,
            discovery_started: false,
            last_discover_ms: 0,
            pending_preempt: None,
            discover_seen: BTreeMap::new(),
            mode,
            preempt: spec.preempt,
            relay: spec.relay,
            prof: spec.prof,
            bus_master: spec.bus_master,
            state: DeviceState::Ready,
            state_since: 0,
            boot_ms: spec.boot_ms,
            actuators: spec.actuators,
            act_states: BTreeMap::new(),
            sensor_faults: BTreeMap::new(),
            alarms: spec.alarms,
            alarm_states: BTreeMap::new(),
            logic_state: vec![LogicState::default(); spec.rules.len()],
            rules: spec.rules,
            queries: BTreeMap::new(),
            next_query_id: 1,
            desc_version,
            desc_crc,
            bindings: BTreeMap::new(),
            desc_cache: BTreeMap::new(),
            desc_frag: BTreeMap::new(),
            grant_epoch: 1,
            group_pending: None,
            group_epoch: 1,
            pending_cmds: Vec::new(),
            next_cmd_id: 1,
            dup_seen: BTreeMap::new(),
            dup_reply: BTreeMap::new(),
        }
    }

    fn next_txn(&mut self) -> u16 {
        self.txn = self.txn.wrapping_add(1);
        if self.txn == 0 {
            self.txn = 1;
        }
        self.txn
    }

    fn frame(&mut self, now: u64, ft: u8, to: Did, txn: u16, payload: Vec<u8>) -> Action {
        self.frame_flags(now, ft, to, txn, payload, 0)
    }

    fn frame_flags(
        &mut self,
        now: u64,
        ft: u8,
        to: Did,
        txn: u16,
        payload: Vec<u8>,
        flags: u8,
    ) -> Action {
        self.seq = self.seq.wrapping_add(1);
        self.counters.tx += 1;
        let frame = Frame::new(ft)
            .seq(self.seq)
            .txn(txn)
            .route(self.did, to)
            .group(self.group)
            .at_us(now.saturating_mul(1000))
            .with_payload(payload);
        let mut frame = frame;
        frame.flags = flags;
        // 控制面帧一律要求链路确认，供 NFR-026 的有界重传使用；业务数据面不强制。
        if matches!(
            ft,
            ftype::HELLO | ftype::MATCH | ftype::NEGOTIATE | ftype::AUTH | ftype::BIND
        ) {
            frame.flags |= FLAG_NEEDACK;
        }
        frame.prof = self.prof;
        Action::Send { to, frame }
    }

    fn trace(&self, kind: &'static str, peer: Did, detail: impl Into<String>) -> Action {
        Action::Trace {
            kind,
            peer,
            detail: detail.into(),
        }
    }

    pub fn cap(&self, index: u16, sub: u8) -> Option<&Capability> {
        self.caps.iter().find(|c| c.index == index && c.sub == sub)
    }

    /// 提供方侧稳定绑定号：同一 peer/点在描述版本不变时保持不变；
    /// 描述发生实质变更（desc_version 变化）时自然派生新 binding_id（FR-028）。
    fn binding_for(&mut self, peer: Did, index: u16, sub: u8) -> u32 {
        let key = (peer, index, sub);
        if let Some(b) = self.bindings.get(&key) {
            if b.desc_version == self.desc_version && b.binding_id != 0 {
                return b.binding_id;
            }
        }
        let seed = (self.did.0[4] as u32) << 24
            | (self.did.0[5] as u32) << 16
            | (self.did.0[6] as u32) << 8
            | self.did.0[7] as u32;
        let mut x = seed
            ^ (peer.0[7] as u32).wrapping_mul(0x9E37_79B9)
            ^ (index as u32).wrapping_mul(0x85EB_CA6B)
            ^ ((sub as u32) << 16)
            ^ self.desc_version.wrapping_mul(0xC2B2_AE35);
        x ^= x >> 15;
        x = x.wrapping_mul(0x2545_F491);
        x ^= x >> 13;
        let id = x.max(1);
        let entry = self.bindings.entry(key).or_default();
        entry.binding_id = id;
        entry.desc_version = self.desc_version;
        entry.desc_crc = self.desc_crc;
        entry.index = index;
        entry.sub = sub;
        id
    }

    pub fn session(&self, peer: Did) -> Option<&Session> {
        self.sessions.get(&peer)
    }

    // ------------------------------------------------------------ 组播（FR-070）

    /// 发起组声明：`mode=REQUIRED` 时必须有 group_epoch 与期望成员，否则拒绝。
    pub fn request_group_declare(
        &mut self,
        now: u64,
        gid: u16,
        expected: Vec<Did>,
        timeout_ms: u32,
        mode: u8,
        epoch: u32,
    ) -> Vec<Action> {
        let mut out = Vec::new();
        if gid == 0 || self.group != gid {
            self.counters.group_rejects += 1;
            out.push(self.trace(
                "group_reject",
                Did::broadcast(),
                format!("组号 {gid} 无效或本机不在该组，拒绝组声明"),
            ));
            return out;
        }
        if mode == response_mode::REQUIRED && (epoch == 0 || expected.is_empty()) {
            self.counters.group_rejects += 1;
            out.push(self.trace(
                "group_reject",
                Did::broadcast(),
                "可靠组播缺少 group_epoch 或成员判据 → 拒绝".to_string(),
            ));
            return out;
        }
        let txn = self.next_txn();
        let mut w = TlvWriter::new();
        w.field_u8(tlv_type::MESSAGE, group_phase::DECLARE);
        let _ = w.raw_put(0, 0, tlv_type::GROUP_ID, &gid.to_be_bytes());
        w.field_u8(tlv_type::RESPONSE_MODE, mode);
        if epoch > 0 {
            w.field_u32(tlv_type::GROUP_EPOCH, epoch);
        }
        if mode == response_mode::REQUIRED {
            w.field_u32(tlv_type::RESPONSE_TIMEOUT, timeout_ms.max(1));
            w.field_u32(tlv_type::EXPECTED_MEMBERS, expected.len() as u32);
            self.group_pending = Some(GroupRound {
                gid,
                txn,
                expected: expected.into_iter().collect(),
                responders: BTreeSet::new(),
                deadline_ms: now + timeout_ms.max(1) as u64,
                epoch,
            });
        }
        out.push(self.frame(now, ftype::GROUP, Did::broadcast(), txn, w.finish()));
        out.push(self.trace(
            "group_declare",
            Did::broadcast(),
            if mode == response_mode::REQUIRED {
                format!("组 {} 可靠组播：等待成员应答，超时 {} ms", gid, timeout_ms.max(1))
            } else {
                format!("组 {} 普通组播：不要求响应", gid)
            },
        ));
        out
    }

    /// 发起 CONFIG：与数据写入受同一套权限判定（FR-065）。
    pub fn request_config(
        &mut self,
        now: u64,
        peer: Did,
        index: u16,
        sub: u8,
        new_perm: u8,
        intent: &str,
    ) -> Vec<Action> {
        let mut out = Vec::new();
        let token = self
            .sessions
            .get(&peer)
            .and_then(|s| s.contract.as_ref())
            .map(|c| c.owner_token)
            .unwrap_or(0);
        let txn = self.next_txn();
        let mut w = TlvWriter::new();
        w.put_u16(index, sub, tlv_type::INDEX, index);
        w.field_u8(tlv_type::PERM, new_perm.min(3));
        w.field_str(tlv_type::INTENT, intent);
        w.field_u32(tlv_type::OWNER, token);
        out.push(self.frame(now, ftype::CONFIG, peer, txn, w.finish()));
        out.push(self.trace(
            "config",
            peer,
            format!("申请配置 {index}/{sub} 权限等级 → P{}", new_perm.min(3)),
        ));
        out
    }

    /// 下发命令（FR-039 三段语义）：CMD 发出后先收 ACK（已受理），执行完成后由提供方回 DONE。
    /// `exec_ms` 仅表示仿真的执行耗时；`fail` 为真时提供方在 DONE 中报告失败原因。
    pub fn request_command(
        &mut self,
        now: u64,
        peer: Did,
        index: u16,
        sub: u8,
        exec_ms: u32,
        fail: bool,
        intent: &str,
    ) -> Vec<Action> {
        let mut out = Vec::new();
        let Some(sess) = self.sessions.get(&peer) else {
            out.push(self.trace("cmd_skip", peer, "会话不存在，无法下发命令"));
            return out;
        };
        if sess.stage != Stage::Active {
            out.push(self.trace("cmd_skip", peer, "会话未处于 active，无法下发命令"));
            return out;
        }
        let token = sess
            .contract
            .as_ref()
            .map(|c| c.owner_token)
            .unwrap_or(0);
        let cmd_id = self.next_cmd_id;
        self.next_cmd_id = self.next_cmd_id.wrapping_add(1).max(1);
        let txn = self.next_txn();
        let mut w = TlvWriter::new();
        w.put_u16(index, sub, tlv_type::INDEX, index);
        w.field_u32(tlv_type::COMMAND_ID, cmd_id);
        w.field_u32(tlv_type::OWNER, token);
        w.field_u32(tlv_type::EXEC_MS, exec_ms.max(1));
        if fail {
            w.field_u8(tlv_type::EXEC_FAIL, 1);
        }
        w.field_str(tlv_type::INTENT, intent);
        out.push(self.frame(now, ftype::CMD, peer, txn, w.finish()));
        self.counters.cmds_sent += 1;
        out.push(self.trace(
            "cmd_sent",
            peer,
            format!("命令 {cmd_id} 已下发（预计 {exec_ms} ms 完成）"),
        ));
        out
    }

    /// 入网/配网（PROVISION）：在已认证会话上申请加入指定组，受 HMAC 保护（SEC-025）。
    pub fn request_provision(
        &mut self,
        now: u64,
        peer: Did,
        gid: u16,
        intent: &str,
    ) -> Vec<Action> {
        let mut out = Vec::new();
        let Some(sess) = self.sessions.get(&peer) else {
            out.push(self.trace("provision_skip", peer, "会话不存在，无法入网"));
            return out;
        };
        if sess.stage != Stage::Active {
            out.push(self.trace("provision_skip", peer, "会话未处于 active，无法入网"));
            return out;
        }
        let session_id = sess.contract.as_ref().map(|c| c.session_id).unwrap_or(0);
        let txn = self.next_txn();
        let nonce = make_nonce(self.did, now, txn);
        let proof = auth_proof(&self.key, &nonce, session_id, self.did, peer);
        let mut w = TlvWriter::new();
        w.field_u16(tlv_type::GROUP_ID, gid);
        w.field_str(tlv_type::INTENT, intent);
        w.field_u64(tlv_type::SESSION_ID, session_id);
        let _ = w.raw_put(0, 0, tlv_type::NONCE, &nonce);
        let _ = w.raw_put(0, 0, tlv_type::AUTH_PROOF, &proof);
        out.push(self.frame_flags(
            now,
            ftype::PROVISION,
            peer,
            txn,
            w.finish(),
            idcell_core::consts::FLAG_AUTH,
        ));
        self.counters.provision_sent += 1;
        out.push(self.trace(
            "provision_sent",
            peer,
            format!("申请入网并加入组 {gid}（{intent}）"),
        ));
        out
    }

    /// 消费方接受提供方的重协商通知：校验 HMAC 后更新契约权限与授权纪元（SEC-025）。
    fn on_renegotiate(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        let Ok(tlvs) = decode_tlvs(&f.payload) else {
            return;
        };
        let index = get_u16(&tlvs, tlv_type::INDEX).unwrap_or(0);
        let sub = tlvs
            .iter()
            .find(|t| t.typ == tlv_type::INDEX)
            .map(|t| t.sub)
            .unwrap_or(0);
        let new_perm = get_u8(&tlvs, tlv_type::PERM).unwrap_or(0);
        let epoch = get_u64(&tlvs, tlv_type::GRANT_EPOCH).unwrap_or(0);
        let bind_id = get_u32(&tlvs, tlv_type::BIND_ID).unwrap_or(0);
        let session_id = get_u64(&tlvs, tlv_type::SESSION_ID).unwrap_or(0);
        let nonce = tlvs
            .iter()
            .find(|t| t.typ == tlv_type::NONCE)
            .map(|t| t.value.clone())
            .unwrap_or_default();
        let proof = tlvs
            .iter()
            .find(|t| t.typ == tlv_type::AUTH_PROOF)
            .map(|t| t.value.clone())
            .unwrap_or_default();
        let Some(sess) = self.sessions.get(&f.src).cloned() else {
            return;
        };
        let Some(contract) = sess.contract.clone() else {
            return;
        };
        let nonce_arr: Option<[u8; 16]> = nonce.as_slice().try_into().ok();
        let expected = nonce_arr.map(|n| auth_proof(&self.key, &n, session_id, f.src, self.did));
        if sess.stage != Stage::Active
            || contract.binding_id != bind_id
            || contract.session_id != session_id
            || expected.map(|e| e.to_vec()) != Some(proof)
        {
            out.push(self.trace(
                "renegotiate_reject",
                f.src,
                "重协商校验失败（会话/绑定/HMAC 不匹配）".to_string(),
            ));
            return;
        }
        if let Some(s) = self.sessions.get_mut(&f.src) {
            if let Some(c) = s.contract.as_mut() {
                c.perm = new_perm;
                c.grant_epoch = epoch;
            }
            s.last_rx_ms = now;
        }
        self.counters.reneg_ok += 1;
        out.push(self.trace(
            "renegotiate_ok",
            f.src,
            format!("已接受重协商：{index}/{sub} → P{new_perm}，授权纪元 g{epoch}"),
        ));
    }

    fn check_groups(&mut self, now: u64, out: &mut Vec<Action>) {
        let Some(r) = self.group_pending.clone() else {
            return;
        };
        if now < r.deadline_ms {
            return;
        }
        self.group_pending = None;
        self.counters.group_rounds += 1;
        let missing: Vec<Did> = r.expected.difference(&r.responders).copied().collect();
        if missing.is_empty() {
            self.counters.group_ok += 1;
            out.push(self.trace(
                "group_ok",
                Did::broadcast(),
                format!("组 {} 全部 {} 个成员已应答", r.gid, r.expected.len()),
            ));
        } else {
            self.counters.group_missing += 1;
            out.push(self.trace(
                "group_absent",
                Did::broadcast(),
                format!(
                    "组 {} 应答超时，缺席 {}/{}：{}",
                    r.gid,
                    missing.len(),
                    r.expected.len(),
                    missing.iter().map(|d| d.to_hex()).collect::<Vec<_>>().join(",")
                ),
            ));
        }
    }

    fn on_group(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        let Ok(tlvs) = decode_tlvs(&f.payload) else {
            return;
        };
        let gid = get_u32(&tlvs, tlv_type::GROUP_ID).unwrap_or(f.group as u32) as u16;
        if gid == 0 || self.group != gid {
            return;
        }
        match get_u8(&tlvs, tlv_type::MESSAGE).unwrap_or(0) {
            group_phase::DECLARE => {
                let mode = get_u8(&tlvs, tlv_type::RESPONSE_MODE).unwrap_or(0);
                let epoch = get_u32(&tlvs, tlv_type::GROUP_EPOCH);
                let expected = get_u32(&tlvs, tlv_type::EXPECTED_MEMBERS);
                if mode == response_mode::REQUIRED {
                    if epoch.is_none() || expected.unwrap_or(0) == 0 {
                        self.counters.group_rejects += 1;
                        self.send_error(
                            now,
                            f.src,
                            ErrCode::Conv,
                            "可靠组播声明缺少 group_epoch/成员判据",
                            out,
                        );
                        return;
                    }
                    if epoch != Some(self.group_epoch) {
                        self.counters.group_rejects += 1;
                        self.send_error(
                            now,
                            f.src,
                            ErrCode::State,
                            "group_epoch 与本地成员关系不一致",
                            out,
                        );
                        return;
                    }
                    let mut w = TlvWriter::new();
                    w.field_u8(tlv_type::MESSAGE, group_phase::REPORT);
                    let _ = w.raw_put(0, 0, tlv_type::GROUP_ID, &gid.to_be_bytes());
                    w.field_u32(tlv_type::GROUP_EPOCH, epoch.unwrap_or(0));
                    out.push(self.frame(now, ftype::GROUP, f.src, f.txn, w.finish()));
                    out.push(self.trace(
                        "group_checkin",
                        f.src,
                        format!("加入组 {gid} 的可靠组播应答"),
                    ));
                } else {
                    out.push(self.trace(
                        "group_rx",
                        f.src,
                        format!("收到组 {gid} 普通组播，不回复"),
                    ));
                }
            }
            group_phase::REPORT => {
                let epoch = get_u32(&tlvs, tlv_type::GROUP_EPOCH).unwrap_or(0);
                let mut complete = false;
                if let Some(r) = self.group_pending.as_mut() {
                    if r.gid == gid && r.epoch == epoch {
                        r.responders.insert(f.src);
                        complete = r.expected.iter().all(|d| r.responders.contains(d));
                    }
                }
                if complete {
                    if let Some(r) = self.group_pending.take() {
                        self.counters.group_rounds += 1;
                        self.counters.group_ok += 1;
                        out.push(self.trace(
                            "group_ok",
                            Did::broadcast(),
                            format!("组 {} 全部 {} 个成员已应答", r.gid, r.expected.len()),
                        ));
                    }
                }
            }
            _ => {}
        }
    }

    fn on_config(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        if !matches!(self.mode, RunMode::Provider | RunMode::Both) {
            return;
        }
        let Ok(tlvs) = decode_tlvs(&f.payload) else {
            return;
        };
        let index = get_u16(&tlvs, tlv_type::INDEX).unwrap_or(0);
        let sub = tlvs
            .iter()
            .find(|t| t.typ == tlv_type::INDEX)
            .map(|t| t.sub)
            .unwrap_or(0);
        let token = get_u32(&tlvs, tlv_type::OWNER).unwrap_or(0);
        let new_perm = get_u8(&tlvs, tlv_type::PERM).unwrap_or(0).min(3);
        let intent = get_str(&tlvs, tlv_type::INTENT).unwrap_or_default();
        let Some(cap) = self.cap(index, sub).cloned() else {
            self.send_error(now, f.src, ErrCode::NoDev, "CONFIG 目标不存在", out);
            return;
        };
        let (active, current_perm) = self
            .sessions
            .get(&f.src)
            .map(|s| {
                (
                    s.stage == Stage::Active,
                    s.requirement.as_ref().map(|r| r.perm).unwrap_or(0),
                )
            })
            .unwrap_or((false, 0));
        if !active {
            self.counters.config_rejects += 1;
            self.send_error(now, f.src, ErrCode::State, "CONFIG 需要 Active 会话", out);
            return;
        }
        let lease_ok = self
            .owner
            .as_ref()
            .map(|o| o.peer == f.src && o.token == token && o.expires_ms > now)
            .unwrap_or(false);
        if !lease_ok {
            self.counters.config_rejects += 1;
            self.send_error(now, f.src, ErrCode::Lease, "CONFIG 缺少有效 owner_token", out);
            return;
        }
        if intent.trim().is_empty() {
            self.counters.config_rejects += 1;
            self.send_error(now, f.src, ErrCode::Perm, "CONFIG 缺少意图结构", out);
            return;
        }
        // FR-065：配置项至少需要 P2；权限不足返回 E_PERM，错误体带被拒项、所需与当前权限。
        let required = cap.perm.max(CONFIG_MIN_PERM);
        if current_perm < required {
            self.counters.config_rejects += 1;
            let mut w = TlvWriter::new();
            w.field_u8(err_field::CODE, ErrCode::Perm as u8);
            w.put_u16(index, sub, err_field::INDEX, index);
            w.field_u8(err_field::REQUIRED, required);
            w.field_u8(err_field::CURRENT, current_perm);
            w.field_str(err_field::REASON, "配置项需要更高实权限");
            out.push(self.frame(now, ftype::ERROR, f.src, f.txn, w.finish()));
            out.push(self.trace(
                "config_reject",
                f.src,
                format!("CONFIG {index}/{sub} 被拒：需要 P{required}，当前 P{current_perm} → E_PERM"),
            ));
            return;
        }
        if let Some(c) = self
            .caps
            .iter_mut()
            .find(|c| c.index == index && c.sub == sub)
        {
            c.perm = new_perm;
        }
        self.counters.config_ok += 1;
        // CONFIG 生效后主动重协商：换发新 grant_epoch 并发出受 HMAC 保护的 RENEGOTIATE（SEC-025）。
        self.grant_epoch = self.grant_epoch.wrapping_add(1).max(1);
        let epoch = self.grant_epoch;
        let session_id = self
            .sessions
            .get(&f.src)
            .and_then(|s| s.contract.as_ref())
            .map(|c| c.session_id)
            .unwrap_or(0);
        let bind_id = self
            .bindings
            .get(&(f.src, index, sub))
            .map(|b| b.binding_id)
            .unwrap_or(0);
        if let Some(s) = self.sessions.get_mut(&f.src) {
            if let Some(c) = s.contract.as_mut() {
                c.perm = new_perm;
                c.grant_epoch = epoch;
            }
            s.last_rx_ms = now;
        }
        let txn = self.next_txn();
        let nonce = make_nonce(self.did, now, txn);
        let proof = auth_proof(&self.key, &nonce, session_id, self.did, f.src);
        let mut rw = TlvWriter::new();
        rw.put_u16(index, sub, tlv_type::INDEX, index);
        rw.field_u8(tlv_type::PERM, new_perm);
        rw.field_u64(tlv_type::GRANT_EPOCH, epoch);
        rw.field_u32(tlv_type::BIND_ID, bind_id);
        rw.field_u64(tlv_type::SESSION_ID, session_id);
        let _ = rw.raw_put(0, 0, tlv_type::NONCE, &nonce);
        let _ = rw.raw_put(0, 0, tlv_type::AUTH_PROOF, &proof);
        out.push(self.frame_flags(
            now,
            ftype::RENEGOTIATE,
            f.src,
            txn,
            rw.finish(),
            idcell_core::consts::FLAG_AUTH,
        ));
        self.counters.reneg_sent += 1;
        out.push(self.trace(
            "renegotiate",
            f.src,
            format!("配置生效，发起重协商：P{new_perm}，g{epoch}"),
        ));
        let mut w = TlvWriter::new();
        w.field_u8(tlv_type::RESULT, ErrCode::Ok as u8);
        w.put_u16(index, sub, tlv_type::INDEX, index);
        w.field_u8(tlv_type::PERM, new_perm);
        out.push(self.frame(now, ftype::ACK, f.src, f.txn, w.finish()));
        out.push(self.trace(
            "config_ok",
            f.src,
            format!("配置 {index}/{sub} 权限等级 → P{new_perm}，既有契约不随之改变"),
        ));
    }

    /// 提供方受理 CMD：立即回 ACK（已受理），执行完成后再发 DONE（FR-039）。
    fn on_cmd(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        if !matches!(self.mode, RunMode::Provider | RunMode::Both) {
            return;
        }
        let Ok(tlvs) = decode_tlvs(&f.payload) else {
            return;
        };
        let index = get_u16(&tlvs, tlv_type::INDEX).unwrap_or(0);
        let sub = tlvs
            .iter()
            .find(|t| t.typ == tlv_type::INDEX)
            .map(|t| t.sub)
            .unwrap_or(0);
        let token = get_u32(&tlvs, tlv_type::OWNER).unwrap_or(0);
        let cmd_id = get_u32(&tlvs, tlv_type::COMMAND_ID).unwrap_or(0);
        let exec_ms = get_u32(&tlvs, tlv_type::EXEC_MS).unwrap_or(200).max(1);
        let fail = get_u8(&tlvs, tlv_type::EXEC_FAIL).unwrap_or(0) != 0;
        let intent = get_str(&tlvs, tlv_type::INTENT).unwrap_or_default();
        let Some(cap) = self.cap(index, sub).cloned() else {
            self.counters.cmd_rejects += 1;
            self.send_error(now, f.src, ErrCode::NoDev, "CMD 目标不存在", out);
            return;
        };
        if !cap.writable() {
            self.counters.cmd_rejects += 1;
            self.send_error(now, f.src, ErrCode::Unsafe, "该能力点不可执行命令", out);
            return;
        }
        let lease_ok = self
            .owner
            .as_ref()
            .map(|o| o.peer == f.src && o.token == token && o.expires_ms > now)
            .unwrap_or(false);
        if !lease_ok {
            self.counters.cmd_rejects += 1;
            self.send_error(now, f.src, ErrCode::Lease, "CMD 缺少有效 owner_token", out);
            return;
        }
        if intent.trim().is_empty() {
            self.counters.cmd_rejects += 1;
            self.send_error(now, f.src, ErrCode::Perm, "CMD 缺少意图结构", out);
            return;
        }
        // 受理与执行分离：ACK 立即返回，不受执行耗时影响（NFR-006）。
        let mut w = TlvWriter::new();
        w.put_u8(index, sub, tlv_type::RESULT, ErrCode::Ok as u8);
        w.put_u16(index, sub, tlv_type::INDEX, index);
        w.field_u32(tlv_type::COMMAND_ID, cmd_id);
        out.push(self.frame(now, ftype::ACK, f.src, f.txn, w.finish()));
        self.counters.commands_rx += 1;
        self.pending_cmds.push(PendingCmd {
            peer: f.src,
            txn: f.txn,
            command_id: cmd_id,
            index,
            sub,
            due_ms: now + exec_ms as u64,
            fail,
            reason: intent,
        });
        out.push(self.trace(
            "cmd_accept",
            f.src,
            format!("命令 {cmd_id} 已受理，预计 {exec_ms} ms 后完成"),
        ));
    }

    /// 消费方收到 DONE：执行完成（或失败并带原因）。
    fn on_done(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        let Ok(tlvs) = decode_tlvs(&f.payload) else {
            return;
        };
        let cmd_id = get_u32(&tlvs, tlv_type::COMMAND_ID).unwrap_or(0);
        let code = result_code(&tlvs);
        let reason = get_str(&tlvs, err_field::REASON).unwrap_or_default();
        self.counters.done_rx += 1;
        if code != ErrCode::Ok {
            self.counters.done_errors += 1;
        }
        if let Some(s) = self.sessions.get_mut(&f.src) {
            s.last_rx_ms = now;
        }
        out.push(self.trace(
            "cmd_done",
            f.src,
            format!("命令 {cmd_id} 完成：{} {}", code.name(), reason),
        ));
    }

    /// 执行到期的命令并发出 DONE（FR-039：失败必须带原因，绝不以缺失 DONE 代替）。
    fn check_commands(&mut self, now: u64, out: &mut Vec<Action>) {
        if self.pending_cmds.is_empty() {
            return;
        }
        let mut remain = Vec::new();
        let mut ready = Vec::new();
        for c in std::mem::take(&mut self.pending_cmds) {
            if now >= c.due_ms {
                ready.push(c);
            } else {
                remain.push(c);
            }
        }
        self.pending_cmds = remain;
        for c in ready {
            let code = if c.fail { ErrCode::Unsafe } else { ErrCode::Ok };
            let mut w = TlvWriter::new();
            w.put_u8(c.index, c.sub, tlv_type::RESULT, code as u8);
            w.put_u16(c.index, c.sub, tlv_type::INDEX, c.index);
            w.field_u32(tlv_type::COMMAND_ID, c.command_id);
            if c.fail {
                w.field_u8(err_field::CODE, code as u8);
                w.field_str(err_field::REASON, &format!("执行失败：{}", c.reason));
            }
            out.push(self.frame(now, ftype::DONE, c.peer, c.txn, w.finish()));
            self.counters.done_sent += 1;
            out.push(self.trace(
                "cmd_result",
                c.peer,
                format!(
                    "命令 {} 执行{}",
                    c.command_id,
                    if c.fail { "失败（已回 DONE 带原因）" } else { "完成" }
                ),
            ));
        }
    }

    /// 提供方受理入网/配网：会话必须 active，组号合法，且 HMAC 证明匹配（SEC-025）。
    fn on_provision(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        if !matches!(self.mode, RunMode::Provider | RunMode::Both) {
            return;
        }
        let Ok(tlvs) = decode_tlvs(&f.payload) else {
            return;
        };
        let Some(sess) = self.sessions.get(&f.src).cloned() else {
            self.counters.provision_rejects += 1;
            out.push(self.trace("provision_reject", f.src, "无会话，拒绝入网".to_string()));
            return;
        };
        if sess.stage != Stage::Active {
            self.counters.provision_rejects += 1;
            self.send_error(now, f.src, ErrCode::State, "入网要求会话处于 active", out);
            return;
        }
        let session_id = sess.contract.as_ref().map(|c| c.session_id).unwrap_or(0);
        let nonce = tlvs
            .iter()
            .find(|t| t.typ == tlv_type::NONCE)
            .map(|t| t.value.clone())
            .unwrap_or_default();
        let got = tlvs
            .iter()
            .find(|t| t.typ == tlv_type::AUTH_PROOF)
            .map(|t| t.value.clone())
            .unwrap_or_default();
        let ok = nonce.len() == 16
            && got.len() == 16
            && auth_proof(
                &self.key,
                &nonce[..16].try_into().unwrap(),
                session_id,
                f.src,
                self.did,
            ) == got[..16];
        if !ok {
            self.counters.provision_rejects += 1;
            self.send_error(now, f.src, ErrCode::Perm, "入网 HMAC 校验失败", out);
            return;
        }
        let gid = get_u16(&tlvs, tlv_type::GROUP_ID).unwrap_or(0);
        if gid == 0 {
            self.counters.provision_rejects += 1;
            self.send_error(now, f.src, ErrCode::Perm, "入网组号非法", out);
            return;
        }
        self.counters.provision_ok += 1;
        let mut w = TlvWriter::new();
        w.field_u8(tlv_type::RESULT, ErrCode::Ok as u8);
        w.field_u16(tlv_type::GROUP_ID, gid);
        w.field_u32(tlv_type::GROUP_EPOCH, self.group_epoch);
        out.push(self.frame(now, ftype::ACK, f.src, f.txn, w.finish()));
        out.push(self.trace(
            "provision_accept",
            f.src,
            format!("允许入网并加入组 {gid}（epoch {}）", self.group_epoch),
        ));
    }

    pub fn active_sessions(&self) -> impl Iterator<Item = &Session> {
        self.sessions.values().filter(|s| s.stage == Stage::Active)
    }

    pub fn point_snapshot(&self) -> Vec<(u16, u8, String, f64, u8, u64)> {
        self.points
            .iter()
            .map(|((idx, sub), p)| {
                let label = self
                    .cap(*idx, *sub)
                    .map(|c| c.label.clone())
                    .unwrap_or_default();
                (*idx, *sub, label, p.value, p.quality, p.ts_ms)
            })
            .collect()
    }

    // ------------------------------------------------------------ 周期驱动

    pub fn tick(&mut self, now: u64) -> Vec<Action> {
        let mut out = Vec::new();
        if !self.powered {
            return out;
        }
        // 启动自检期间不发现、不发布、不应答（仍保留点位初值）。
        if now < self.start_ms.saturating_add(self.boot_ms as u64) {
            self.state = DeviceState::Boot;
            self.state_since = now;
            return out;
        }
        self.update_actuators(now);
        self.update_simulated_points(now);
        self.update_alarms(now);
        self.update_state(now);
        if self.awake && self.rx_on {
            self.maybe_discover(now, &mut out);
        }
        self.check_retries(now, &mut out);
        self.check_heartbeats(now, &mut out);
        self.check_leases(now, &mut out);
        self.check_consumer_stale(now, &mut out);
        self.check_queries(now, &mut out);
        self.check_desc_frag(now, &mut out);
        self.check_groups(now, &mut out);
        self.check_commands(now, &mut out);
        self.publish_due(now, &mut out);
        out
    }

    /// 事件驱动的下一次唤醒时刻（毫秒绝对时间）。
    ///
    /// 返回 `None` 表示设备当前没有任何内部定时任务（休眠、或无会话且无需发现），
    /// 世界不会为它排事件队列，从而避免固定 tick 的空转扫描。
    pub fn next_deadline(&self, now: u64) -> Option<u64> {
        let mut best: Option<u64> = None;
        let mut push = |t: u64| {
            // 已经过期的定时器立刻生效，但至少推进 1ms，避免同刻自激
            let t = t.max(now + 1);
            if best.map_or(true, |b| t < b) {
                best = Some(t);
            }
        };

        if !self.powered || !self.awake {
            // 断电/休眠由外部事件驱动
            return None;
        }
        let boot_at = self.start_ms.saturating_add(self.boot_ms as u64);
        if now < boot_at {
            push(boot_at);
        }

        // 发现：没有存活消费者会话时按 1s 重发
        let consumer_mode = matches!(self.mode, RunMode::Consumer | RunMode::Both);
        if consumer_mode && !self.reqs.is_empty() && self.rx_on {
            let has_consumer = self.sessions.values().any(|s| {
                s.role == Role::Consumer && s.stage != Stage::Failed && s.stage != Stage::Closed
            });
            if !has_consumer {
                if self.discovery_started {
                    push(self.last_discover_ms + 1000);
                } else {
                    push(now);
                }
            }
        }

        for s in self.sessions.values() {
            match s.stage {
                Stage::Matched
                | Stage::Negotiating
                | Stage::Authenticating
                | Stage::Binding
                | Stage::BindingPrepared => {
                    if s.next_retry_ms != 0 {
                        push(s.next_retry_ms);
                    }
                }
                Stage::Active => {
                    push(s.last_rx_ms + LINK_TIMEOUT_MS + 1);
                    push(s.last_hb_ms + HEARTBEAT_MS);
                    if s.role == Role::Provider && s.subscribed && self.publishing {
                        if let Some(c) = s.contract.as_ref() {
                            push(s.last_pub_ms + c.t_pub_ms.max(1) as u64);
                        }
                    }
                    if s.role == Role::Consumer && !s.stale {
                        let stale_after = s
                            .contract
                            .as_ref()
                            .map(|c| c.stale_ms)
                            .filter(|v| *v > 0)
                            .unwrap_or(500) as u64;
                        if s.last_update_ms != 0 {
                            push(s.last_update_ms + stale_after + 1);
                        }
                    }
                }
                _ => {}
            }
        }
        if let Some(o) = self.owner.as_ref() {
            push(o.expires_ms);
        }
        for a in self.act_states.values() {
            push(a.end_ms);
            if a.start_ms > now {
                push(a.start_ms);
            }
        }
        for q in self.queries.values() {
            if !q.done {
                push(q.deadline_ms);
            }
        }
        if let Some(g) = self.group_pending.as_ref() {
            push(g.deadline_ms);
        }
        if let Some(t) = self.pending_cmds.iter().map(|c| c.due_ms).min() {
            push(t);
        }
        if let Some(t) = self.desc_frag.values().map(|b| b.deadline_ms).min() {
            push(t);
        }
        best
    }

    /// 推进执行器：按行程时间/速率从起点逼近目标，未到位前持续更新实际值。
    fn update_actuators(&mut self, now: u64) {
        let keys: Vec<(u16, u8)> = self.act_states.keys().copied().collect();
        for key in keys {
            let Some(st) = self.act_states.get(&key).cloned() else {
                continue;
            };
            if now < st.start_ms {
                continue;
            }
            let span = st.end_ms.saturating_sub(st.start_ms).max(1);
            let p = ((now - st.start_ms) as f64 / span as f64).clamp(0.0, 1.0);
            let v = st.from + (st.target - st.from) * p;
            if let Some(pt) = self.points.get_mut(&key) {
                if (pt.value - v).abs() > f64::EPSILON {
                    pt.value = v;
                    pt.ts_ms = now;
                }
            }
            if p >= 1.0 {
                self.act_states.remove(&key);
            }
        }
    }

    /// 运行状态机：电源/自检/链路状态决定 Boot/Ready/Run/Degraded/Fault。
    fn update_state(&mut self, now: u64) {
        let active = self
            .sessions
            .values()
            .any(|s| s.stage == Stage::Active && s.error.is_none());
        let degraded = self
            .sessions
            .values()
            .any(|s| s.error.is_some() || s.stage == Stage::Stale);
        let next = if !self.powered {
            DeviceState::Fault
        } else if now < self.start_ms.saturating_add(self.boot_ms as u64) {
            DeviceState::Boot
        } else if !self.awake || !self.rx_on || degraded {
            DeviceState::Degraded
        } else if active {
            DeviceState::Run
        } else {
            DeviceState::Ready
        };
        if next != self.state {
            self.state = next;
            self.state_since = now;
            self.counters.state_changes += 1;
        }
    }

    /// 外部事件（断电/休眠/接收关闭）后刷新状态机，保证面板立即反映。
    pub fn refresh_state(&mut self, now: u64) {
        self.update_state(now);
    }

    /// 注入采集通道故障：1=卡值 2=失效 3=漂移(单位/秒) 4=跳变(偏移量)。
    pub fn set_sensor_fault(&mut self, now: u64, index: u16, sub: u8, mode: u8, value: f64) {
        self.sensor_faults.insert(
            (index, sub),
            SensorFault {
                mode,
                value,
                at_ms: now,
                last_ms: now,
                acc: 0.0,
            },
        );
        if let Some(p) = self.points.get_mut(&(index, sub)) {
            if mode == 1 || mode == 2 || mode == 3 {
                p.quality = if mode == 2 {
                    quality::BAD
                } else {
                    quality::UNCERTAIN
                };
            }
            p.ts_ms = now;
        }
    }

    /// 清除采集通道故障，恢复质量位并重新叠加正常波形。
    pub fn clear_sensor_fault(&mut self, now: u64, index: u16, sub: u8) {
        if self.sensor_faults.remove(&(index, sub)).is_some() {
            if let Some(p) = self.points.get_mut(&(index, sub)) {
                p.quality = quality::GOOD;
                p.ts_ms = now;
            }
        }
    }

    /// 点位当前报警等级：0=正常 1=低低 2=低 3=高 4=高高。
    pub fn alarm_level(&self, index: u16, sub: u8) -> u8 {
        self.alarm_states
            .get(&(index, sub))
            .map(|s| s.level)
            .unwrap_or(0)
    }

    /// 报警判定：阈值 + 死区 + 持续时间确认。
    fn update_alarms(&mut self, now: u64) {
        let defs = self.alarms.clone();
        for a in defs {
            let key = (a.index, a.sub);
            let Some(v) = self.points.get(&key).map(|p| p.value) else {
                continue;
            };
            let st = self.alarm_states.entry(key).or_default();
            let cur = st.level;
            let target = if cur == 4 {
                if v >= a.hh - a.deadband {
                    4
                } else if v >= a.h {
                    3
                } else if v <= a.ll {
                    1
                } else if v <= a.l {
                    2
                } else {
                    0
                }
            } else if cur == 3 {
                if v >= a.hh {
                    4
                } else if v >= a.h - a.deadband {
                    3
                } else if v <= a.ll {
                    1
                } else if v <= a.l {
                    2
                } else {
                    0
                }
            } else if cur == 2 {
                if v >= a.hh {
                    4
                } else if v >= a.h {
                    3
                } else if v <= a.ll {
                    1
                } else if v <= a.l + a.deadband {
                    2
                } else {
                    0
                }
            } else if cur == 1 {
                if v >= a.hh {
                    4
                } else if v >= a.h {
                    3
                } else if v <= a.ll + a.deadband {
                    1
                } else if v <= a.l {
                    2
                } else {
                    0
                }
            } else if v >= a.hh {
                4
            } else if v >= a.h {
                3
            } else if v <= a.ll {
                1
            } else if v <= a.l {
                2
            } else {
                0
            };
            if target == cur {
                st.pending = cur;
                st.pending_since = now;
                continue;
            }
            if st.pending != target {
                st.pending = target;
                st.pending_since = now;
            }
            if now.saturating_sub(st.pending_since) >= a.delay_ms {
                st.level = target;
                st.since_ms = now;
                if target == 0 {
                    self.counters.alarms_cleared += 1;
                } else {
                    self.counters.alarms_raised += 1;
                }
            }
        }
    }

    fn update_simulated_points(&mut self, now: u64) {
        // 可写点代表执行器保持值：不叠加波形，但持续刷新时标，避免被误判为过期。
        let writable: Vec<(u16, u8)> = self
            .caps
            .iter()
            .filter(|c| c.writable())
            .map(|c| (c.index, c.sub))
            .collect();
        for key in writable {
            if let Some(p) = self.points.get_mut(&key) {
                p.ts_ms = now;
            }
        }
        let keys: Vec<(u16, u8)> = self.sims.keys().copied().collect();
        for key in keys {
            // 可写点由外部 WRITE 控制；若继续叠加模拟波形，写进去的值会被下一次采样冲掉。
            if self
                .caps
                .iter()
                .any(|c| c.index == key.0 && c.sub == key.1 && c.writable())
            {
                continue;
            }
            let Some(sim) = self.sims.get(&key).cloned() else {
                continue;
            };
            let period = sim.period_ms.max(1) as f64;
            let w = std::f64::consts::TAU * (now as f64 / period) + sim.phase;
            let noise = sim.noise * hash_noise(sim.seed, now);
            let mut v = sim.base + sim.amplitude * w.sin() + noise;
            let mut q = quality::GOOD;
            // 采集通道故障：卡值/失效/漂移/跳变，让质量位与数值一起退化。
            if let Some(f) = self.sensor_faults.get(&key) {
                match f.mode {
                    1 => {
                        // 卡值：停止更新，保持故障发生瞬间的值。
                        q = quality::UNCERTAIN;
                        if let Some(p) = self.points.get_mut(&key) {
                            p.quality = q;
                            p.ts_ms = now;
                        }
                        continue;
                    }
                    2 => {
                        // 失效：保留最后值，质量置 BAD。
                        q = quality::BAD;
                    }
                    3 => {
                        // 漂移：按速率累加偏差。
                        v += f.acc;
                        q = quality::UNCERTAIN;
                    }
                    4 => {
                        // 跳变：叠加固定偏移。
                        v += f.value;
                    }
                    _ => {}
                }
            }
            if let Some(f) = self.sensor_faults.get_mut(&key) {
                if f.mode == 3 {
                    let dt = now.saturating_sub(f.last_ms) as f64 / 1000.0;
                    f.acc += f.value * dt;
                    f.last_ms = now;
                }
            }
            if let Some(p) = self.points.get_mut(&key) {
                if (p.value - v).abs() > f64::EPSILON || p.quality != q {
                    p.value = v;
                    p.ts_ms = now;
                    p.quality = q;
                }
            }
        }
    }

    fn maybe_discover(&mut self, now: u64, out: &mut Vec<Action>) {
        if !matches!(self.mode, RunMode::Consumer | RunMode::Both) || self.reqs.is_empty() {
            return;
        }
        if now < self.start_ms {
            return;
        }
        let has_consumer = self
            .sessions
            .values()
            .any(|s| s.role == Role::Consumer && s.stage != Stage::Failed && s.stage != Stage::Closed);
        if has_consumer {
            return;
        }
        if self.discovery_started && now < self.last_discover_ms + 1000 {
            return;
        }
        self.discovery_started = true;
        self.last_discover_ms = now;
        let txn = self.next_txn();
        let mut w = TlvWriter::new();
        w.field_u8(tlv_type::MESSAGE, DISCOVER_PROBE);
        w.field_u8(tlv_type::ROLE, ROLE_REQUIREMENT);
        w.field_u32(tlv_type::QUERY_ID, txn as u32);
        w.field_u32(tlv_type::HOP_LIMIT, 4);
        // 断链重连：向曾经绑定的提供者定向探询，并携带旧 binding_id/desc_version，
        // 让双方复用公共描述缓存、跳过重复拉取（FR-028）。旧 session_id 只作校验。
        let resume = self.sessions.iter().find_map(|(peer, s)| {
            if s.role != Role::Consumer
                || !matches!(s.stage, Stage::Closed | Stage::Failed)
            {
                return None;
            }
            let c = s.contract.as_ref()?;
            if c.binding_id == 0 || c.session_id == 0 {
                return None;
            }
            let cache = self.desc_cache.get(peer)?;
            if self.cap(c.index, c.sub).is_none()
                && !cache.caps.iter().any(|x| x.index == c.index && x.sub == c.sub)
            {
                return None;
            }
            Some((*peer, c.binding_id, c.session_id, cache.desc_version, cache.desc_crc))
        });
        if let Some((peer, binding_id, session_id, ver, crc)) = resume {
            w.field_u32(tlv_type::OLD_BINDING, binding_id);
            w.field_u64(tlv_type::OLD_SESSION, session_id);
            w.field_u32(tlv_type::DESC_VER, ver);
            w.field_u32(tlv_type::DESC_CRC, crc);
            out.push(self.frame(now, ftype::DISCOVER, peer, txn, w.finish()));
            out.push(self.trace(
                "discover_resume",
                peer,
                format!("携带旧绑定 0x{binding_id:08X}/desc v{ver} 定向重连，请求复用描述缓存"),
            ));
            return;
        }
        out.push(self.frame(now, ftype::DISCOVER, Did::broadcast(), txn, w.finish()));
        out.push(self.trace("discover", Did::broadcast(), "发送 DISCOVER（广播）"));
    }

    fn check_retries(&mut self, now: u64, out: &mut Vec<Action>) {
        let peers: Vec<Did> = self.sessions.keys().copied().collect();
        for peer in peers {
            let Some(s) = self.sessions.get(&peer).cloned() else {
                continue;
            };
            if s.stage != Stage::Matched
                && s.stage != Stage::Negotiating
                && s.stage != Stage::Authenticating
                && s.stage != Stage::Binding
                && s.stage != Stage::BindingPrepared
            {
                continue;
            }
            if s.next_retry_ms == 0 || now < s.next_retry_ms {
                continue;
            }
            if s.retries >= 3 {
                if let Some(sess) = self.sessions.get_mut(&peer) {
                    sess.stage = Stage::Failed;
                    sess.error = Some(ErrCode::Unavailable);
                }
                self.counters.binds_fail += 1;
                self.counters.retries += 1;
                out.push(self.trace(
                    "timeout",
                    peer,
                    format!("阶段 {} 超时，重试耗尽 → E_UNAVAILABLE", s.stage.name()),
                ));
                continue;
            }
            self.counters.retries += 1;
            if let Some(sess) = self.sessions.get_mut(&peer) {
                sess.retries += 1;
                sess.next_retry_ms = now + 600;
            }
            out.push(self.trace(
                "retry",
                peer,
                format!("阶段 {} 超时，第 {} 次重试", s.stage.name(), s.retries + 1),
            ));
            // 简化重试：重新从 MATCH 开始，避免在中间态复制半成品契约。
            if s.role == Role::Consumer {
                if let (Some(req), Some(target)) = (s.requirement.clone(), s.target) {
                    out.push(self.match_request(now, peer, target.0, target.1, &req));
                }
            }
        }
    }

    fn check_heartbeats(&mut self, now: u64, out: &mut Vec<Action>) {
        let peers: Vec<Did> = self.sessions.keys().copied().collect();
        for peer in peers {
            let Some(s) = self.sessions.get(&peer).cloned() else {
                continue;
            };
            if s.stage == Stage::Active {
                if now.saturating_sub(s.last_rx_ms) > LINK_TIMEOUT_MS {
                    self.counters.session_timeouts += 1;
                    self.mark_session_lost(peer, now, &s);
                    out.push(self.trace(
                        "offline",
                        peer,
                        format!("{} ms 未收到对端帧，绑定失效", now.saturating_sub(s.last_rx_ms)),
                    ));
                    continue;
                }
                if now.saturating_sub(s.last_hb_ms) >= HEARTBEAT_MS {
                    let txn = self.next_txn();
                    let mut w = TlvWriter::new();
                    w.field_u32(tlv_type::TTL, s.contract.as_ref().map(|c| c.ttl_ms).unwrap_or(DEFAULT_TTL_MS));
                    w.field_u32(tlv_type::OWNER, s.owner_token);
                    w.field_u64(tlv_type::SESSION_ID, s.contract.as_ref().map(|c| c.session_id).unwrap_or(0));
                    w.field_u8(tlv_type::CHECKIN, 1);
                    out.push(self.frame(now, ftype::HEARTBEAT, peer, txn, w.finish()));
                    if let Some(sess) = self.sessions.get_mut(&peer) {
                        sess.last_hb_ms = now;
                    }
                }
            }
        }
    }

    fn mark_session_lost(&mut self, peer: Did, now: u64, s: &Session) {
        if s.role == Role::Consumer {
            for v in self.recv.values_mut() {
                v.stale = true;
                v.quality = quality::BAD;
            }
            self.discovery_started = false;
            self.last_discover_ms = now;
        } else if let Some(owner) = self.owner.clone() {
            if owner.peer == peer {
                self.owner = None;
            }
        }
        if let Some(sess) = self.sessions.get_mut(&peer) {
            sess.stage = Stage::Closed;
            sess.error = Some(ErrCode::Unavailable);
        }
    }

    fn check_leases(&mut self, now: u64, out: &mut Vec<Action>) {
        let Some(owner) = self.owner.clone() else {
            return;
        };
        if now < owner.expires_ms {
            return;
        }
        self.owner = None;
        if let Some(sess) = self.sessions.get_mut(&owner.peer) {
            if sess.role == Role::Provider {
                sess.owner_token = 0;
                if sess.stage == Stage::Active {
                    sess.stage = Stage::Closed;
                }
            }
        }
        let txn = self.next_txn();
        let mut w = TlvWriter::new();
        w.field_u32(tlv_type::OWNER, 0);
        w.field_u32(tlv_type::TTL, 0);
        w.put_u16(owner.index, owner.sub, tlv_type::INDEX, owner.index);
        out.push(self.frame(now, ftype::LEASE, owner.peer, txn, w.finish()));
        out.push(self.trace("lease_expired", owner.peer, "写租约 TTL 到期，所有权释放"));
    }

    fn check_consumer_stale(&mut self, now: u64, out: &mut Vec<Action>) {
        let peers: Vec<Did> = self.sessions.keys().copied().collect();
        for peer in peers {
            let Some(s) = self.sessions.get(&peer).cloned() else {
                continue;
            };
            if s.stage != Stage::Active || s.role != Role::Consumer || s.stale {
                continue;
            }
            let stale_after = s
                .contract
                .as_ref()
                .map(|c| c.stale_ms)
                .filter(|v| *v > 0)
                .unwrap_or(500);
            if s.last_update_ms != 0 && now.saturating_sub(s.last_update_ms) > stale_after as u64 {
                if let Some(sess) = self.sessions.get_mut(&peer) {
                    sess.stale = true;
                }
                for v in self.recv.values_mut() {
                    if now.saturating_sub(v.received_ms) > stale_after as u64 {
                        v.stale = true;
                        v.quality = quality::UNCERTAIN;
                    }
                }
                self.counters.stale_events += 1;
                out.push(self.trace(
                    "stale",
                    peer,
                    format!("{} ms 未更新，超过 T_stale={} ms", now.saturating_sub(s.last_update_ms), stale_after),
                ));
            }
        }
    }

    /// 查询超时兜底：没有 REPLY_END 时不无限等待。
    fn check_queries(&mut self, now: u64, out: &mut Vec<Action>) {
        let ids: Vec<u32> = self
            .queries
            .iter()
            .filter(|(_, q)| !q.done && now >= q.deadline_ms)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            if let Some(q) = self.queries.get_mut(&id) {
                q.done = true;
                let replies = q.replies.len();
                let selector = q.selector.clone();
                // all 模式按聚合窗口收尾：有应答就是正常结束，完全没有才算超时。
                if replies == 0 {
                    self.counters.query_timeouts += 1;
                    out.push(self.trace(
                        "query_timeout",
                        Did::broadcast(),
                        format!("查询 {id}（{selector}）超时，未收到任何应答"),
                    ));
                } else {
                    out.push(self.trace(
                        "query_done",
                        Did::broadcast(),
                        format!("查询 {id}（{selector}）聚合窗口结束，共 {replies} 条应答"),
                    ));
                }
            }
        }
    }

    fn publish_due(&mut self, now: u64, out: &mut Vec<Action>) {
        if !self.publishing || !self.awake || !self.powered {
            return;
        }
        let peers: Vec<Did> = self.sessions.keys().copied().collect();
        for peer in peers {
            let Some(s) = self.sessions.get(&peer).cloned() else {
                continue;
            };
            if s.role != Role::Provider || s.stage != Stage::Active || !s.subscribed {
                continue;
            }
            let Some(contract) = s.contract.clone() else {
                continue;
            };
            let Some(cap) = self.cap(contract.index, contract.sub).cloned() else {
                continue;
            };
            if !cap.readable() {
                continue;
            }
            let Some(point) = self.points.get(&(contract.index, contract.sub)).cloned() else {
                continue;
            };
            let t_pub = contract.t_pub_ms.max(1) as u64;
            if now < s.last_pub_ms + t_pub {
                continue;
            }
            // 值未更新就不发，绝不重复旧值伪装刷新。
            if s.last_pub_ts != 0 && point.ts_ms == s.last_pub_ts {
                continue;
            }
            let txn = self.next_txn();
            let mut w = TlvWriter::new();
            let raw = encode_value(contract.dtype, contract.scale_exp, point.value);
            let _ = w.raw_put(contract.index, contract.sub, tlv_type::VALUE, &raw);
            w.field_u8(tlv_type::QUALITY, point.quality);
            w.field_u8(tlv_type::PROV, cap.provenance);
            w.field_u64(tlv_type::SCHEMA_ID, contract.session_id);
            out.push(self.frame(now, ftype::EVENT, peer, txn, w.finish()));
            if let Some(sess) = self.sessions.get_mut(&peer) {
                sess.last_pub_ms = now;
                sess.last_pub_ts = point.ts_ms;
            }
        }
    }

    // ------------------------------------------------------------ 接收

    pub fn on_frame(&mut self, now: u64, f: Frame) -> Vec<Action> {
        let mut out = Vec::new();
        self.counters.rx += 1;
        if !self.powered {
            self.counters.asleep_drops += 1;
            out.push(self.trace(
                "power_off",
                f.src,
                format!("未上电，丢弃 {}", ftype::name(f.frame_type)),
            ));
            return out;
        }
        if !self.awake || !self.rx_on {
            self.counters.asleep_drops += 1;
            out.push(self.trace(
                "asleep",
                f.src,
                format!("休眠/接收关闭，丢弃 {}", ftype::name(f.frame_type)),
            ));
            return out;
        }
        let peer = f.src;
        if let Some(sess) = self.sessions.get_mut(&peer) {
            sess.last_rx_ms = now;
        }
        // 未协商的加密/压缩不能静默按明文处理，显式拒绝。
        let unsupported = f.flags & (FLAG_ENCRYPT | FLAG_COMPRESS);
        if unsupported != 0 {
            self.counters.proto_rejects += 1;
            self.send_error(
                now,
                peer,
                ErrCode::Unsafe,
                "未协商的加密/压缩标志",
                &mut out,
            );
            out.push(self.trace(
                "proto_reject",
                peer,
                format!("拒绝未支持标志 0x{:02X}", unsupported),
            ));
            return out;
        }
        // 链路级确认（NFR-026）：带 NEEDACK 的数据帧由接收方先回链路 ACK，与业务类型解耦。
        if f.flags & FLAG_NEEDACK != 0 && f.frame_type != ftype::ACK {
            let mut w = TlvWriter::new();
            w.field_u8(tlv_type::LINK_ACK, 1);
            out.push(self.frame(now, ftype::ACK, f.src, f.txn, w.finish()));
            self.counters.link_ack_tx += 1;
        }
        // 链路重传会带来重复帧：控制面同一 (对端, TXN, 类型) 只处理一次，
        // 重复请求仅重放上次应答，既不回退状态也不重复计数。
        let mut dup_key = None;
        if f.flags & FLAG_NEEDACK != 0 {
            let frag = decode_tlvs(&f.payload)
                .ok()
                .and_then(|t| get_u8(&t, tlv_type::DESC_FRAG_IDX))
                .unwrap_or(0);
            let key = (peer, f.txn, f.frame_type, frag);
            if let Some(t) = self.dup_seen.get(&key) {
                if now.saturating_sub(*t) <= 3000 {
                    self.counters.dup_drops += 1;
                    if let Some(replies) = self.dup_reply.get(&key).cloned() {
                        for (to, frame) in replies {
                            out.push(Action::Send { to, frame });
                        }
                    }
                    return out;
                }
            }
            self.dup_seen.insert(key, now);
            dup_key = Some(key);
            if self.dup_seen.len() > 512 {
                let cutoff = now.saturating_sub(5000);
                self.dup_seen.retain(|_, t| *t >= cutoff);
            }
        }
        let before = out.len();
        match f.frame_type {
            ftype::DISCOVER => self.on_discover(now, &f, &mut out),
            ftype::HELLO => self.on_hello(now, &f, &mut out),
            ftype::MATCH => self.on_match(now, &f, &mut out),
            ftype::NEGOTIATE => self.on_negotiate(now, &f, &mut out),
            ftype::AUTH => self.on_auth(now, &f, &mut out),
            ftype::BIND => self.on_bind(now, &f, &mut out),
            ftype::READ => self.on_read(now, &f, &mut out),
            ftype::WRITE => self.on_write(now, &f, &mut out),
            ftype::SUBSCRIBE => self.on_subscribe(now, &f, &mut out),
            ftype::UNSUB => {
                if let Some(sess) = self.sessions.get_mut(&peer) {
                    sess.subscribed = false;
                }
            }
            ftype::EVENT => self.on_event(now, &f, &mut out),
            ftype::GROUP => self.on_group(now, &f, &mut out),
            ftype::CONFIG => self.on_config(now, &f, &mut out),
            ftype::CMD => self.on_cmd(now, &f, &mut out),
            ftype::DONE => self.on_done(now, &f, &mut out),
            ftype::PROVISION => self.on_provision(now, &f, &mut out),
            ftype::RENEGOTIATE => {
                // 带 AUTH 标志的是 CONFIG 生效后由提供方发起的受保护重协商（SEC-025）；
                // 其余是消费方发起的 T_pub 重协商，沿用原协商处理路径。
                if f.flags & idcell_core::consts::FLAG_AUTH != 0 {
                    self.on_renegotiate(now, &f, &mut out)
                } else {
                    self.on_negotiate(now, &f, &mut out)
                }
            }
            ftype::QUERY => self.on_query(now, &f, &mut out),
            ftype::REPLY => self.on_reply(now, &f, &mut out),
            ftype::REPLY_END => self.on_reply_end(now, &f, &mut out),
            ftype::ACK => self.on_ack(now, &f, &mut out),
            ftype::HEARTBEAT => self.on_heartbeat(now, &f, &mut out),
            ftype::LEASE => self.on_lease(now, &f, &mut out),
            ftype::PREEMPT => self.on_preempt(now, &f, &mut out),
            ftype::STALE => self.on_stale(now, &f, &mut out),
            ftype::OFFLINE => self.on_offline(now, &f, &mut out),
            ftype::ERROR => self.on_error(now, &f, &mut out),
            _ => {
                // 已知但暂未实现或未知类型：返回结构化错误，避免被静默忽略。
                self.counters.proto_rejects += 1;
                self.send_error(
                    now,
                    peer,
                    ErrCode::Unavailable,
                    &format!(
                        "未实现的帧类型 {} (0x{:02X})",
                        ftype::name(f.frame_type),
                        f.frame_type
                    ),
                    &mut out,
                );
                out.push(self.trace(
                    "proto_reject",
                    peer,
                    format!("拒绝未实现帧类型 0x{:02X}", f.frame_type),
                ));
            }
        }
        // 缓存本请求的应答，供重复请求原样重放（幂等，不改变状态）。
        if let Some(key) = dup_key {
            let replies: Vec<(Did, Frame)> = out[before..]
                .iter()
                .filter_map(|a| match a {
                    Action::Send { to, frame } => Some((*to, frame.clone())),
                    _ => None,
                })
                .collect();
            self.dup_reply.insert(key, replies);
        }
        out
    }

    fn on_discover(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        if !matches!(self.mode, RunMode::Provider | RunMode::Both) || self.caps.is_empty() {
            return;
        }
        let tlvs = match decode_tlvs(&f.payload) {
            Ok(t) => t,
            Err(_) => {
                out.push(self.trace("tlv_error", f.src, "DISCOVER 载荷 TLV 截断"));
                return;
            }
        };
        let role = tlvs
            .iter()
            .find(|t| t.typ == tlv_type::ROLE)
            .and_then(|t| t.as_u8())
            .unwrap_or(ROLE_REQUIREMENT);
        if role != ROLE_REQUIREMENT {
            return;
        }
        // 重复发现请求：同一来源同一 txn 在 1s 内只回一次。
        if let Some((last_txn, last_ms)) = self.discover_seen.get(&f.src) {
            if *last_txn == f.txn && now.saturating_sub(*last_ms) < 1000 {
                return;
            }
        }
        self.discover_seen.insert(f.src, (f.txn, now));

        let txn = self.next_txn();
        // 重连复用：旧 binding_id + 旧 session_id + 相同 desc_version 才允许跳过描述拉取。
        let old_binding = get_u32(&tlvs, tlv_type::OLD_BINDING);
        let old_session = get_u64(&tlvs, tlv_type::OLD_SESSION);
        let want_ver = get_u32(&tlvs, tlv_type::DESC_VER);
        let resume = match (old_binding, old_session, want_ver) {
            (Some(bid), Some(sid), Some(ver)) => {
                ver == self.desc_version
                    && self.bindings.iter().any(|((peer, _, _), b)| {
                        *peer == f.src && b.binding_id == bid && b.session_id == sid
                    })
            }
            _ => false,
        };
        let mut w = TlvWriter::new();
        w.field_u8(tlv_type::ROLE, ROLE_CAPABILITY);
        w.field_u32(tlv_type::DESC_VER, self.desc_version);
        w.field_u32(tlv_type::DESC_CRC, self.desc_crc);
        w.field_str(tlv_type::SUMMARY, &self.name);
        if resume {
            // 公共视图未变：不重复发送 CAP_DESC，消费者直接复用缓存。
            w.field_u8(tlv_type::RESUMED, 1);
        } else {
            // FR-008：公共视图超过单帧容量时必须分片，并携带片号/总片数与整体校验；
            // SEC-044：超过 8 KB / 256 点上限时必须明确报错，不得截断后继续。
            let mut stream = TlvWriter::new();
            for cap in &self.caps {
                let _ = stream.raw_put(cap.index, cap.sub, tlv_type::CAP_DESC, &cap.encode_public());
            }
            let desc_bytes = stream.finish();
            if desc_bytes.len() > DESC_MAX_BYTES || self.caps.len() > DESC_MAX_CAPS {
                self.counters.desc_oversize += 1;
                out.push(self.trace(
                    "desc_oversize",
                    f.src,
                    format!(
                        "公共描述 {} B / {} 点，超过 8 KB / 256 点上限，拒绝提供不完整视图",
                        desc_bytes.len(),
                        self.caps.len()
                    ),
                ));
                self.send_error(
                    now,
                    f.src,
                    ErrCode::NoDev,
                    "描述符超过上限，拒绝提供不完整视图",
                    out,
                );
                return;
            }
            if desc_bytes.len() <= DESC_FRAG_BYTES {
                // 单帧可容纳：沿用逐能力点 TLV 视图。
                for cap in &self.caps {
                    let _ = w.raw_put(cap.index, cap.sub, tlv_type::CAP_DESC, &cap.encode_public());
                }
            } else {
                let chunks: Vec<&[u8]> = desc_bytes.chunks(DESC_FRAG_BYTES).collect();
                let total = chunks.len();
                for (i, chunk) in chunks.iter().enumerate() {
                    let mut fw = TlvWriter::new();
                    fw.field_u8(tlv_type::ROLE, ROLE_CAPABILITY);
                    fw.field_u32(tlv_type::DESC_VER, self.desc_version);
                    fw.field_u32(tlv_type::DESC_CRC, self.desc_crc);
                    fw.field_str(tlv_type::SUMMARY, &self.name);
                    fw.field_u8(tlv_type::DESC_FRAG_IDX, i as u8);
                    fw.field_u8(tlv_type::DESC_FRAG_TOTAL, total as u8);
                    let _ = fw.raw_put(0, 0, tlv_type::CAP_DESC, chunk);
                    out.push(self.frame(now, ftype::HELLO, f.src, txn, fw.finish()));
                }
                self.counters.desc_frag_tx += total as u64;
                out.push(self.trace(
                    "hello_frag",
                    f.src,
                    format!(
                        "公共描述 {} B 超过单帧容量，按 {} 片下发（整体 CRC 0x{:08X}）",
                        desc_bytes.len(),
                        total,
                        self.desc_crc
                    ),
                ));
                return;
            }
        }
        out.push(self.frame(now, ftype::HELLO, f.src, txn, w.finish()));
        out.push(self.trace(
            "hello",
            f.src,
            if resume {
                format!("响应重连探询，命中描述缓存 v{}（desc_crc=0x{:08X}）", self.desc_version, self.desc_crc)
            } else {
                format!("回应 DISCOVER，公布 {} 个能力点", self.caps.len())
            },
        ));
    }

    /// 收集描述符分片并按整体摘要校验（FR-008/SEC-026）。
    /// 返回 `None` 表示尚未取全或校验失败——两种情况下都禁止进入 MATCH。
    #[allow(clippy::too_many_arguments)]
    fn accept_desc_fragment(
        &mut self,
        tlvs: &[idcell_core::Tlv],
        peer: Did,
        total: usize,
        desc_ver: u32,
        desc_crc: u32,
        now: u64,
        out: &mut Vec<Action>,
    ) -> Option<Vec<Capability>> {
        let idx = get_u8(tlvs, tlv_type::DESC_FRAG_IDX).unwrap_or(0) as usize;
        let Some(chunk) = tlvs.iter().find(|t| t.typ == tlv_type::CAP_DESC) else {
            self.counters.desc_crc_errors += 1;
            out.push(self.trace("desc_frag_invalid", peer, "分片缺少 CAP_DESC 载荷".to_string()));
            return None;
        };
        // SEC-044：分片数与总字节都必须有上限，避免分片风暴或无限缓冲。
        if total == 0 || total > DESC_MAX_CAPS || idx >= total {
            self.counters.desc_crc_errors += 1;
            out.push(self.trace(
                "desc_frag_invalid",
                peer,
                format!("分片序号非法：{idx}/{total}"),
            ));
            return None;
        }
        if total.saturating_mul(DESC_FRAG_BYTES) > DESC_MAX_BYTES + DESC_FRAG_BYTES {
            self.counters.desc_oversize += 1;
            out.push(self.trace(
                "desc_oversize",
                peer,
                format!("分片总量超过 8 KB 上限（{total} 片），拒绝重组"),
            ));
            return None;
        }
        let need_new = match self.desc_frag.get(&peer) {
            Some(b) => b.desc_version != desc_ver || b.desc_crc != desc_crc || b.total != total,
            None => true,
        };
        if need_new {
            self.desc_frag.insert(
                peer,
                FragBuffer {
                    desc_version: desc_ver,
                    desc_crc,
                    total,
                    chunks: vec![None; total],
                    deadline_ms: now + DESC_FRAG_TIMEOUT_MS,
                },
            );
        }
        let (complete, got) = {
            let Some(buf) = self.desc_frag.get_mut(&peer) else {
                return None;
            };
            buf.deadline_ms = now + DESC_FRAG_TIMEOUT_MS;
            buf.chunks[idx] = Some(chunk.value.clone());
            let got = buf.chunks.iter().filter(|c| c.is_some()).count();
            (got == total, got)
        };
        self.counters.desc_frag_rx += 1;
        if !complete {
            out.push(self.trace(
                "desc_frag_wait",
                peer,
                format!("描述符分片 {got}/{total}，等待剩余分片"),
            ));
            return None;
        }
        let Some(buf) = self.desc_frag.remove(&peer) else {
            return None;
        };
        let mut stream = Vec::new();
        for c in &buf.chunks {
            if let Some(v) = c {
                stream.extend_from_slice(v);
            }
        }
        let Ok(items) = decode_tlvs(&stream) else {
            self.counters.desc_crc_errors += 1;
            out.push(self.trace("desc_crc_error", peer, "分片重组后 TLV 流不可解析".to_string()));
            return None;
        };
        let caps: Vec<Capability> = items
            .iter()
            .filter(|t| t.typ == tlv_type::CAP_DESC)
            .filter_map(|t| {
                Capability::decode(&t.value).ok().map(|mut c| {
                    c.index = t.idx;
                    c.sub = t.sub;
                    c
                })
            })
            .collect();
        let (ver, crc) = descriptor_digest(&caps);
        if ver != buf.desc_version || crc != buf.desc_crc {
            // SEC-026：整体校验失败必须丢弃全部分片，且不得缓存、不得 MATCH。
            self.counters.desc_crc_errors += 1;
            out.push(self.trace(
                "desc_crc_error",
                peer,
                format!(
                    "描述符整体校验失败：算出 0x{crc:08X}，声明 0x{:08X}，已丢弃 {} 片",
                    buf.desc_crc, buf.total
                ),
            ));
            return None;
        }
        self.counters.desc_reassemble_ok += 1;
        out.push(self.trace(
            "desc_reassembled",
            peer,
            format!("描述符 {} 片已重组，{} B / {} 点，整体 CRC 通过", buf.total, stream.len(), caps.len()),
        ));
        Some(caps)
    }

    /// 分片等待超时：丢弃未取全的视图并计数（禁止 MATCH）。
    fn check_desc_frag(&mut self, now: u64, out: &mut Vec<Action>) {
        if self.desc_frag.is_empty() {
            return;
        }
        let expired: Vec<Did> = self
            .desc_frag
            .iter()
            .filter(|(_, b)| now >= b.deadline_ms)
            .map(|(d, _)| *d)
            .collect();
        for d in expired {
            if let Some(b) = self.desc_frag.remove(&d) {
                let got = b.chunks.iter().filter(|c| c.is_some()).count();
                self.counters.desc_crc_errors += 1;
                out.push(self.trace(
                    "desc_frag_timeout",
                    d,
                    format!("描述符仅收到 {got}/{} 片，超时丢弃，禁止 MATCH", b.total),
                ));
            }
        }
    }

    fn on_hello(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        if !matches!(self.mode, RunMode::Consumer | RunMode::Both) || self.reqs.is_empty() {
            return;
        }
        let tlvs = match decode_tlvs(&f.payload) {
            Ok(t) => t,
            Err(_) => return,
        };
        let resumed = get_u8(&tlvs, tlv_type::RESUMED) == Some(1);
        let desc_ver = get_u32(&tlvs, tlv_type::DESC_VER);
        let desc_crc = get_u32(&tlvs, tlv_type::DESC_CRC);
        // FR-006：公共视图必须带版本与完整性摘要，否则不得进入 MATCH。
        let (Some(desc_ver), Some(desc_crc)) = (desc_ver, desc_crc) else {
            out.push(self.trace(
                "desc_incomplete",
                f.src,
                "HELLO 缺少 DESC_VER/DESC_CRC，禁止 MATCH".to_string(),
            ));
            return;
        };
        let caps: Vec<Capability> = if resumed {
            let Some(cache) = self.desc_cache.get(&f.src).cloned() else {
                out.push(self.trace("desc_cache_miss", f.src, "对方声称命中缓存但本端无缓存".to_string()));
                return;
            };
            if cache.desc_version != desc_ver || cache.desc_crc != desc_crc {
                out.push(self.trace(
                    "desc_mismatch",
                    f.src,
                    format!("描述缓存不一致：本地 v{} 0x{:08X}，对方 v{} 0x{:08X}", cache.desc_version, cache.desc_crc, desc_ver, desc_crc),
                ));
                return;
            }
            cache.caps
        } else {
            let caps: Vec<Capability> = if let Some(total) = get_u8(&tlvs, tlv_type::DESC_FRAG_TOTAL) {
                // FR-008：分片视图。未取全或整体校验失败时禁止进入 MATCH。
                match self.accept_desc_fragment(&tlvs, f.src, total as usize, desc_ver, desc_crc, now, out) {
                    Some(caps) => caps,
                    None => return,
                }
            } else {
                tlvs.iter()
                    .filter(|t| t.typ == tlv_type::CAP_DESC)
                    .filter_map(|t| {
                        Capability::decode(&t.value).ok().map(|mut c| {
                            // 点标识在 TLV 头里，不在描述符体内——必须回填，否则所有点都退化成默认索引。
                            c.index = t.idx;
                            c.sub = t.sub;
                            c
                        })
                    })
                    .collect()
            };
            if caps.is_empty() {
                return;
            }
            let (ver, crc) = descriptor_digest(&caps);
            if ver != desc_ver || crc != desc_crc {
                out.push(self.trace(
                    "desc_mismatch",
                    f.src,
                    format!("公共描述视图校验失败：算出 0x{crc:08X}，声明 0x{desc_crc:08X}"),
                ));
                return;
            }
            self.desc_cache.insert(
                f.src,
                DescCache {
                    desc_version: ver,
                    desc_crc: crc,
                    caps: caps.clone(),
                },
            );
            caps
        };
        let mut chosen: Option<(Requirement, Capability)> = None;
        for req in &self.reqs {
            for cap in &caps {
                if matches_public(req, cap).is_ok() {
                    chosen = Some((req.clone(), cap.clone()));
                    break;
                }
            }
            if chosen.is_some() {
                break;
            }
        }
        let Some((req, cap)) = chosen else {
            out.push(self.trace(
                "no_match",
                f.src,
                "HELLO 中没有满足需求的能力点（量种/单位/量程/类型）".to_string(),
            ));
            return;
        };
        if let Some(sess) = self.sessions.get(&f.src) {
            if sess.stage.is_pipeline_done() {
                return;
            }
        }
        let txn = self.next_txn();
        let mut sess = Session::new(f.src, Role::Consumer, now);
        sess.stage = Stage::HelloReceived;
        sess.resumed = resumed;
        sess.txn = txn;
        sess.target = Some((cap.index, cap.sub));
        sess.requirement = Some(req.clone());
        sess.peer_caps = caps;
        sess.next_retry_ms = now + 600;
        self.sessions.insert(f.src, sess);
        out.push(self.match_request(now, f.src, cap.index, cap.sub, &req));
        out.push(self.trace(
            "match",
            f.src,
            format!("选中能力点 {}/{}（{}）", cap.index, cap.sub, cap.label),
        ));
    }

    fn match_request(
        &mut self,
        now: u64,
        peer: Did,
        index: u16,
        sub: u8,
        req: &Requirement,
    ) -> Action {
        let txn = self.next_txn();
        if let Some(sess) = self.sessions.get_mut(&peer) {
            sess.stage = Stage::Matched;
            sess.txn = txn;
            sess.next_retry_ms = now + 600;
        }
        let mut w = TlvWriter::new();
        let _ = w.raw_put(index, sub, tlv_type::REQ_DESC, &req.encode());
        w.put_u16(index, sub, tlv_type::INDEX, index);
        self.frame(now, ftype::MATCH, peer, txn, w.finish())
    }

    fn on_match(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        let role = self.sessions.get(&f.src).map(|s| s.role);
        let tlvs = match decode_tlvs(&f.payload) {
            Ok(t) => t,
            Err(_) => return,
        };
        if role == Some(Role::Consumer) {
            let code = result_code(&tlvs);
            if code == ErrCode::Ok {
                let Some(sess) = self.sessions.get(&f.src).cloned() else {
                    return;
                };
                let (idx, sub) = sess.target.unwrap_or((0, 0));
                let req = sess.requirement.clone().unwrap_or_default();
                let txn = self.next_txn();
                if let Some(s) = self.sessions.get_mut(&f.src) {
                    s.stage = Stage::Negotiating;
                    s.txn = txn;
                    s.next_retry_ms = now + 600;
                }
                let mut w = TlvWriter::new();
                w.put_u16(idx, sub, tlv_type::INDEX, idx);
                w.field_u32(tlv_type::TPUB, req.want_ms);
                w.field_u32(tlv_type::STALE, req.stale_ms);
                w.field_u8(tlv_type::PERM, req.perm);
                w.field_str(tlv_type::UNIT, &req.unit);
                out.push(self.frame(now, ftype::NEGOTIATE, f.src, txn, w.finish()));
                out.push(self.trace("negotiate", f.src, "MATCH 通过，发起周期协商".to_string()));
            } else {
                self.fail_session(f.src, code, out);
            }
            return;
        }

        // Provider 侧：处理 MATCH 请求。
        let req_tlv = tlvs.iter().find(|t| t.typ == tlv_type::REQ_DESC);
        let Some(req_tlv) = req_tlv else {
            self.send_error(now, f.src, ErrCode::NoDev, "MATCH 缺少需求描述", out);
            return;
        };
        let (index, sub) = (req_tlv.idx, req_tlv.sub);
        let Ok(req) = Requirement::decode(&req_tlv.value) else {
            self.send_error(now, f.src, ErrCode::NoDev, "需求描述解码失败", out);
            return;
        };
        let code = match self.cap(index, sub) {
            Some(cap) => matches(&req, cap).err().unwrap_or(ErrCode::Ok),
            None => ErrCode::NoDev,
        };
        if code != ErrCode::Ok {
            self.counters.binds_fail += 1;
            self.send_match_result(now, f.src, f.txn, index, sub, code, out);
            out.push(self.trace("match_reject", f.src, format!("MATCH 拒绝：{}", code.name())));
            return;
        }
        let mut sess = self.sessions.get(&f.src).cloned().unwrap_or_else(|| {
            Session::new(f.src, Role::Provider, now)
        });
        sess.role = Role::Provider;
        sess.stage = Stage::Matched;
        sess.target = Some((index, sub));
        sess.requirement = Some(req);
        sess.txn = f.txn;
        self.sessions.insert(f.src, sess);
        self.send_match_result(now, f.src, f.txn, index, sub, ErrCode::Ok, out);
        out.push(self.trace(
            "matched",
            f.src,
            format!("接受 MATCH，能力点 {}/{}", index, sub),
        ));
    }

    fn send_match_result(
        &mut self,
        now: u64,
        peer: Did,
        txn: u16,
        index: u16,
        sub: u8,
        code: ErrCode,
        out: &mut Vec<Action>,
    ) {
        let mut w = TlvWriter::new();
        w.put_u8(index, sub, tlv_type::RESULT, code as u8);
        if code != ErrCode::Ok {
            w.field_u8(err_field::CODE, code as u8);
            w.field_str(err_field::REASON, code.name());
            w.field_u8(err_field::RETRY, u8::from(code.retryable()));
        }
        out.push(self.frame(now, ftype::MATCH, peer, txn, w.finish()));
    }

    fn on_negotiate(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        let role = self.sessions.get(&f.src).map(|s| s.role);
        let tlvs = match decode_tlvs(&f.payload) {
            Ok(t) => t,
            Err(_) => return,
        };
        if role == Some(Role::Consumer) {
            let code = result_code(&tlvs);
            if code != ErrCode::Ok {
                self.fail_session(f.src, code, out);
                return;
            }
            let Some(sess) = self.sessions.get(&f.src).cloned() else {
                return;
            };
            // Active 会话上的 NEGOTIATE 是“重新协商”：原地更新 T_pub/T_stale，
            // 不重建会话、不重新鉴权、不影响已有绑定与租约。
            if sess.stage == Stage::Active {
                let t_pub = get_u32(&tlvs, tlv_type::TPUB)
                    .or_else(|| sess.contract.as_ref().map(|c| c.t_pub_ms))
                    .unwrap_or(0);
                let stale = get_u32(&tlvs, tlv_type::STALE)
                    .or_else(|| sess.contract.as_ref().map(|c| c.stale_ms))
                    .unwrap_or(0);
                if let Some(s) = self.sessions.get_mut(&f.src) {
                    if let Some(c) = s.contract.as_mut() {
                        c.t_pub_ms = t_pub;
                        if stale > 0 {
                            c.stale_ms = stale;
                        }
                    }
                    s.stale = false;
                }
                out.push(self.trace(
                    "renegotiated",
                    f.src,
                    format!("重新协商生效：T_pub = {t_pub} ms"),
                ));
                return;
            }
            let mut contract = sess.contract.clone().unwrap_or_default();
            contract.t_pub_ms = get_u32(&tlvs, tlv_type::TPUB).unwrap_or(contract.t_pub_ms);
            contract.ttl_ms = get_u32(&tlvs, tlv_type::TTL).unwrap_or(DEFAULT_TTL_MS);
            contract.arb = get_u32(&tlvs, tlv_type::ARB).unwrap_or(DEFAULT_ARB);
            contract.binding_id = get_u32(&tlvs, tlv_type::BIND_ID).unwrap_or(0);
            contract.session_id = get_u64(&tlvs, tlv_type::SESSION_ID).unwrap_or(0);
            contract.grant_epoch = get_u64(&tlvs, tlv_type::GRANT_EPOCH).unwrap_or(0);
            contract.unit = get_str(&tlvs, tlv_type::UNIT).unwrap_or_default();
            contract.dtype = get_u8(&tlvs, tlv_type::DTYPE).unwrap_or(8);
            contract.scale_exp = get_u8(&tlvs, tlv_type::SCALE).unwrap_or(0);
            contract.stale_ms = sess
                .requirement
                .as_ref()
                .map(|r| r.stale_ms)
                .unwrap_or(500);
            contract.index = sess.target.map(|t| t.0).unwrap_or(0);
            contract.sub = sess.target.map(|t| t.1).unwrap_or(0);
            let txn = self.next_txn();
            let nonce = make_nonce(self.did, now, txn);
            let proof = auth_proof(&self.key, &nonce, contract.session_id, self.did, f.src);
            if let Some(s) = self.sessions.get_mut(&f.src) {
                s.stage = Stage::Authenticating;
                s.contract = Some(contract.clone());
                s.nonce = nonce;
                s.txn = txn;
                s.next_retry_ms = now + 600;
            }
            let mut w = TlvWriter::new();
            w.field_u64(tlv_type::SESSION_ID, contract.session_id);
            let _ = w.raw_put(0, 0, tlv_type::NONCE, &nonce);
            let _ = w.raw_put(0, 0, tlv_type::AUTH_PROOF, &proof);
            w.field_u32(tlv_type::BIND_ID, contract.binding_id);
            out.push(self.frame_flags(now, ftype::AUTH, f.src, txn, w.finish(), idcell_core::consts::FLAG_AUTH));
            out.push(self.trace(
                "auth",
                f.src,
                format!("协商完成 T_pub={} ms，发起鉴权", contract.t_pub_ms),
            ));
            return;
        }

        // Provider 侧：处理协商请求。
        let Some(sess) = self.sessions.get(&f.src).cloned() else {
            self.send_error(now, f.src, ErrCode::State, "未匹配即协商", out);
            return;
        };
        let (index, sub) = sess.target.unwrap_or((0, 0));
        let Some(cap) = self.cap(index, sub).cloned() else {
            self.send_error(now, f.src, ErrCode::NoDev, "能力点不存在", out);
            return;
        };
        let want = get_u32(&tlvs, tlv_type::TPUB).unwrap_or(50);
        let want_stale = get_u32(&tlvs, tlv_type::STALE).unwrap_or(1000);
        let t_pub = cap.t_prod_ms.max(want).max(self.link_min_ms).max(1);
        let stale_cap = cap.stale_ms.max(1);
        let stale = want_stale.min(stale_cap).max(1);
        // Active 会话上的 RENEGOTIATE：原地更新契约，保持绑定与租约不变
        if sess.stage == Stage::Active {
            if t_pub > stale {
                let reason = format!("重新协商被拒：T_pub {t_pub} ms > T_stale {stale} ms");
                let mut w = TlvWriter::new();
                w.put_u8(index, sub, tlv_type::RESULT, ErrCode::Negotiate as u8);
                w.field_u8(err_field::CODE, ErrCode::Negotiate as u8);
                w.field_str(err_field::REASON, &reason);
                w.field_u8(err_field::RETRY, 1);
                out.push(self.frame(now, ftype::NEGOTIATE, f.src, f.txn, w.finish()));
                out.push(self.trace("negotiate_reject", f.src, reason));
                return;
            }
            if let Some(s) = self.sessions.get_mut(&f.src) {
                if let Some(c) = s.contract.as_mut() {
                    c.t_pub_ms = t_pub;
                    c.stale_ms = stale;
                }
                let _ = &s.requirement;
                s.last_pub_ms = 0;
                s.last_pub_ts = 0;
            }
            let mut w = TlvWriter::new();
            w.put_u8(index, sub, tlv_type::RESULT, ErrCode::Ok as u8);
            w.field_u32(tlv_type::TPUB, t_pub);
            w.field_u32(tlv_type::STALE, stale);
            out.push(self.frame(now, ftype::NEGOTIATE, f.src, f.txn, w.finish()));
            out.push(self.trace(
                "renegotiated",
                f.src,
                format!("重新协商 T_pub = {t_pub} ms（原地生效）"),
            ));
            return;
        }
        if t_pub > stale {
            let reason = format!(
                "提供方最快 {} ms（T_stale={} ms），你要 {} ms → E_NEGOTIATE",
                t_pub, stale_cap, want
            );
            self.counters.binds_fail += 1;
            if let Some(s) = self.sessions.get_mut(&f.src) {
                s.stage = Stage::Failed;
                s.error = Some(ErrCode::Negotiate);
            }
            let mut w = TlvWriter::new();
            w.put_u8(index, sub, tlv_type::RESULT, ErrCode::Negotiate as u8);
            w.field_u8(err_field::CODE, ErrCode::Negotiate as u8);
            w.field_str(err_field::REASON, &reason);
            w.field_u8(err_field::RETRY, 1);
            w.field_u32(err_field::REQUIRED, want);
            w.field_u32(err_field::CURRENT, t_pub);
            out.push(self.frame(now, ftype::NEGOTIATE, f.src, f.txn, w.finish()));
            out.push(self.trace("negotiate_reject", f.src, reason));
            return;
        }
        // 同一 peer/点在同一描述版本内复用 binding_id；重连只换 session_id（FR-028）。
        let binding_id = self.binding_for(f.src, index, sub);
        let session_id = ((now as u64) << 20) ^ ((self.id as u64) << 8) ^ 0x51ED_0001;
        // 每次绑定换发新授权纪元：重连只复用描述缓存与绑定号，权限必须重新确认。
        self.grant_epoch = self.grant_epoch.wrapping_add(1).max(1);
        let grant_epoch = self.grant_epoch;
        let contract = Contract {
            binding_id,
            session_id,
            grant_epoch,
            owner_token: 0,
            ttl_ms: DEFAULT_TTL_MS,
            t_pub_ms: t_pub,
            arb: DEFAULT_ARB,
            index,
            sub,
            perm: cap.perm,
            unit: cap.unit.clone(),
            dtype: cap.dtype,
            scale_exp: cap.scale_exp,
            stale_ms: stale,
        };
        if let Some(s) = self.sessions.get_mut(&f.src) {
            s.stage = Stage::Negotiating;
            s.contract = Some(contract.clone());
            s.requirement = Some(Requirement {
                want_ms: want,
                stale_ms: want_stale,
                ..s.requirement.clone().unwrap_or_default()
            });
            s.txn = f.txn;
        }
        let mut w = TlvWriter::new();
        w.put_u8(index, sub, tlv_type::RESULT, ErrCode::Ok as u8);
        w.field_u32(tlv_type::TPUB, t_pub);
        w.field_u32(tlv_type::TTL, DEFAULT_TTL_MS);
        w.field_u32(tlv_type::ARB, DEFAULT_ARB);
        w.field_u32(tlv_type::BIND_ID, binding_id);
        w.field_u64(tlv_type::SESSION_ID, session_id);
        w.field_u64(tlv_type::GRANT_EPOCH, grant_epoch);
        w.field_u32(tlv_type::DESC_VER, self.desc_version);
        w.field_u32(tlv_type::DESC_CRC, self.desc_crc);
        w.field_u8(tlv_type::PERM, cap.perm);
        w.field_str(tlv_type::UNIT, &cap.unit);
        w.field_u8(tlv_type::DTYPE, cap.dtype);
        w.field_u8(tlv_type::SCALE, cap.scale_exp);
        out.push(self.frame(now, ftype::NEGOTIATE, f.src, f.txn, w.finish()));
        out.push(self.trace(
            "negotiated",
            f.src,
            format!("T_pub = max(T_prod {}, T_want {}, T_link_min {}) = {} ms", cap.t_prod_ms, want, self.link_min_ms, t_pub),
        ));
    }

    fn on_auth(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        let role = self.sessions.get(&f.src).map(|s| s.role);
        let tlvs = match decode_tlvs(&f.payload) {
            Ok(t) => t,
            Err(_) => return,
        };
        if role == Some(Role::Consumer) {
            let code = result_code(&tlvs);
            if code != ErrCode::Ok {
                self.fail_session(f.src, code, out);
                return;
            }
            // FR-006：授权视图必须与公共视图同 desc_version / 同完整性摘要。
            let ver = get_u32(&tlvs, tlv_type::DESC_VER);
            let crc = get_u32(&tlvs, tlv_type::DESC_CRC);
            if let Some(cache) = self.desc_cache.get(&f.src).cloned() {
                if ver != Some(cache.desc_version) || crc != Some(cache.desc_crc) {
                    self.counters.binds_fail += 1;
                    out.push(self.trace(
                        "auth_reject",
                        f.src,
                        "授权视图与公共描述视图版本/摘要不一致 → 拒绝进入 BIND".to_string(),
                    ));
                    self.fail_session(f.src, ErrCode::State, out);
                    return;
                }
            }
            let Some(sess) = self.sessions.get(&f.src).cloned() else {
                return;
            };
            let contract = sess.contract.clone().unwrap_or_default();
            let txn = self.next_txn();
            let mut w = TlvWriter::new();
            w.field_u8(tlv_type::BIND_PHASE, bind_phase::PREPARE);
            w.field_u32(tlv_type::BIND_ID, contract.binding_id);
            w.field_u64(tlv_type::SESSION_ID, contract.session_id);
            w.field_u32(tlv_type::TTL, contract.ttl_ms);
            w.field_u32(tlv_type::OWNER, 0);
            w.put_u16(contract.index, contract.sub, tlv_type::INDEX, contract.index);
            // 断链重连时声明旧绑定/旧会话，供提供方校验并复用绑定号；实际会话仍是新 session_id。
            if let Some(old) = self.bindings.get(&(f.src, contract.index, contract.sub)).cloned() {
                if old.binding_id != 0 && old.session_id != 0 && old.session_id != contract.session_id {
                    w.field_u32(tlv_type::OLD_BINDING, old.binding_id);
                    w.field_u64(tlv_type::OLD_SESSION, old.session_id);
                    w.field_u64(tlv_type::OLD_GRANT, old.grant_epoch);
                }
            }
            if let Some(s) = self.sessions.get_mut(&f.src) {
                s.stage = Stage::Binding;
                s.txn = txn;
                s.next_retry_ms = now + 600;
            }
            out.push(self.frame_flags(
                now,
                ftype::BIND,
                f.src,
                txn,
                w.finish(),
                if self.preempt {
                    idcell_core::consts::FLAG_PREEMPT
                } else {
                    0
                },
            ));
            out.push(self.trace("bind", f.src, "鉴权通过，BIND prepare".to_string()));
            return;
        }

        // Provider 校验 HMAC 证明。
        let nonce = tlvs
            .iter()
            .find(|t| t.typ == tlv_type::NONCE)
            .map(|t| t.value.clone())
            .unwrap_or_default();
        let got = tlvs
            .iter()
            .find(|t| t.typ == tlv_type::AUTH_PROOF)
            .map(|t| t.value.clone())
            .unwrap_or_default();
        let session_id = get_u64(&tlvs, tlv_type::SESSION_ID).unwrap_or(0);
        let ok = nonce.len() == 16
            && got.len() == 16
            && auth_proof(&self.key, &nonce[..16].try_into().unwrap(), session_id, f.src, self.did)
                == got[..16];
        let code = if ok { ErrCode::Ok } else { ErrCode::Perm };
        if !ok {
            self.counters.binds_fail += 1;
            if let Some(s) = self.sessions.get_mut(&f.src) {
                s.stage = Stage::Failed;
                s.error = Some(ErrCode::Perm);
            }
            out.push(self.trace("auth_reject", f.src, "HMAC 证明不匹配 → E_PERM".to_string()));
        } else if let Some(s) = self.sessions.get_mut(&f.src) {
            s.stage = Stage::Authed;
        }
        let mut w = TlvWriter::new();
        w.field_u8(tlv_type::RESULT, code as u8);
        w.field_u64(tlv_type::SESSION_ID, session_id);
        w.field_u32(tlv_type::DESC_VER, self.desc_version);
        w.field_u32(tlv_type::DESC_CRC, self.desc_crc);
        out.push(self.frame(now, ftype::AUTH, f.src, f.txn, w.finish()));
    }

    fn on_bind(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        let role = self.sessions.get(&f.src).map(|s| s.role);
        let tlvs = match decode_tlvs(&f.payload) {
            Ok(t) => t,
            Err(_) => return,
        };
        let phase = get_u8(&tlvs, tlv_type::BIND_PHASE).unwrap_or(0);
        if role != Some(Role::Provider) {
            // Consumer 侧：处理 PROVIDER 的 prepare/commit 应答。
            let code = result_code(&tlvs);
            if code != ErrCode::Ok {
                self.fail_session(f.src, code, out);
                return;
            }
            let token = get_u32(&tlvs, tlv_type::OWNER).unwrap_or(0);
            let Some(sess) = self.sessions.get(&f.src).cloned() else {
                return;
            };
            match phase {
                bind_phase::PREPARED => {
                    let mut contract = sess.contract.clone().unwrap_or_default();
                    if token != 0 {
                        contract.owner_token = token;
                    }
                    let resumed = get_u8(&tlvs, tlv_type::RESUMED) == Some(1);
                    if let Some(s) = self.sessions.get_mut(&f.src) {
                        s.contract = Some(contract.clone());
                        s.owner_token = contract.owner_token;
                        s.stage = Stage::BindingPrepared;
                        s.bind_phase = phase;
                        s.resumed = resumed;
                    }
                    if resumed {
                        out.push(self.trace(
                            "resume_ok",
                            f.src,
                            format!("提供方确认复用绑定 0x{:08X}，已换发新 owner_token=0x{:08X}", contract.binding_id, contract.owner_token),
                        ));
                    }
                    let txn = self.next_txn();
                    let mut w = TlvWriter::new();
                    w.field_u8(tlv_type::BIND_PHASE, bind_phase::COMMIT);
                    w.field_u32(tlv_type::BIND_ID, contract.binding_id);
                    w.field_u64(tlv_type::SESSION_ID, contract.session_id);
                    w.field_u32(tlv_type::OWNER, contract.owner_token);
                    w.put_u16(contract.index, contract.sub, tlv_type::INDEX, contract.index);
                    if let Some(s) = self.sessions.get_mut(&f.src) {
                        s.txn = txn;
                        s.next_retry_ms = now + 600;
                    }
                    out.push(self.frame(now, ftype::BIND, f.src, txn, w.finish()));
                    out.push(self.trace(
                        "bind",
                        f.src,
                        format!("PREPARED，owner_token=0x{:08X}，提交 COMMIT", contract.owner_token),
                    ));
                }
                bind_phase::COMMITTED => {
                    let (index, sub) = sess.target.unwrap_or((0, 0));
                    // 记录本次成功绑定的 binding_id/session_id，供下次断链重连校验与复用。
                    if let Some(contract) = sess.contract.clone() {
                        let (ver, crc) = self
                            .desc_cache
                            .get(&f.src)
                            .map(|d| (d.desc_version, d.desc_crc))
                            .unwrap_or((self.desc_version, 0));
                        self.bindings.insert(
                            (f.src, index, sub),
                            BindingCache {
                                binding_id: contract.binding_id,
                                desc_version: ver,
                                desc_crc: crc,
                                session_id: contract.session_id,
                                grant_epoch: contract.grant_epoch,
                                index,
                                sub,
                            },
                        );
                    }
                    if let Some(s) = self.sessions.get_mut(&f.src) {
                        s.stage = Stage::Active;
                        s.bind_phase = phase;
                        s.last_rx_ms = now;
                        s.last_hb_ms = now;
                        s.last_update_ms = now;
                        s.stale = false;
                        s.next_retry_ms = 0;
                    }
                    self.counters.binds_ok += 1;
                    self.discovery_started = false;
                    let txn = self.next_txn();
                    let mut w = TlvWriter::new();
                    w.put_u16(index, sub, tlv_type::INDEX, index);
                    w.field_u32(tlv_type::TPUB, sess.contract.as_ref().map(|c| c.t_pub_ms).unwrap_or(50));
                    if let Some(s) = self.sessions.get_mut(&f.src) {
                        s.txn = txn;
                    }
                    out.push(self.frame(now, ftype::SUBSCRIBE, f.src, txn, w.finish()));
                    out.push(self.trace(
                        "active",
                        f.src,
                        format!("绑定 ACTIVE，订阅能力点 {}/{}", index, sub),
                    ));
                }
                _ => {}
            }
            return;
        }

        // Provider 侧：处理 PREPARE / COMMIT / RELEASE。
        let index = get_u16(&tlvs, tlv_type::INDEX).unwrap_or(0);
        let sub = tlvs
            .iter()
            .find(|t| t.typ == tlv_type::INDEX)
            .map(|t| t.sub)
            .unwrap_or(0);
        let bind_id = self.binding_for(f.src, index, sub);
        let session_id = get_u64(&tlvs, tlv_type::SESSION_ID).unwrap_or(0);
        let old_binding = get_u32(&tlvs, tlv_type::OLD_BINDING).unwrap_or(0);
        let old_session = get_u64(&tlvs, tlv_type::OLD_SESSION).unwrap_or(0);
        let old_grant = get_u64(&tlvs, tlv_type::OLD_GRANT).unwrap_or(0);
        let requested_ttl = get_u32(&tlvs, tlv_type::TTL).unwrap_or(DEFAULT_TTL_MS);
        let owner_token = get_u32(&tlvs, tlv_type::OWNER).unwrap_or(0);
        // FR-028：旧 binding_id + 旧 session_id 都匹配、且描述版本未变，才认定“重连复用”。
        // 即使复用，下面也会换发新 owner_token，旧 token 绝不恢复。
        let resumed = old_session != 0
            && old_session != session_id
            && (old_grant == 0 || old_grant < self.grant_epoch)
            && self
                .bindings
                .get(&(f.src, index, sub))
                .map(|b| {
                    b.binding_id == old_binding
                        && b.session_id == old_session
                        && b.desc_version == self.desc_version
                })
                .unwrap_or(false);
        if resumed {
            self.counters.resumes_ok += 1;
        }
        match phase {
            bind_phase::PREPARE => {
                if let Some(existing) = self.owner.clone() {
                    if existing.peer != f.src && existing.expires_ms > now {
                        if f.flags & idcell_core::consts::FLAG_PREEMPT != 0 {
                            self.pending_preempt = Some(f.src);
                            let txn = self.next_txn();
                            let mut w = TlvWriter::new();
                            w.put_u16(existing.index, existing.sub, tlv_type::INDEX, existing.index);
                            w.field_str(tlv_type::STR, "新的更高优先 owner 请求接管");
                            out.push(self.frame(now, ftype::PREEMPT, existing.peer, txn, w.finish()));
                            out.push(self.trace(
                                "preempt",
                                existing.peer,
                                "收到抢占请求，通知旧 owner 释放".to_string(),
                            ));
                        } else {
                            self.counters.binds_fail += 1;
                            self.send_bind_result(
                                now, f.src, f.txn, bind_phase::ABORT, bind_id, session_id, 0,
                                ErrCode::Lease, false, out,
                            );
                            out.push(self.trace("bind_reject", f.src, "写租约被占用 → E_LEASE".to_string()));
                        }
                        return;
                    }
                }
                self.next_token = self.next_token.wrapping_add(0x0101);
                let token = self.next_token ^ (now as u32).rotate_left(13);
                let token = if token == 0 { 0x5EED } else { token };
                self.owner = Some(Lease {
                    peer: f.src,
                    token,
                    expires_ms: now + requested_ttl.max(1000) as u64,
                    index,
                    sub,
                });
                if let Some(s) = self.sessions.get_mut(&f.src) {
                    if let Some(c) = s.contract.as_mut() {
                        c.owner_token = token;
                        c.binding_id = bind_id;
                        c.session_id = session_id;
                    }
                    s.owner_token = token;
                    s.bind_phase = bind_phase::PREPARED;
                    s.stage = Stage::BindingPrepared;
                }
                self.send_bind_result(
                    now, f.src, f.txn, bind_phase::PREPARED, bind_id, session_id, token,
                    ErrCode::Ok, resumed, out,
                );
                out.push(self.trace(
                    "bind_prepare",
                    f.src,
                    format!("授予写租约 owner_token=0x{:08X}，TTL={} ms", token, requested_ttl.max(1000)),
                ));
            }
            bind_phase::COMMIT => {
                let valid = self
                    .owner
                    .as_ref()
                    .map(|o| o.peer == f.src && o.token == owner_token && o.expires_ms > now)
                    .unwrap_or(false);
                if !valid {
                    self.counters.binds_fail += 1;
                    self.send_bind_result(
                        now, f.src, f.txn, bind_phase::ABORT, bind_id, session_id, 0,
                        ErrCode::Lease, false, out,
                    );
                    return;
                }
                if let Some(o) = self.owner.as_mut() {
                    o.expires_ms = now + requested_ttl.max(1000) as u64;
                }
                if let Some(s) = self.sessions.get_mut(&f.src) {
                    s.stage = Stage::Active;
                    s.bind_phase = bind_phase::COMMITTED;
                    s.last_rx_ms = now;
                }
                // 只有到 COMMIT 才登记新 session_id：旧会话号从此失效，但绑定号保持稳定。
                let entry = self.bindings.entry((f.src, index, sub)).or_default();
                entry.binding_id = bind_id;
                entry.session_id = session_id;
                entry.grant_epoch = self.grant_epoch;
                entry.desc_version = self.desc_version;
                entry.desc_crc = self.desc_crc;
                entry.index = index;
                entry.sub = sub;
                self.counters.binds_ok += 1;
                self.send_bind_result(
                    now, f.src, f.txn, bind_phase::COMMITTED, bind_id, session_id, owner_token,
                    ErrCode::Ok, resumed, out,
                );
                out.push(self.trace("active", f.src, "两阶段绑定完成，进入 ACTIVE".to_string()));
            }
            bind_phase::RELEASE => {
                if self.owner.as_ref().map(|o| o.peer == f.src).unwrap_or(false) {
                    self.owner = None;
                }
                if let Some(s) = self.sessions.get_mut(&f.src) {
                    s.stage = Stage::Closed;
                    s.owner_token = 0;
                    s.bind_phase = bind_phase::RELEASE;
                }
                self.send_bind_result(
                    now, f.src, f.txn, bind_phase::COMMITTED, bind_id, session_id, 0,
                    ErrCode::Ok, false, out,
                );
                out.push(self.trace("release", f.src, "旧 owner 已释放写租约".to_string()));
                if let Some(pending) = self.pending_preempt.take() {
                    if pending != f.src {
                        self.grant_pending(now, pending, out);
                    }
                }
            }
            _ => {}
        }
    }

    fn grant_pending(&mut self, now: u64, peer: Did, out: &mut Vec<Action>) {
        let Some(sess) = self.sessions.get(&peer).cloned() else {
            return;
        };
        let Some(contract) = sess.contract.clone() else {
            return;
        };
        self.next_token = self.next_token.wrapping_add(0x0101);
        let token = (self.next_token ^ (now as u32).rotate_left(13)) | 1;
        self.owner = Some(Lease {
            peer,
            token,
            expires_ms: now + contract.ttl_ms.max(1000) as u64,
            index: contract.index,
            sub: contract.sub,
        });
        if let Some(s) = self.sessions.get_mut(&peer) {
            s.owner_token = token;
            s.stage = Stage::BindingPrepared;
            s.bind_phase = bind_phase::PREPARED;
        }
        self.send_bind_result(
            now, peer, sess.txn, bind_phase::PREPARED, contract.binding_id, contract.session_id,
            token, ErrCode::Ok, false, out,
        );
        out.push(self.trace("preempt_grant", peer, "旧 owner 释放，写租约转交新 owner".to_string()));
    }

    #[allow(clippy::too_many_arguments)]
    fn send_bind_result(
        &mut self,
        now: u64,
        peer: Did,
        txn: u16,
        phase: u8,
        bind_id: u32,
        session_id: u64,
        token: u32,
        code: ErrCode,
        resumed: bool,
        out: &mut Vec<Action>,
    ) {
        let mut w = TlvWriter::new();
        w.field_u8(tlv_type::BIND_PHASE, phase);
        w.field_u32(tlv_type::BIND_ID, bind_id);
        w.field_u64(tlv_type::SESSION_ID, session_id);
        w.field_u32(tlv_type::OWNER, token);
        w.field_u8(tlv_type::RESULT, code as u8);
        if resumed {
            w.field_u8(tlv_type::RESUMED, 1);
        }
        if code != ErrCode::Ok {
            w.field_u8(err_field::CODE, code as u8);
            w.field_str(err_field::REASON, code.name());
        }
        out.push(self.frame(now, ftype::BIND, peer, txn, w.finish()));
    }

    fn on_read(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        if !matches!(self.mode, RunMode::Provider | RunMode::Both) {
            return;
        }
        let Ok(tlvs) = decode_tlvs(&f.payload) else {
            return;
        };
        let Some(t) = tlvs.iter().find(|t| t.typ == tlv_type::INDEX) else {
            return;
        };
        let (index, sub) = (t.as_u16().unwrap_or(0), t.sub);
        let cap = match self.cap(index, sub) {
            Some(c) if c.readable() => c.clone(),
            _ => {
                self.send_error(now, f.src, ErrCode::NoDev, "能力点不存在或不可读", out);
                return;
            }
        };
        let point = self.points.get(&(index, sub)).cloned().unwrap_or(PointState {
            value: 0.0,
            ts_ms: now,
            quality: quality::GOOD,
        });
        // 事件驱动下没有固定 tick：读之前就地采样，保证 READ 返回当前时刻的模型值
        let point = if self.sims.contains_key(&(index, sub)) {
            self.update_simulated_points(now);
            self.points.get(&(index, sub)).cloned().unwrap_or(point)
        } else {
            point
        };
        let mut w = TlvWriter::new();
        w.put_u8(index, sub, tlv_type::RESULT, ErrCode::Ok as u8);
        let raw = encode_value(cap.dtype, cap.scale_exp, point.value);
        let _ = w.raw_put(index, sub, tlv_type::VALUE, &raw);
        w.field_u8(tlv_type::QUALITY, point.quality);
        w.field_u8(tlv_type::PROV, cap.provenance);
        out.push(self.frame(now, ftype::ACK, f.src, f.txn, w.finish()));
    }

    fn on_write(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        if !matches!(self.mode, RunMode::Provider | RunMode::Both) {
            return;
        }
        let Ok(tlvs) = decode_tlvs(&f.payload) else {
            return;
        };
        let index = get_u16(&tlvs, tlv_type::INDEX).unwrap_or(0);
        let sub = tlvs
            .iter()
            .find(|t| t.typ == tlv_type::INDEX)
            .map(|t| t.sub)
            .unwrap_or(0);
        let token = get_u32(&tlvs, tlv_type::OWNER).unwrap_or(0);
        let intent = get_str(&tlvs, tlv_type::INTENT).unwrap_or_default();
        let value = tlvs
            .iter()
            .find(|t| t.typ == tlv_type::VALUE)
            .and_then(|t| {
                let cap = self.cap(index, sub)?;
                decode_value(cap.dtype, cap.scale_exp, &t.value)
            });
        let Some(cap) = self.cap(index, sub).cloned() else {
            self.send_error(now, f.src, ErrCode::NoDev, "WRITE 目标不存在", out);
            return;
        };
        if !cap.writable() {
            self.counters.writes_rejected += 1;
            self.send_error(now, f.src, ErrCode::Unsafe, "该能力点不可写", out);
            return;
        }
        let lease_ok = self
            .owner
            .as_ref()
            .map(|o| o.peer == f.src && o.token == token && o.expires_ms > now)
            .unwrap_or(false);
        if !lease_ok {
            self.counters.writes_rejected += 1;
            self.send_error(now, f.src, ErrCode::Lease, "owner_token 缺失、错误或已过期", out);
            out.push(self.trace("write_reject", f.src, "写被拒：无有效 owner_token → E_LEASE".to_string()));
            return;
        }
        if intent.trim().is_empty() {
            self.counters.writes_rejected += 1;
            self.send_error(now, f.src, ErrCode::Perm, "写操作缺少意图结构", out);
            out.push(self.trace("write_reject", f.src, "写被拒：缺少意图 → E_PERM".to_string()));
            return;
        }
        let Some(value) = value else {
            self.counters.writes_rejected += 1;
            self.send_error(now, f.src, ErrCode::Ctx, "WRITE 缺少可解释的值载荷", out);
            return;
        };
        if value < cap.range.0 || value > cap.range.1 {
            self.counters.writes_rejected += 1;
            let mut w = TlvWriter::new();
            w.field_u8(err_field::CODE, ErrCode::Range as u8);
            w.field_str(err_field::REASON, "值超出声明量程");
            w.field_f64(err_field::RANGE_LO, cap.range.0);
            w.field_f64(err_field::RANGE_HI, cap.range.1);
            w.field_f64(err_field::VALUE, value);
            w.put_u16(index, sub, tlv_type::INDEX, index);
            out.push(self.frame(now, ftype::ERROR, f.src, f.txn, w.finish()));
            out.push(self.trace(
                "write_reject",
                f.src,
                format!("写被拒：{} 超出 [{}, {}]", value, cap.range.0, cap.range.1),
            ));
            return;
        }
        let key = (index, sub);
        if let Some(act) = self.actuators.get(&key).cloned() {
            // 执行器：受理写入后按行程时间/速率逼近目标，期间上报真实位置。
            let current = self.points.get(&key).map(|p| p.value).unwrap_or(0.0);
            let was_on = current >= 0.5;
            let will_on = value >= 0.5;
            let last = self
                .act_states
                .get(&key)
                .map(|s| s.last_switch_ms)
                .unwrap_or(0);
            let mut start = now;
            if was_on != will_on && last > 0 {
                let hold = if was_on { act.min_on_ms } else { act.min_off_ms };
                if hold > 0 {
                    start = now.max(last + hold);
                }
            }
            let duration = if act.rate > 0.0 {
                (((value - current).abs() / act.rate) * 1000.0)
                    .round()
                    .max(1.0) as u64
            } else {
                (act.travel_ms as u64).max(1)
            };
            let end = start + duration;
            self.act_states.insert(
                key,
                ActState {
                    target: value,
                    from: current,
                    start_ms: start,
                    end_ms: end,
                    last_switch_ms: if was_on != will_on { end } else { last },
                },
            );
            self.counters.actuator_moves += 1;
            out.push(self.trace(
                "actuator",
                f.src,
                format!(
                    "执行器 {index}/{sub} 目标 {value:.3}，{} ms 到位{}",
                    duration,
                    if start > now {
                        format!("（最小保持等待 {} ms）", start - now)
                    } else {
                        String::new()
                    }
                ),
            ));
        } else {
            let p = self.points.entry((index, sub)).or_insert(PointState {
                value: 0.0,
                ts_ms: now,
                quality: quality::GOOD,
            });
            p.value = value;
            p.ts_ms = now;
            p.quality = quality::GOOD;
        }
        self.counters.writes_ok += 1;
        self.update_alarms(now);
        if let Some(o) = self.owner.as_mut() {
            o.expires_ms = now + DEFAULT_TTL_MS as u64;
        }
        let mut w = TlvWriter::new();
        w.put_u8(index, sub, tlv_type::RESULT, ErrCode::Ok as u8);
        w.put_u16(index, sub, tlv_type::INDEX, index);
        out.push(self.frame(now, ftype::ACK, f.src, f.txn, w.finish()));
        out.push(self.trace(
            "write_ok",
            f.src,
            format!("写入 {}/{} = {:.3} {}（意图：{}）", index, sub, value, cap.unit, intent),
        ));
    }

    fn on_subscribe(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        let Ok(tlvs) = decode_tlvs(&f.payload) else {
            return;
        };
        let index = get_u16(&tlvs, tlv_type::INDEX).unwrap_or(0);
        let sub = tlvs
            .iter()
            .find(|t| t.typ == tlv_type::INDEX)
            .map(|t| t.sub)
            .unwrap_or(0);
        let want = get_u32(&tlvs, tlv_type::TPUB).unwrap_or(0);
        let Some(sess) = self.sessions.get(&f.src).cloned() else {
            self.send_error(now, f.src, ErrCode::State, "未绑定即订阅", out);
            return;
        };
        if sess.stage != Stage::Active {
            self.send_error(now, f.src, ErrCode::State, "订阅要求 ACTIVE 绑定", out);
            return;
        }
        if let Some(s) = self.sessions.get_mut(&f.src) {
            s.subscribed = true;
            if let Some(c) = s.contract.as_mut() {
                if want > 0 {
                    c.t_pub_ms = c.t_pub_ms.max(want);
                }
            }
            s.last_pub_ms = 0;
            s.last_pub_ts = 0;
        }
        let t_pub = self
            .sessions
            .get(&f.src)
            .and_then(|s| s.contract.as_ref())
            .map(|c| c.t_pub_ms)
            .unwrap_or(0);
        let mut w = TlvWriter::new();
        w.put_u8(index, sub, tlv_type::RESULT, ErrCode::Ok as u8);
        w.field_u32(tlv_type::TPUB, t_pub);
        out.push(self.frame(now, ftype::ACK, f.src, f.txn, w.finish()));
    }

    fn on_event(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        let Ok(tlvs) = decode_tlvs(&f.payload) else {
            return;
        };
        let Some(value_tlv) = tlvs.iter().find(|t| t.typ == tlv_type::VALUE) else {
            return;
        };
        let q = get_u8(&tlvs, tlv_type::QUALITY).unwrap_or(quality::GOOD);
        let prov = get_u8(&tlvs, tlv_type::PROV).unwrap_or(0);
        let (index, sub) = (value_tlv.idx, value_tlv.sub);
        let Some(sess) = self.sessions.get(&f.src).cloned() else {
            return;
        };
        let Some(contract) = sess.contract.clone() else {
            return;
        };
        let Some(value) = decode_value(contract.dtype, contract.scale_exp, &value_tlv.value) else {
            return;
        };
        self.recv.insert(
            (index, sub),
            ReceivedValue {
                value,
                quality: q,
                prov,
                received_ms: now,
                stale: false,
            },
        );
        self.counters.events_rx += 1;
        if let Some(s) = self.sessions.get_mut(&f.src) {
            s.last_update_ms = now;
            s.last_rx_ms = now;
            s.stale = false;
            s.error = None;
        }
        self.evaluate_logic(now, out);
    }

    /// 收到新数据后执行设备行为规则：先算聚合，再跑阈值，命中则写本地点或远端执行器。
    fn evaluate_logic(&mut self, now: u64, out: &mut Vec<Action>) {
        if self.rules.is_empty() {
            return;
        }
        let rules = self.rules.clone();
        for (i, rule) in rules.iter().enumerate() {
            let state = self.logic_state[i].clone();
            if rule.min_interval_ms > 0
                && state.last_ms != 0
                && now < state.last_ms + rule.min_interval_ms
            {
                continue;
            }
            let Some(value) = self.rule_value(rule) else {
                continue;
            };
            if state
                .last_out
                .map(|v| (v - value).abs() < 1e-9)
                .unwrap_or(false)
            {
                continue;
            }
            self.logic_state[i].last_ms = now;
            self.logic_state[i].last_out = Some(value);
            self.counters.logic_fired += 1;
            let (index, sub) = rule.output;
            if rule.target.is_empty() {
                if let Some(p) = self.points.get_mut(&(index, sub)) {
                    p.value = value;
                    p.ts_ms = now;
                    p.quality = quality::GOOD;
                }
                out.push(self.trace(
                    "logic",
                    self.did,
                    format!("规则「{}」→ 本地 {index}/{sub} = {value:.3}", rule.name),
                ));
            } else {
                out.push(Action::LogicWrite {
                    target: rule.target.clone(),
                    index,
                    sub,
                    value,
                    intent: format!("规则:{}", rule.name),
                });
            }
        }
    }

    /// 计算一条规则的输出值；输入优先取接收缓存，本地能力点作为兜底（支持规则级联）。
    fn rule_value(&self, rule: &LogicRule) -> Option<f64> {
        let read = |key: &(u16, u8)| -> Option<f64> {
            if let Some(v) = self.recv.get(key) {
                if v.stale {
                    return None;
                }
                return Some(v.value);
            }
            self.points.get(key).map(|p| p.value)
        };
        match rule.kind {
            LogicKind::Threshold => {
                let v = read(rule.sources.first()?)?;
                let hit = match rule.op {
                    1 => v > rule.threshold,
                    2 => v >= rule.threshold,
                    3 => v < rule.threshold,
                    4 => v <= rule.threshold,
                    5 => (v - rule.threshold).abs() < 1e-9,
                    6 => v >= rule.threshold && v <= rule.threshold2,
                    _ => false,
                };
                Some(if hit { rule.on_value } else { rule.off_value })
            }
            LogicKind::Aggregate => {
                let vals: Vec<f64> = rule.sources.iter().filter_map(read).collect();
                if vals.is_empty() {
                    return None;
                }
                Some(match rule.agg {
                    2 => vals.iter().sum(),
                    3 => vals.iter().cloned().fold(f64::INFINITY, f64::min),
                    4 => vals.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
                    5 => vals.len() as f64,
                    _ => vals.iter().sum::<f64>() / vals.len() as f64,
                })
            }
        }
    }

    // ------------------------------------------------------------ 查询 / 应答

    /// 提供者侧：按选择器匹配本地能力点，逐点回 REPLY，最后回 REPLY_END。
    fn on_query(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        if !matches!(self.mode, RunMode::Provider | RunMode::Both) {
            return;
        }
        let Ok(tlvs) = decode_tlvs(&f.payload) else {
            return;
        };
        let qid = get_u32(&tlvs, tlv_type::QUERY_ID).unwrap_or(0);
        let selector_text = get_str(&tlvs, tlv_type::SELECTOR).unwrap_or_else(|| "*".into());
        let Some(selector) = Selector::parse(&selector_text) else {
            return;
        };
        let hits: Vec<Capability> = self
            .caps
            .iter()
            .filter(|c| c.readable() && selector.matches(c.index, c.sub))
            .cloned()
            .collect();
        if !hits.is_empty() {
            if self.sims.contains_key(&(hits[0].index, hits[0].sub)) {
                self.update_simulated_points(now);
            }
        }
        let total = hits.len() as u32;
        for cap in &hits {
            let Some(point) = self.points.get(&(cap.index, cap.sub)).cloned() else {
                continue;
            };
            let mut w = TlvWriter::new();
            w.field_u32(tlv_type::QUERY_ID, qid);
            w.put_u16(cap.index, cap.sub, tlv_type::INDEX, cap.index);
            let raw = encode_value(cap.dtype, cap.scale_exp, point.value);
            let _ = w.raw_put(cap.index, cap.sub, tlv_type::VALUE, &raw);
            w.field_u8(tlv_type::DTYPE, cap.dtype);
            w.field_u8(tlv_type::SCALE, cap.scale_exp);
            w.field_u8(tlv_type::QUALITY, point.quality);
            w.field_u8(tlv_type::PROV, cap.provenance);
            w.field_str(tlv_type::LABEL, &cap.label);
            w.field_u32(tlv_type::REPLY_COUNT, total);
            out.push(self.frame(now, ftype::REPLY, f.src, f.txn, w.finish()));
        }
        // 无匹配也回 REPLY_END，发起方才能立刻知道“这个提供者没有贡献”，
        // 不必等到超时；REPLY_COUNT=0 明确表达这一点。
        let mut w = TlvWriter::new();
        w.field_u32(tlv_type::QUERY_ID, qid);
        w.field_u32(tlv_type::REPLY_COUNT, total);
        out.push(self.frame(now, ftype::REPLY_END, f.src, f.txn, w.finish()));
        self.counters.queries_answered += 1;
        out.push(self.trace(
            "query_served",
            f.src,
            format!("响应查询 {qid}（{selector_text}），命中 {total} 个点"),
        ));
    }

    /// 发起方侧：按 QUERY_ID 聚合应答。
    fn on_reply(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        let Ok(tlvs) = decode_tlvs(&f.payload) else {
            return;
        };
        let qid = get_u32(&tlvs, tlv_type::QUERY_ID).unwrap_or(0);
        let Some(t) = tlvs.iter().find(|t| t.typ == tlv_type::INDEX) else {
            return;
        };
        let (index, sub) = (t.as_u16().unwrap_or(0), t.sub);
        let dtype = get_u8(&tlvs, tlv_type::DTYPE).unwrap_or(idcell_core::consts::dtype::F64);
        let scale = get_u8(&tlvs, tlv_type::SCALE).unwrap_or(0);
        let value = tlvs
            .iter()
            .find(|t| t.typ == tlv_type::VALUE)
            .and_then(|t| decode_value(dtype, scale, &t.value))
            .unwrap_or(0.0);
        let label = get_str(&tlvs, tlv_type::LABEL).unwrap_or_default();
        let quality = get_u8(&tlvs, tlv_type::QUALITY).unwrap_or(quality::GOOD);
        let total = get_u32(&tlvs, tlv_type::REPLY_COUNT).unwrap_or(0);

        let Some(q) = self.queries.get_mut(&qid) else {
            return;
        };
        if q.done {
            return;
        }
        if q.providers.insert(f.src) {
            q.expected = q.expected.saturating_add(total);
        }
        q.replies.push(QueryReply {
            from: f.src,
            index,
            sub,
            label: label.clone(),
            value,
            quality,
            at_ms: now,
        });
        self.counters.replies_rx += 1;
        let count = q.replies.len();
        if q.mode == query_mode::FIRST {
            q.done = true;
        }
        out.push(self.trace(
            "reply",
            f.src,
            format!("查询 {qid} 收到 {index}/{sub} = {value:.3}（{label}），第 {count} 条"),
        ));
    }

    fn on_reply_end(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        let Ok(tlvs) = decode_tlvs(&f.payload) else {
            return;
        };
        let qid = get_u32(&tlvs, tlv_type::QUERY_ID).unwrap_or(0);
        let Some(q) = self.queries.get_mut(&qid) else {
            return;
        };
        q.ended += 1;
        // all 模式不知道还有多少提供者，等聚合窗口结束；first 模式立即收尾。
        if q.mode == query_mode::FIRST && !q.done {
            q.done = true;
        }
        let summary = format!(
            "查询 {qid}：{replies} 条应答，{ended} 个提供者回复完毕",
            replies = q.replies.len(),
            ended = q.ended
        );
        out.push(self.trace("reply_end", f.src, summary));
        let _ = now;
    }

    /// 发起查询：广播（或定向）QUERY，由多提供者并行应答。
    pub fn request_query(
        &mut self,
        now: u64,
        to: Did,
        selector: &str,
        mode: u8,
        hop_limit: u32,
    ) -> Vec<Action> {
        let text = Selector::parse(selector)
            .map(|s| s.as_text())
            .unwrap_or_else(|| "*".into());
        let id = self.next_query_id;
        self.next_query_id = self.next_query_id.wrapping_add(1).max(1);
        self.queries.insert(
            id,
            QuerySession {
                id,
                selector: text.clone(),
                mode,
                started_ms: now,
                deadline_ms: now + QUERY_TIMEOUT_MS,
                expected: 0,
                providers: BTreeSet::new(),
                replies: Vec::new(),
                ended: 0,
                done: false,
            },
        );
        self.counters.queries_sent += 1;
        let mut w = TlvWriter::new();
        w.field_u32(tlv_type::QUERY_ID, id);
        w.field_str(tlv_type::SELECTOR, &text);
        w.field_u8(tlv_type::QUERY_MODE, mode);
        w.field_u32(tlv_type::HOP_LIMIT, if hop_limit == 0 { 6 } else { hop_limit });
        w.field_u32(tlv_type::TARGET, 0);
        let txn = self.next_txn();
        vec![
            self.frame(now, ftype::QUERY, to, txn, w.finish()),
            self.trace(
                "query",
                to,
                format!("发起查询 {id}，选择器 {text}，模式 {}", query_mode::name(mode)),
            ),
        ]
    }

    fn on_ack(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        let Ok(tlvs) = decode_tlvs(&f.payload) else {
            return;
        };
        let code = result_code(&tlvs);
        // 携带 COMMAND_ID 的 ACK 是命令受理确认（FR-039 第二段），与 WRITE/READ 的 ACK 区分。
        if let Some(t) = tlvs.iter().find(|t| t.typ == tlv_type::COMMAND_ID) {
            self.counters.cmd_acks += 1;
            if let Some(s) = self.sessions.get_mut(&f.src) {
                s.last_rx_ms = now;
            }
            out.push(self.trace(
                "cmd_ack",
                f.src,
                format!("命令 {} 已受理", t.as_u32().unwrap_or(0)),
            ));
        }
        // 入网 ACK：携带 GROUP_ID（不含 COMMAND_ID）时把本机加入该组。
        if !tlvs.iter().any(|t| t.typ == tlv_type::COMMAND_ID) {
            if let Some(gid) = get_u16(&tlvs, tlv_type::GROUP_ID) {
                if code == ErrCode::Ok {
                    self.group = gid;
                    self.counters.provision_ok += 1;
                    if let Some(s) = self.sessions.get_mut(&f.src) {
                        s.last_rx_ms = now;
                    }
                    out.push(self.trace(
                        "provision_ok",
                        f.src,
                        format!("入网完成，已加入组 {gid}"),
                    ));
                }
            }
        }
        let Some(sess) = self.sessions.get(&f.src).cloned() else {
            return;
        };
        if code != ErrCode::Ok {
            if sess.role == Role::Consumer {
                self.counters.writes_rejected += 1;
                if let Some(s) = self.sessions.get_mut(&f.src) {
                    s.error = Some(code);
                }
                out.push(self.trace("ack_error", f.src, format!("请求被拒：{}", code.name())));
            }
            return;
        }
        if let Some(value_tlv) = tlvs.iter().find(|t| t.typ == tlv_type::VALUE) {
            let Some(contract) = sess.contract.clone() else {
                return;
            };
            if let Some(value) = decode_value(contract.dtype, contract.scale_exp, &value_tlv.value) {
                self.recv.insert(
                    (value_tlv.idx, value_tlv.sub),
                    ReceivedValue {
                        value,
                        quality: get_u8(&tlvs, tlv_type::QUALITY).unwrap_or(quality::GOOD),
                        prov: get_u8(&tlvs, tlv_type::PROV).unwrap_or(0),
                        received_ms: now,
                        stale: false,
                    },
                );
            }
        }
        if let Some(t) = tlvs.iter().find(|t| t.typ == tlv_type::TPUB) {
            let t_pub = t.as_u32().unwrap_or(0);
            if let Some(s) = self.sessions.get_mut(&f.src) {
                if let Some(c) = s.contract.as_mut() {
                    c.t_pub_ms = t_pub;
                }
            }
        }
        let _ = out;
    }

    fn on_heartbeat(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        let Ok(tlvs) = decode_tlvs(&f.payload) else {
            return;
        };
        let token = get_u32(&tlvs, tlv_type::OWNER).unwrap_or(0);
        let ttl = get_u32(&tlvs, tlv_type::TTL).unwrap_or(DEFAULT_TTL_MS);
        if let Some(s) = self.sessions.get_mut(&f.src) {
            s.last_rx_ms = now;
            // 注意：last_hb_ms 只表示“本端上次发送心跳”，不能被收到的对端心跳重置，
            // 否则双方互相刷新会让谁都不再发心跳（死锁式静默）。
        }
        if let Some(owner) = self.owner.as_mut() {
            if owner.peer == f.src && owner.token == token && token != 0 {
                owner.expires_ms = now + ttl.max(1000) as u64;
            }
        }
        let _ = out;
    }

    fn on_lease(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        let Ok(tlvs) = decode_tlvs(&f.payload) else {
            return;
        };
        let token = get_u32(&tlvs, tlv_type::OWNER).unwrap_or(0);
        if let Some(s) = self.sessions.get_mut(&f.src) {
            s.owner_token = token;
            if let Some(c) = s.contract.as_mut() {
                c.owner_token = token;
            }
            if token == 0 {
                s.stage = Stage::Closed;
                out.push(self.trace("lease_lost", f.src, "写租约被收回".to_string()));
            }
        }
        let _ = now;
    }

    fn on_preempt(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        let Some(sess) = self.sessions.get(&f.src).cloned() else {
            return;
        };
        if sess.stage != Stage::Active {
            return;
        }
        let contract = sess.contract.clone().unwrap_or_default();
        let txn = self.next_txn();
        let mut w = TlvWriter::new();
        w.field_u8(tlv_type::BIND_PHASE, bind_phase::RELEASE);
        w.field_u32(tlv_type::BIND_ID, contract.binding_id);
        w.field_u64(tlv_type::SESSION_ID, contract.session_id);
        w.field_u32(tlv_type::OWNER, sess.owner_token);
        w.put_u16(contract.index, contract.sub, tlv_type::INDEX, contract.index);
        if let Some(s) = self.sessions.get_mut(&f.src) {
            s.stage = Stage::Closed;
            s.owner_token = 0;
        }
        out.push(self.frame(now, ftype::BIND, f.src, txn, w.finish()));
        out.push(self.trace(
            "preempted",
            f.src,
            "收到 PREEMPT，停止控制并释放 owner_token".to_string(),
        ));
    }

    fn on_stale(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        let _ = (now, f);
        for v in self.recv.values_mut() {
            v.stale = true;
            v.quality = quality::UNCERTAIN;
        }
        self.counters.stale_events += 1;
        out.push(self.trace("stale_notice", f.src, "对端声明来源降级，降低该点信任权重".to_string()));
    }

    fn on_offline(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        if let Some(s) = self.sessions.get_mut(&f.src) {
            s.stage = Stage::Closed;
            s.error = Some(ErrCode::Unavailable);
        }
        for v in self.recv.values_mut() {
            v.stale = true;
            v.quality = quality::BAD;
        }
        out.push(self.trace("offline", f.src, "对端声明离线".to_string()));
        let _ = now;
    }

    fn on_error(&mut self, now: u64, f: &Frame, out: &mut Vec<Action>) {
        let Ok(tlvs) = decode_tlvs(&f.payload) else {
            return;
        };
        let code = tlvs
            .iter()
            .find(|t| t.typ == err_field::CODE)
            .and_then(|t| t.as_u8())
            .map(ErrCode::from_u8)
            .unwrap_or(ErrCode::State);
        let reason = tlvs
            .iter()
            .find(|t| t.typ == err_field::REASON)
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        // 请求级错误（错误体带被拒项）只影响本次操作，不拆会话；
        // 例如 CONFIG 因 E_PERM 被拒后，既有绑定契约仍应继续有效（FR-065）。
        if tlvs.iter().any(|t| t.typ == err_field::INDEX) {
            if let Some(s) = self.sessions.get_mut(&f.src) {
                s.error = Some(code);
            }
            out.push(self.trace(
                "error_rejected",
                f.src,
                format!("请求被拒（{}）：{}", code.name(), reason),
            ));
            return;
        }
        if let Some(s) = self.sessions.get_mut(&f.src) {
            s.error = Some(code);
            s.stage = Stage::Failed;
        }
        out.push(self.trace("error", f.src, format!("{}：{}", code.name(), reason)));
        let _ = now;
    }

    fn fail_session(&mut self, peer: Did, code: ErrCode, out: &mut Vec<Action>) {
        let mut role = Role::Consumer;
        if let Some(s) = self.sessions.get_mut(&peer) {
            s.stage = Stage::Failed;
            s.error = Some(code);
            role = s.role;
        }
        if role == Role::Consumer {
            self.counters.binds_fail += 1;
        }
        out.push(self.trace("failed", peer, format!("绑定失败：{}", code.name())));
    }

    fn send_error(&mut self, now: u64, peer: Did, code: ErrCode, reason: &str, out: &mut Vec<Action>) {
        let txn = self.next_txn();
        let mut w = TlvWriter::new();
        w.field_u8(err_field::CODE, code as u8);
        w.field_str(err_field::REASON, reason);
        w.field_u8(err_field::RETRY, u8::from(code.retryable()));
        out.push(self.frame(now, ftype::ERROR, peer, txn, w.finish()));
        out.push(self.trace("error", peer, format!("{}：{}", code.name(), reason)));
    }

    // ------------------------------------------------------------ 外部操作

    pub fn request_read(&mut self, now: u64, peer: Did, index: u16, sub: u8) -> Vec<Action> {
        let mut w = TlvWriter::new();
        w.put_u16(index, sub, tlv_type::INDEX, index);
        let txn = self.next_txn();
        vec![self.frame(now, ftype::READ, peer, txn, w.finish())]
    }

    pub fn request_write(
        &mut self,
        now: u64,
        peer: Did,
        index: u16,
        sub: u8,
        value: f64,
        intent: &str,
    ) -> Vec<Action> {
        let token = self
            .sessions
            .get(&peer)
            .map(|s| s.owner_token)
            .unwrap_or(0);
        // 值载荷必须按协商出的 (dtype, scale) 编码；消费者自身没有该点的能力描述，
        // 因此优先取本端会话契约，其次才有能力描述符可依。
        let (dtype, scale) = self
            .sessions
            .values()
            .filter_map(|s| s.contract.as_ref())
            .find(|c| c.index == index && c.sub == sub)
            .map(|c| (c.dtype, c.scale_exp))
            .or_else(|| self.cap(index, sub).map(|c| (c.dtype, c.scale_exp)))
            .unwrap_or((idcell_core::consts::dtype::F64, 0));
        let mut w = TlvWriter::new();
        w.put_u16(index, sub, tlv_type::INDEX, index);
        let raw = encode_value(dtype, scale, value);
        let _ = w.raw_put(index, sub, tlv_type::VALUE, &raw);
        w.field_u32(tlv_type::OWNER, token);
        w.field_str(tlv_type::INTENT, intent);
        w.field_u32(tlv_type::VALID_FOR, DEFAULT_TTL_MS / 2);
        w.field_u32(tlv_type::COMMAND_ID, self.next_txn() as u32);
        let txn = self.next_txn();
        vec![self.frame(now, ftype::WRITE, peer, txn, w.finish())]
    }

    /// 运行中重新协商发布周期（不改绑定、不重新鉴权）。
    /// want_ms 为期望的 T_pub；0 表示沿用当前契约值。
    pub fn request_renegotiate(&mut self, now: u64, peer: Did, want_ms: u32) -> Vec<Action> {
        let Some(sess) = self.sessions.get(&peer) else {
            return vec![self.trace("renegotiate_skip", peer, "会话不存在，无法重新协商")];
        };
        if sess.stage != Stage::Active {
            return vec![self.trace("renegotiate_skip", peer, "会话未处于 active，无法重新协商")];
        }
        let (index, sub, cur_t_pub, cur_stale) = match sess.contract.as_ref() {
            Some(c) => (c.index, c.sub, c.t_pub_ms, c.stale_ms),
            None => (0, 0, 0, 0),
        };
        let want = if want_ms == 0 { cur_t_pub } else { want_ms };
        let mut w = TlvWriter::new();
        w.put_u8(index, sub, tlv_type::RESULT, ErrCode::Ok as u8);
        w.field_u32(tlv_type::TPUB, want);
        w.field_u32(tlv_type::STALE, cur_stale);
        let txn = self.next_txn();
        vec![
            self.frame(now, ftype::RENEGOTIATE, peer, txn, w.finish()),
            self.trace("renegotiate", peer, format!("请求重新协商 T_pub = {want} ms")),
        ]
    }

    /// 运行中退订某个点（仅通知提供方停止推送，不影响绑定）。
    pub fn request_unsubscribe(&mut self, now: u64, peer: Did, index: u16, sub: u8) -> Vec<Action> {
        let mut w = TlvWriter::new();
        w.put_u16(index, sub, tlv_type::INDEX, index);
        let txn = self.next_txn();
        if let Some(s) = self.sessions.get_mut(&peer) {
            if s.contract.as_ref().map(|c| (c.index, c.sub)) == Some((index, sub)) {
                s.subscribed = false;
            }
        }
        vec![
            self.frame(now, ftype::UNSUB, peer, txn, w.finish()),
            self.trace("unsubscribe", peer, format!("退订 {index}/{sub}")),
        ]
    }

    pub fn set_asleep(&mut self, asleep: bool) {
        self.awake = !asleep;
        self.presence = if asleep { 1 } else { 0 };
    }

    pub fn set_rx_on(&mut self, on: bool) {
        self.rx_on = on;
    }

    /// 电源开关：断电后不再参与任何收发与定时行为。
    pub fn set_power(&mut self, on: bool) {
        self.powered = on;
        if !on {
            self.presence = 1;
        } else if self.awake {
            self.presence = 0;
        }
    }
}

// ---------------------------------------------------------------- 辅助

fn result_code(tlvs: &[idcell_core::Tlv]) -> ErrCode {
    if let Some(code) = tlvs
        .iter()
        .find(|t| t.typ == err_field::CODE)
        .and_then(|t| t.as_u8())
    {
        return ErrCode::from_u8(code);
    }
    match tlvs.iter().find(|t| t.typ == tlv_type::RESULT).and_then(|t| t.as_u8()) {
        Some(0) | None => ErrCode::Ok,
        Some(code) => ErrCode::from_u8(code),
    }
}

fn get_u8(tlvs: &[idcell_core::Tlv], typ: u8) -> Option<u8> {
    tlvs.iter().find(|t| t.typ == typ).and_then(|t| t.as_u8())
}

fn get_u16(tlvs: &[idcell_core::Tlv], typ: u8) -> Option<u16> {
    tlvs.iter().find(|t| t.typ == typ).and_then(|t| t.as_u16())
}

fn get_u32(tlvs: &[idcell_core::Tlv], typ: u8) -> Option<u32> {
    tlvs.iter().find(|t| t.typ == typ).and_then(|t| t.as_u32())
}

fn get_u64(tlvs: &[idcell_core::Tlv], typ: u8) -> Option<u64> {
    tlvs.iter().find(|t| t.typ == typ).and_then(|t| t.as_u64())
}

fn get_str(tlvs: &[idcell_core::Tlv], typ: u8) -> Option<String> {
    tlvs.iter()
        .find(|t| t.typ == typ)
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
}

fn make_nonce(did: Did, now: u64, txn: u16) -> [u8; 16] {
    let mut n = [0u8; 16];
    n[..8].copy_from_slice(&did.0);
    let x = now
        .rotate_left(17)
        .wrapping_mul(0x9E37_79B9)
        .wrapping_add(txn as u64);
    n[8..].copy_from_slice(&x.to_be_bytes());
    n
}

fn auth_proof(key: &[u8], nonce: &[u8; 16], session_id: u64, src: Did, dst: Did) -> [u8; 16] {
    let mut msg = Vec::with_capacity(48);
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(&session_id.to_be_bytes());
    msg.extend_from_slice(&src.0);
    msg.extend_from_slice(&dst.0);
    let mac = hmac_sha256(key, &msg);
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac[..16]);
    out
}

fn hash_noise(seed: u64, t: u64) -> f64 {
    let mut x = seed ^ t.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^= x >> 31;
    ((x >> 11) as f64 / ((1u64 << 53) as f64)) * 2.0 - 1.0
}
