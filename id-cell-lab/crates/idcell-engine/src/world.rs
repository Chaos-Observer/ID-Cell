//! 世界编排：虚拟时钟、事件队列、路由、链路损伤、指标与快照。

use crate::device::{Action, Device, DeviceCounters, DeviceSpec, Role, RunMode, Stage};
use crate::link::{Link, LinkConfig};
use crate::rng::Rng;
use crate::trace::{json_escape, json_num, TraceEntry, TraceLog};
use idcell_core::{decode_tlvs, ftype, tlv_type, Did, Frame, TlvWriter};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone)]
pub struct WorldConfig {
    pub seed: u64,
    pub duration_ms: u64,
    /// 0 = 纯事件驱动（每个设备按自身定时器唤醒）。
    /// >0 = 额外按该周期插入脉冲，用于需要固定采样步长的模型。
    pub tick_ms: u64,
    pub trace_cap: usize,
    /// true 时只有显式连线的设备对之间才能收发；未连线直接丢弃。
    /// 画布编辑器用它实现“像电路一样必须接线才导通”的语义。
    pub require_link: bool,
    /// 广播洪泛 / 中继选路的最大跳数（每经过一个中继算一跳）。
    pub max_hops: u8,
}

impl Default for WorldConfig {
    fn default() -> Self {
        WorldConfig {
            seed: 42,
            duration_ms: 12_000,
            tick_ms: 0,
            trace_cap: 4_000,
            require_link: false,
            max_hops: 6,
        }
    }
}

#[derive(Debug, Clone)]
enum Event {
    /// 设备定时器到期（由设备自身 next_deadline 计算）
    Tick(usize),
    /// 可选周期脉冲（tick_ms > 0 时启用）
    Pulse(usize),
    Deliver {
        to: usize,
        bytes: Vec<u8>,
        /// 上一跳设备（中继广播时用于排除回程；直连为 None）。
        from: Option<usize>,
    },
    /// 链路 ACK 超时：按 id 取待确认帧重传或放弃。
    LinkAck(u64),
}

struct Pending {
    at: u64,
    seq: u64,
    event: Event,
}

#[derive(Debug, Clone, Default)]
pub struct Metrics {
    pub frames_tx: u64,
    pub frames_rx: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub drops: u64,
    pub duplicated: u64,
    pub crc_errors: u64,
    pub latency_samples: u64,
    pub latency_sum_ms: u64,
    pub latency_max_ms: u64,
    pub latency_sum_sq: f64,
    pub link_extra_ms: u64,
    /// 排队造成的额外等待（带宽受限时）
    pub link_queue_ms: u64,
    /// 1ms 粒度时延直方图，末桶为溢出
    pub latency_hist: Vec<u32>,
    /// 控制面帧的链路级重传次数（NFR-026）
    pub link_retx: u64,
    /// 已收到的链路级 ACK
    pub link_acks: u64,
    /// 重传达到上限仍未确认、被放弃的帧
    pub link_drops: u64,
}

/// 链路确认时延与重传上限（NFR-026：控制面帧 3 次重传内成功）。
pub const LINK_ACK_TIMEOUT_MS: u64 = 240;
pub const LINK_MAX_RETX: u32 = 3;

/// 已发出、等待链路 ACK 的帧。
struct LinkPending {
    from: usize,
    to: Did,
    frame: Frame,
    tries: u32,
}

impl Metrics {
    pub fn avg_latency_ms(&self) -> f64 {
        if self.latency_samples == 0 {
            0.0
        } else {
            self.latency_sum_ms as f64 / self.latency_samples as f64
        }
    }

    pub fn drop_rate(&self) -> f64 {
        let total = self.frames_tx + self.drops;
        if total == 0 {
            0.0
        } else {
            self.drops as f64 / total as f64
        }
    }

    /// 时延分位数（p ∈ 0..=1），基于直方图，误差不超过 1ms。
    pub fn percentile_ms(&self, p: f64) -> f64 {
        let total: u64 = self.latency_hist.iter().map(|v| *v as u64).sum();
        if total == 0 {
            return 0.0;
        }
        let rank = ((total as f64) * p.clamp(0.0, 1.0)).ceil() as u64;
        let mut acc = 0u64;
        for (i, v) in self.latency_hist.iter().enumerate() {
            acc += *v as u64;
            if acc >= rank.max(1) {
                return i as f64;
            }
        }
        self.latency_max_ms as f64
    }

    /// 时延抖动（总体标准差，ms）
    pub fn jitter_ms(&self) -> f64 {
        if self.latency_samples == 0 {
            return 0.0;
        }
        let n = self.latency_samples as f64;
        let mean = self.latency_sum_ms as f64 / n;
        let var = (self.latency_sum_sq / n - mean * mean).max(0.0);
        var.sqrt()
    }

    /// 平均吞吐（kbps），按已运行时长折算。
    pub fn throughput_kbps(&self, elapsed_ms: u64) -> f64 {
        if elapsed_ms == 0 {
            return 0.0;
        }
        (self.bytes_rx as f64 * 8.0) / elapsed_ms as f64
    }
}

pub struct World {
    pub now_ms: u64,
    pub duration_ms: u64,
    pub tick_ms: u64,
    pub devices: Vec<Device>,
    pub links: Vec<Link>,
    pub default_link: LinkConfig,
    /// 见 `WorldConfig::require_link`。
    pub require_link: bool,
    /// 见 `WorldConfig::max_hops`。
    pub max_hops: u8,
    pub metrics: Metrics,
    pub trace: TraceLog,
    pub rng: Rng,
    pub finished: bool,
    seq: u64,
    pending: Vec<Pending>,
    did_map: BTreeMap<Did, usize>,
    pub type_counts: BTreeMap<u8, u64>,
    /// 有序点对的方向队列空闲时刻，模拟带宽受限时的排队
    serial: BTreeMap<(usize, usize), u64>,
    /// 最近发出的原始帧（十六进制），供面板做帧级详情
    frames: VecDeque<FrameView>,
    /// 广播洪泛去重：`(原始 src, seq, query_id)` → 首次转发时刻。
    flood_seen: BTreeMap<(Did, u16, u32), u64>,
    /// 待链路确认的控制面帧。
    link_pending: BTreeMap<u64, LinkPending>,
    next_link_id: u64,
}

impl World {
    pub fn new(cfg: WorldConfig) -> Self {
        World {
            now_ms: 0,
            duration_ms: cfg.duration_ms,
            tick_ms: cfg.tick_ms,
            devices: Vec::new(),
            links: Vec::new(),
            default_link: LinkConfig::default(),
            require_link: cfg.require_link,
            max_hops: cfg.max_hops.max(1),
            metrics: Metrics {
                latency_hist: vec![0u32; 2048],
                ..Metrics::default()
            },
            trace: TraceLog::new(cfg.trace_cap),
            rng: Rng::new(cfg.seed),
            finished: false,
            seq: 1,
            pending: Vec::new(),
            did_map: BTreeMap::new(),
            type_counts: BTreeMap::new(),
            serial: BTreeMap::new(),
            frames: VecDeque::new(),
            flood_seen: BTreeMap::new(),
            link_pending: BTreeMap::new(),
            next_link_id: 1,
        }
    }

    pub fn add_device(&mut self, spec: DeviceSpec, mode: RunMode) -> usize {
        let id = self.devices.len();
        let did = spec.did;
        self.did_map.insert(did, id);
        let device = Device::new(id, spec, mode);
        self.devices.push(device);
        self.schedule_wake(id);
        if self.tick_ms > 0 {
            self.push_event(0, Event::Pulse(id));
        }
        id
    }

    pub fn add_link(&mut self, a: usize, b: usize, cfg: LinkConfig) {
        self.links.push(Link::new(a, b, cfg));
    }

    pub fn resolve(&self, name: &str) -> Option<usize> {
        self.devices
            .iter()
            .position(|d| d.name == name || d.did.to_hex().eq_ignore_ascii_case(name))
    }

    pub fn device(&self, name: &str) -> Option<&Device> {
        self.resolve(name).map(|i| &self.devices[i])
    }

    pub fn device_mut(&mut self, name: &str) -> Option<&mut Device> {
        self.resolve(name).map(move |i| &mut self.devices[i])
    }

    fn push_event(&mut self, at: u64, event: Event) {
        let seq = self.seq;
        self.seq += 1;
        self.pending.push(Pending { at, seq, event });
    }

    fn pop_before(&mut self, target: u64) -> Option<Pending> {
        let mut best: Option<usize> = None;
        for (i, p) in self.pending.iter().enumerate() {
            if p.at > target {
                continue;
            }
            match best {
                None => best = Some(i),
                Some(b) => {
                    let pb = &self.pending[b];
                    if (p.at, p.seq) < (pb.at, pb.seq) {
                        best = Some(i);
                    }
                }
            }
        }
        best.map(|i| self.pending.swap_remove(i))
    }

    /// 执行一次设备定时器唤醒，并按设备的新需求重新排队。
    fn tick_device(&mut self, id: usize) {
        if let Some(device) = self.devices.get_mut(id) {
            let actions = device.tick(self.now_ms);
            self.apply_actions(id, actions);
        }
        self.schedule_wake(id);
    }

    /// 为设备排入下一次唤醒；没有定时任务就不再排队。
    fn schedule_wake(&mut self, id: usize) {
        if let Some(deadline) = self.devices.get(id).and_then(|d| d.next_deadline(self.now_ms)) {
            self.push_event(deadline, Event::Tick(id));
        }
    }

    pub fn advance_to(&mut self, target: u64) {
        let target = target.min(self.duration_ms);
        if target < self.now_ms {
            return;
        }
        while let Some(p) = self.pop_before(target) {
            self.now_ms = self.now_ms.max(p.at);
            match p.event {
                Event::Tick(id) => self.tick_device(id),
                Event::Pulse(id) => {
                    if let Some(device) = self.devices.get_mut(id) {
                        let actions = device.tick(self.now_ms);
                        self.apply_actions(id, actions);
                    }
                    let next = self.now_ms + self.tick_ms;
                    self.push_event(next, Event::Pulse(id));
                }
                Event::Deliver { to, bytes, from } => self.deliver(to, bytes, from),
                Event::LinkAck(id) => self.on_link_ack_timeout(id),
            }
        }
        self.now_ms = target;
        if self.now_ms >= self.duration_ms {
            self.finished = true;
        }
    }

    pub fn run(&mut self) {
        self.advance_to(self.duration_ms);
        self.finished = true;
    }

    /// 推进单个事件（用于面板的“步进”）。
    pub fn step_event(&mut self) -> bool {
        let Some(p) = self.pop_before(u64::MAX) else {
            return false;
        };
        self.now_ms = self.now_ms.max(p.at);
        match p.event {
            Event::Tick(id) => self.tick_device(id),
            Event::Pulse(id) => {
                if let Some(device) = self.devices.get_mut(id) {
                    let actions = device.tick(self.now_ms);
                    self.apply_actions(id, actions);
                }
                let next = self.now_ms + self.tick_ms;
                self.push_event(next, Event::Pulse(id));
            }
            Event::Deliver { to, bytes, from } => self.deliver(to, bytes, from),
            Event::LinkAck(id) => self.on_link_ack_timeout(id),
        }
        true
    }

    fn apply_actions(&mut self, from: usize, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::Send { to, frame } => {
                    // NFR-026：控制面帧先登记链路确认，超时按退避重传，最多 3 次。
                    // 广播帧不登记（多接收方聚合确认超出链路层职责）。
                    if frame.flags & idcell_core::consts::FLAG_NEEDACK != 0 && !to.is_broadcast() {
                        let id = self.next_link_id;
                        self.next_link_id += 1;
                        self.link_pending.insert(
                            id,
                            LinkPending {
                                from,
                                to,
                                frame: frame.clone(),
                                tries: 0,
                            },
                        );
                        let at = self.now_ms + LINK_ACK_TIMEOUT_MS;
                        self.push_event(at, Event::LinkAck(id));
                    }
                    self.route(from, to, frame)
                }
                Action::LogicWrite {
                    target,
                    index,
                    sub,
                    value,
                    intent,
                } => {
                    let from_name = self.devices[from].name.clone();
                    if let Some(ti) = self.resolve(&target) {
                        self.trace.push(TraceEntry::new(
                            self.now_ms,
                            "logic_write",
                            &from_name,
                            &target,
                            "WRITE",
                            format!("规则下发 {index}/{sub} = {value:.3}（{intent}）"),
                        ));
                        let did = self.devices[ti].did;
                        let actions =
                            self.devices[from].request_write(self.now_ms, did, index, sub, value, &intent);
                        self.apply_actions(from, actions);
                    } else {
                        self.trace.push(TraceEntry::new(
                            self.now_ms,
                            "logic_error",
                            &from_name,
                            &target,
                            "",
                            format!("规则目标设备 {target} 不存在"),
                        ));
                    }
                }
                Action::Trace { kind, peer, detail } => {
                    let from_name = self.devices[from].name.clone();
                    let to_name = self
                        .did_map
                        .get(&peer)
                        .map(|i| self.devices[*i].name.clone())
                        .unwrap_or_else(|| peer.to_hex());
                    self.trace.push(TraceEntry::new(
                        self.now_ms,
                        kind,
                        &from_name,
                        &to_name,
                        "",
                        detail,
                    ));
                }
            }
        }
    }

    /// 链路 ACK 超时：有界重传（指数退避），达上限则放弃并计数（NFR-026）。
    fn on_link_ack_timeout(&mut self, id: u64) {
        let Some(mut p) = self.link_pending.remove(&id) else {
            return;
        };
        let from_name = self.devices[p.from].name.clone();
        let to_name = self
            .did_map
            .get(&p.to)
            .map(|i| self.devices[*i].name.clone())
            .unwrap_or_else(|| p.to.to_hex());
        if p.tries >= LINK_MAX_RETX {
            self.metrics.link_drops += 1;
            self.trace.push(TraceEntry::new(
                self.now_ms,
                "link_drop",
                &from_name,
                &to_name,
                ftype::name(p.frame.frame_type),
                format!("链路重传 {} 次仍未确认，放弃", p.tries),
            ));
            return;
        }
        p.tries += 1;
        self.metrics.link_retx += 1;
        let backoff = LINK_ACK_TIMEOUT_MS * (1u64 << p.tries.min(3));
        self.trace.push(TraceEntry::new(
            self.now_ms,
            "link_retx",
            &from_name,
            &to_name,
            ftype::name(p.frame.frame_type),
            format!("未收到链路 ACK，第 {} 次重传", p.tries),
        ));
        let (from, to, frame) = (p.from, p.to, p.frame.clone());
        self.push_event(self.now_ms + backoff, Event::LinkAck(id));
        self.link_pending.insert(id, p);
        self.route(from, to, frame);
    }

    /// 链路 ACK 到达：清除与 (发送方, 对端, TXN) 匹配的待确认帧。
    fn clear_link_pending(&mut self, ack_from: Did, ack_to: Did, txn: u16) {
        self.link_pending.retain(|_, p| {
            !(p.to == ack_from && p.frame.src == ack_to && p.frame.txn == txn)
        });
        self.metrics.link_acks += 1;
    }

    fn link_index(&self, a: usize, b: usize) -> Option<usize> {
        self.links.iter().position(|l| l.connects(a, b))
    }

    fn link_config(&self, a: usize, b: usize) -> (LinkConfig, bool) {
        match self.link_index(a, b) {
            Some(i) => (self.links[i].cfg.clone(), self.links[i].partitioned),
            None => (self.default_link.clone(), false),
        }
    }

    fn route(&mut self, from: usize, to: Did, frame: Frame) {
        let targets: Vec<usize> = if to.is_broadcast() {
            self.broadcast_targets(from, None, frame.group, frame.frame_type == ftype::GROUP)
        } else {
            match self.did_map.get(&to) {
                Some(i) if *i != from => vec![*i],
                _ => Vec::new(),
            }
        };
        if targets.is_empty() {
            return;
        }
        let from_name = self.devices[from].name.clone();
        let key = self.devices[from].key.clone();
        let ft = frame.frame_type;
        let seq = frame.seq;
        let bytes = match frame.encode_with_key(Some(&key)) {
            Ok(b) => b,
            Err(e) => {
                self.trace.push(TraceEntry::new(
                    self.now_ms,
                    "encode_error",
                    &from_name,
                    "",
                    ftype::name(ft),
                    format!("帧编码失败：{e}"),
                ));
                return;
            }
        };
        let mut hex = String::with_capacity(bytes.len() * 2);
        for b in &bytes {
            hex.push_str(&format!("{b:02X}"));
        }
        let to_label = if to.is_broadcast() {
            "*".to_string()
        } else {
            targets
                .iter()
                .map(|t| self.devices[*t].name.clone())
                .collect::<Vec<_>>()
                .join(",")
        };
        if self.frames.len() >= 300 {
            self.frames.pop_front();
        }
        self.frames.push_back(FrameView {
            t_ms: self.now_ms,
            from: from_name.clone(),
            to: to_label,
            ftype: ftype::name(ft).to_string(),
            seq,
            len: bytes.len(),
            hex,
        });

        for target in targets {
            if to.is_broadcast() {
                self.emit_direct(from, target, &frame, &bytes);
            } else {
                self.emit_unicast(from, target, &frame, &bytes);
            }
        }
    }

    /// 广播目标：除自己、可选排除上一跳之外，同组且满足连线约束的设备。
    ///
    /// `strict_group=true` 仅用于 GROUP 帧：组播必须精确投递给 group_id 成员，
    /// 组外设备（含未分组设备）不得收到（FR-070）。
    fn broadcast_targets(
        &self,
        from: usize,
        exclude: Option<usize>,
        group: u16,
        strict_group: bool,
    ) -> Vec<usize> {
        self.devices
            .iter()
            .enumerate()
            .filter(|(i, d)| {
                let in_group = if strict_group {
                    d.group == group
                } else {
                    group == 0 || d.group == group || d.group == 0
                };
                *i != from
                    && Some(*i) != exclude
                    && in_group
                    && (!self.require_link || self.link_index(from, *i).is_some())
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// 直连投递：现有单跳语义（隔离/MTU/丢包/带宽/重复帧）。
    fn emit_direct(&mut self, from: usize, target: usize, frame: &Frame, bytes: &[u8]) {
        let from_name = self.devices[from].name.clone();
        let to_name = self.devices[target].name.clone();
        let ft = frame.frame_type;
        if self.require_link && self.link_index(from, target).is_none() {
            self.metrics.drops += 1;
            self.trace.push(TraceEntry::new(
                self.now_ms,
                "drop",
                &from_name,
                &to_name,
                ftype::name(ft),
                "两者之间没有显式连线，帧被丢弃".to_string(),
            ));
            return;
        }
        let Some(delay) = self.hop_plan(from, target, bytes.len(), ft, &from_name, &to_name) else {
            return;
        };
        self.trace.push(TraceEntry {
            t_ms: self.now_ms,
            kind: "tx".into(),
            from: from_name.clone(),
            to: to_name,
            ftype: ftype::name(ft).into(),
            seq: frame.seq,
            detail: format!("{} B，链路时延 {} ms", bytes.len(), delay),
        });
        self.push_event(
            self.now_ms + delay,
            Event::Deliver {
                to: target,
                bytes: bytes.to_vec(),
                from: Some(from),
            },
        );
        self.maybe_duplicate(from, target, frame, bytes, delay, &from_name);
    }

    /// 定向单播：直连优先，否则沿“允许中继”的网关多跳转发。
    fn emit_unicast(&mut self, from: usize, target: usize, frame: &Frame, bytes: &[u8]) {
        if !self.require_link || self.link_index(from, target).is_some() {
            self.emit_direct(from, target, frame, bytes);
            return;
        }
        let max_hops = self.max_hops as usize;
        match self.find_relay_path(from, target, max_hops) {
            Some(path) => self.emit_relay_path(&path, frame, bytes),
            None => {
                self.metrics.drops += 1;
                self.trace.push(TraceEntry::new(
                    self.now_ms,
                    "no_route",
                    &self.devices[from].name.clone(),
                    &self.devices[target].name.clone(),
                    ftype::name(frame.frame_type),
                    format!("无直连且找不到可用中继路径（上限 {max_hops} 跳）"),
                ));
            }
        }
    }

    /// 多跳：逐跳计入链路指标与累计时延，最后一次性投递到终点。
    fn emit_relay_path(&mut self, path: &[usize], frame: &Frame, bytes: &[u8]) {
        let mut total = 0u64;
        for w in path.windows(2) {
            let (a, b) = (w[0], w[1]);
            let from_name = self.devices[a].name.clone();
            let to_name = self.devices[b].name.clone();
            let Some(delay) =
                self.hop_plan(a, b, bytes.len(), frame.frame_type, &from_name, &to_name)
            else {
                return;
            };
            self.trace.push(TraceEntry {
                t_ms: self.now_ms + total,
                kind: "tx".into(),
                from: from_name,
                to: to_name,
                ftype: ftype::name(frame.frame_type).into(),
                seq: frame.seq,
                detail: format!("{} B，中继跳时延 {} ms", bytes.len(), delay),
            });
            total += delay;
        }
        for node in &path[1..path.len() - 1] {
            self.trace.push(TraceEntry::new(
                self.now_ms,
                "relay",
                &self.devices[*node].name.clone(),
                "",
                ftype::name(frame.frame_type),
                "作为网关转发（多跳）".to_string(),
            ));
        }
        let dest = *path.last().unwrap();
        self.push_event(
            self.now_ms + total,
            Event::Deliver {
                to: dest,
                bytes: bytes.to_vec(),
                from: path.get(path.len() - 2).copied(),
            },
        );
    }

    /// 单跳链路处理：隔离 / MTU / 丢包 / 时延抖动 / 重排 / 带宽排队 + 指标。
    fn hop_plan(
        &mut self,
        a: usize,
        b: usize,
        len: usize,
        ft: u8,
        from_name: &str,
        to_name: &str,
    ) -> Option<u64> {
        let (cfg, partitioned) = self.link_config(a, b);
        if partitioned {
            self.count_drop(a, b);
            self.trace.push(TraceEntry::new(
                self.now_ms,
                "drop",
                from_name,
                to_name,
                ftype::name(ft),
                "链路隔离，帧被丢弃".to_string(),
            ));
            return None;
        }
        // 支持分段/重组的介质（CAN/串口/USB 等）按整帧语义传递，
        // 只有超过协议最大帧才丢弃；其它介质按链路 MTU 判定。
        let frame_limit = if cfg.segment {
            idcell_core::consts::MAX_FRAME
        } else if cfg.mtu > 0 {
            cfg.mtu as usize
        } else {
            usize::MAX
        };
        if len > frame_limit {
            self.count_drop(a, b);
            self.trace.push(TraceEntry::new(
                self.now_ms,
                "drop",
                from_name,
                to_name,
                ftype::name(ft),
                format!(
                    "{} {} 不足，帧长 {}",
                    if cfg.segment { "协议最大帧" } else { "链路 MTU" },
                    frame_limit,
                    len
                ),
            ));
            return None;
        }
        if self.rng.chance_ppm(cfg.loss_ppm) {
            self.count_drop(a, b);
            self.trace.push(TraceEntry::new(
                self.now_ms,
                "drop",
                from_name,
                to_name,
                ftype::name(ft),
                format!("链路丢包（loss={} ppm）", cfg.loss_ppm),
            ));
            return None;
        }
        let mut delay = cfg.delay_ms as u64;
        if cfg.jitter_ms > 0 {
            delay += self.rng.range_u32(0, cfg.jitter_ms) as u64;
        }
        if cfg.host_proxy {
            delay += 1;
        }
        if cfg.reorder_ppm > 0 && self.rng.chance_ppm(cfg.reorder_ppm) {
            let extra = self.rng.range_u32(5, 20) as u64;
            delay += extra;
            self.metrics.link_extra_ms += extra;
        }
        let from_is_a = match self.link_index(a, b) {
            Some(i) => self.links[i].a == a,
            None => true,
        };
        let kbps = cfg.bandwidth_for(from_is_a) as u64;
        if kbps > 0 {
            let bits = len as u64 * 8;
            let tx_ms = bits.div_ceil(kbps).max(1);
            let free = self.serial.get(&(a, b)).copied().unwrap_or(0);
            let start = self.now_ms.max(free);
            let queued = start.saturating_sub(self.now_ms);
            self.metrics.link_queue_ms += queued;
            self.serial.insert((a, b), start + tx_ms);
            delay += queued + tx_ms;
        }
        self.metrics.frames_tx += 1;
        self.metrics.bytes_tx += len as u64;
        *self.type_counts.entry(ft).or_insert(0) += 1;
        if let Some(li) = self.link_index(a, b) {
            self.links[li].frames += 1;
            self.links[li].bytes += len as u64;
        }
        Some(delay)
    }

    fn count_drop(&mut self, a: usize, b: usize) {
        self.metrics.drops += 1;
        if let Some(li) = self.link_index(a, b) {
            self.links[li].dropped += 1;
        }
    }

    fn maybe_duplicate(
        &mut self,
        from: usize,
        target: usize,
        frame: &Frame,
        bytes: &[u8],
        delay: u64,
        from_name: &str,
    ) {
        let (cfg, _) = self.link_config(from, target);
        if self.rng.chance_ppm(cfg.dup_ppm) {
            self.metrics.duplicated += 1;
            if let Some(li) = self.link_index(from, target) {
                self.links[li].duplicated += 1;
            }
            let to_name = self.devices[target].name.clone();
            self.trace.push(TraceEntry::new(
                self.now_ms,
                "duplicate",
                from_name,
                &to_name,
                ftype::name(frame.frame_type),
                "链路重复帧".to_string(),
            ));
            self.push_event(
                self.now_ms + delay + 1,
                Event::Deliver {
                    to: target,
                    bytes: bytes.to_vec(),
                    from: Some(from),
                },
            );
        }
    }

    /// 在显式链路图上 BFS 找路；中间节点必须允许中继。
    fn find_relay_path(&self, from: usize, to: usize, max_hops: usize) -> Option<Vec<usize>> {
        if from == to {
            return None;
        }
        let mut prev: BTreeMap<usize, usize> = BTreeMap::new();
        let mut visited: BTreeSet<usize> = BTreeSet::new();
        let mut queue: VecDeque<usize> = VecDeque::new();
        visited.insert(from);
        queue.push_back(from);
        while let Some(cur) = queue.pop_front() {
            for n in self.neighbors(cur) {
                if visited.contains(&n) {
                    continue;
                }
                let is_dest = n == to;
                if !is_dest && !self.devices[n].relay {
                    continue;
                }
                visited.insert(n);
                prev.insert(n, cur);
                if is_dest {
                    let mut path = vec![n];
                    let mut c = n;
                    while let Some(&p) = prev.get(&c) {
                        path.push(p);
                        c = p;
                    }
                    path.reverse();
                    return if path.len() - 1 <= max_hops {
                        Some(path)
                    } else {
                        None
                    };
                }
                queue.push_back(n);
            }
        }
        None
    }

    fn neighbors(&self, i: usize) -> Vec<usize> {
        let mut out = Vec::new();
        for l in &self.links {
            if l.partitioned {
                continue;
            }
            if l.a == i {
                out.push(l.b);
            } else if l.b == i {
                out.push(l.a);
            }
        }
        out
    }

    fn deliver(&mut self, to: usize, bytes: Vec<u8>, prev: Option<usize>) {
        let key = self.devices[to].key.clone();
        let name = self.devices[to].name.clone();
        match Frame::decode_with_key(&bytes, Some(&key)) {
            Ok((frame, _)) => {
                if !frame.dst.is_broadcast() && frame.dst != self.devices[to].did {
                    return;
                }
                // 链路级 ACK：清除匹配的待确认帧，避免无谓重传。
                if frame.frame_type == ftype::ACK && has_link_ack(&frame.payload) {
                    self.clear_link_pending(frame.src, frame.dst, frame.txn);
                }
                self.metrics.frames_rx += 1;
                self.metrics.bytes_rx += bytes.len() as u64;
                if frame.frame_type == ftype::EVENT && frame.ts_us > 0 {
                    let sent_ms = frame.ts_us / 1000;
                    let lat = self.now_ms.saturating_sub(sent_ms);
                    self.metrics.latency_samples += 1;
                    self.metrics.latency_sum_ms += lat;
                    self.metrics.latency_sum_sq += (lat * lat) as f64;
                    self.metrics.latency_max_ms = self.metrics.latency_max_ms.max(lat);
                    let bucket = (lat as usize).min(self.metrics.latency_hist.len() - 1);
                    self.metrics.latency_hist[bucket] += 1;
                }
                let from_name = self
                    .did_map
                    .get(&frame.src)
                    .map(|i| self.devices[*i].name.clone())
                    .unwrap_or_else(|| frame.src.to_hex());
                self.trace.push(TraceEntry {
                    t_ms: self.now_ms,
                    kind: "rx".into(),
                    from: from_name,
                    to: name,
                    ftype: ftype::name(frame.frame_type).into(),
                    seq: frame.seq,
                    detail: format!("{} B", bytes.len()),
                });
                let is_flood = frame.dst.is_broadcast() && self.devices[to].relay;
                let flood_frame = if is_flood { Some(frame.clone()) } else { None };
                let actions = self.devices[to].on_frame(self.now_ms, frame);
                self.apply_actions(to, actions);
                // 收到帧可能新建会话/改变状态，需要重算该设备的定时器
                self.schedule_wake(to);
                // 中继设备继续把广播帧扩散出去（去重 + 递减 HOP_LIMIT）。
                if let Some(f) = flood_frame {
                    self.flood_forward(to, &f, prev);
                }
            }
            Err(e) => {
                self.metrics.crc_errors += 1;
                let from_name = "unknown".to_string();
                self.trace.push(TraceEntry::new(
                    self.now_ms,
                    "decode_error",
                    &from_name,
                    &name,
                    "",
                    format!("{}（{} B）", e.label(), bytes.len()),
                ));
            }
        }
    }

    /// 中继节点转发广播帧：递减 HOP_LIMIT、(src,seq,query_id) 去重、排除回程。
    fn flood_forward(&mut self, node: usize, frame: &Frame, prev: Option<usize>) {
        let Some((payload, remaining)) = decrement_hop_limit(&frame.payload, self.max_hops) else {
            self.trace.push(TraceEntry::new(
                self.now_ms,
                "hop_limit",
                &self.devices[node].name.clone(),
                "",
                ftype::name(frame.frame_type),
                "HOP_LIMIT 已耗尽，停止洪泛".to_string(),
            ));
            return;
        };
        let key = (frame.src, frame.seq, query_id_of(&frame.payload));
        if let Some(t) = self.flood_seen.get(&key) {
            if self.now_ms.saturating_sub(*t) < 3000 {
                return;
            }
        }
        self.flood_seen.insert(key, self.now_ms);
        if self.flood_seen.len() > 4096 {
            let cutoff = self.now_ms.saturating_sub(10_000);
            self.flood_seen.retain(|_, t| *t >= cutoff);
        }

        let mut nf = frame.clone();
        nf.payload = payload;
        let targets =
            self.broadcast_targets(node, prev, nf.group, nf.frame_type == ftype::GROUP);
        if targets.is_empty() {
            return;
        }
        let key_bytes = self.devices[node].key.clone();
        let Ok(bytes) = nf.encode_with_key(Some(&key_bytes)) else {
            return;
        };
        let names: Vec<String> = targets
            .iter()
            .map(|t| self.devices[*t].name.clone())
            .collect();
        self.trace.push(TraceEntry::new(
            self.now_ms,
            "relay_flood",
            &self.devices[node].name.clone(),
            &names.join(","),
            ftype::name(nf.frame_type),
            format!("洪泛转发到 {} 个邻居（剩余跳数 {}）", targets.len(), remaining),
        ));
        for t in targets {
            self.emit_direct(node, t, &nf, &bytes);
        }
    }

    // ------------------------------------------------------------ 故障注入与外部操作

    pub fn set_partition(&mut self, a: &str, b: &str, on: bool) -> bool {
        let (Some(ia), Some(ib)) = (self.resolve(a), self.resolve(b)) else {
            return false;
        };
        if let Some(i) = self.link_index(ia, ib) {
            self.links[i].partitioned = on;
        } else {
            let mut link = Link::new(ia, ib, self.default_link.clone());
            link.partitioned = on;
            self.links.push(link);
        }
        self.trace.push(TraceEntry::new(
            self.now_ms,
            if on { "partition" } else { "repair" },
            a,
            b,
            "",
            if on {
                "链路隔离".to_string()
            } else {
                "链路恢复".to_string()
            },
        ));
        true
    }

    pub fn set_device_publishing(&mut self, name: &str, on: bool) -> bool {
        if let Some(i) = self.resolve(name) {
            self.devices[i].publishing = on;
            let label = if on { "恢复发布" } else { "停止发布" };
            self.trace
                .push(TraceEntry::new(self.now_ms, "fault", name, "", "", label.to_string()));
            self.schedule_wake(i);
            true
        } else {
            false
        }
    }

    pub fn set_device_asleep(&mut self, name: &str, on: bool) -> bool {
        if let Some(i) = self.resolve(name) {
            self.devices[i].set_asleep(on);
            let label = if on { "进入休眠" } else { "唤醒" };
            self.trace
                .push(TraceEntry::new(self.now_ms, "fault", name, "", "", label.to_string()));
            self.schedule_wake(i);
            true
        } else {
            false
        }
    }

    pub fn set_device_rx(&mut self, name: &str, on: bool) -> bool {
        if let Some(i) = self.resolve(name) {
            self.devices[i].set_rx_on(on);
            let label = if on { "打开接收机" } else { "关闭接收机" };
            self.trace
                .push(TraceEntry::new(self.now_ms, "fault", name, "", "", label.to_string()));
            self.schedule_wake(i);
            true
        } else {
            false
        }
    }

    /// 电源开关：断电后设备停止收发与所有定时行为。
    pub fn set_device_power(&mut self, name: &str, on: bool) -> bool {
        if let Some(i) = self.resolve(name) {
            self.devices[i].set_power(on);
            let label = if on { "上电" } else { "断电" };
            self.trace
                .push(TraceEntry::new(self.now_ms, "fault", name, "", "", label.to_string()));
            self.schedule_wake(i);
            true
        } else {
            false
        }
    }

    pub fn request_read(&mut self, consumer: &str, provider: &str, index: u16, sub: u8) -> bool {
        let (Some(ci), Some(pi)) = (self.resolve(consumer), self.resolve(provider)) else {
            return false;
        };
        let peer = self.devices[pi].did;
        let actions = self.devices[ci].request_read(self.now_ms, peer, index, sub);
        self.apply_actions(ci, actions);
        true
    }

    pub fn request_write(
        &mut self,
        consumer: &str,
        provider: &str,
        index: u16,
        sub: u8,
        value: f64,
        intent: &str,
    ) -> bool {
        let (Some(ci), Some(pi)) = (self.resolve(consumer), self.resolve(provider)) else {
            return false;
        };
        let peer = self.devices[pi].did;
        let actions = self.devices[ci].request_write(self.now_ms, peer, index, sub, value, intent);
        self.apply_actions(ci, actions);
        true
    }

    /// 面板写值（开关 / 加减调节）。
    ///
    /// 优先挑一台与该提供者已处于 ACTIVE 的消费者，按协议发 WRITE（带 owner_token）；
    /// 现场没有在线控制器时退化为上位机本地置值，并在事件流里留下 `panel_write` 记录。
    /// 直接向设备注入一帧原始帧，用于验证未知类型/未支持标志的拒绝路径。
    pub fn inject_raw_frame(&mut self, device: &str, peer: &str, ftype: u8, flags: u8) -> bool {
        let (Some(di), Some(pi)) = (self.resolve(device), self.resolve(peer)) else {
            return false;
        };
        let mut f = Frame::default();
        f.prof = self.devices[pi].prof;
        f.flags = flags;
        f.frame_type = ftype;
        f.seq = 1;
        f.txn = 1;
        f.src = self.devices[pi].did;
        f.dst = self.devices[di].did;
        f.ts_us = self.now_ms * 1000;
        let actions = self.devices[di].on_frame(self.now_ms, f);
        self.apply_actions(di, actions);
        true
    }

    pub fn panel_write(
        &mut self,
        provider: &str,
        index: u16,
        sub: u8,
        value: f64,
        intent: &str,
    ) -> Result<String, String> {
        let pi = self
            .resolve(provider)
            .ok_or_else(|| format!("设备 {provider} 不存在"))?;
        let name = self.devices[pi].name.clone();
        let did = self.devices[pi].did;
        if self.finished {
            return Err("仿真已结束，请重置后再写入".into());
        }
        let cap = self.devices[pi]
            .cap(index, sub)
            .cloned()
            .ok_or_else(|| format!("{name} 没有能力点 {index}/{sub}"))?;
        if !cap.writable() {
            return Err(format!("{name} 的能力点 {index}/{sub} 不可写"));
        }
        if value < cap.range.0 || value > cap.range.1 {
            return Err(format!(
                "值 {value} 超出量程 [{}, {}]",
                cap.range.0, cap.range.1
            ));
        }
        let controller = self.devices.iter().position(|d| {
            d.id != pi
                && d.sessions
                    .get(&did)
                    .map(|s| s.stage == Stage::Active && s.role == Role::Consumer)
                    .unwrap_or(false)
        });
        if let Some(ci) = controller {
            let ctrl = self.devices[ci].name.clone();
            let actions = self.devices[ci].request_write(
                self.now_ms,
                did,
                index,
                sub,
                value,
                intent,
            );
            self.apply_actions(ci, actions);
            return Ok(format!("{ctrl} → {name}：WRITE {index}/{sub} = {value:.3}"));
        }
        let p = self.devices[pi]
            .points
            .entry((index, sub))
            .or_insert(crate::device::PointState {
                value: 0.0,
                ts_ms: self.now_ms,
                quality: idcell_core::consts::quality::GOOD,
            });
        p.value = value;
        p.ts_ms = self.now_ms;
        p.quality = idcell_core::consts::quality::GOOD;
        self.trace.push(TraceEntry::new(
            self.now_ms,
            "panel_write",
            &name,
            "",
            "",
            format!("上位机本地置值 {index}/{sub} = {value:.3}（{intent}）"),
        ));
        Ok(format!("{name}：本地置值 {index}/{sub} = {value:.3}"))
    }

    /// 运行中重新协商发布周期（不改绑定）。
    pub fn request_renegotiate(&mut self, consumer: &str, provider: &str, want_ms: u32) -> bool {
        let (Some(ci), Some(pi)) = (self.resolve(consumer), self.resolve(provider)) else {
            return false;
        };
        let peer = self.devices[pi].did;
        let actions = self.devices[ci].request_renegotiate(self.now_ms, peer, want_ms);
        self.apply_actions(ci, actions);
        true
    }

    /// 运行中退订。
    pub fn request_unsubscribe(
        &mut self,
        consumer: &str,
        provider: &str,
        index: u16,
        sub: u8,
    ) -> bool {
        let (Some(ci), Some(pi)) = (self.resolve(consumer), self.resolve(provider)) else {
            return false;
        };
        let peer = self.devices[pi].did;
        let actions = self.devices[ci].request_unsubscribe(self.now_ms, peer, index, sub);
        self.apply_actions(ci, actions);
        true
    }

    /// 发起可靠/普通组播声明（FR-070）。
    pub fn request_group_declare(
        &mut self,
        device: &str,
        gid: u16,
        expected: &[&str],
        timeout_ms: u32,
        mode: u8,
        epoch: u32,
    ) -> bool {
        if self.finished {
            return false;
        }
        let Some(di) = self.resolve(device) else {
            return false;
        };
        let mut members = Vec::new();
        for name in expected {
            let Some(mi) = self.resolve(name) else {
                return false;
            };
            members.push(self.devices[mi].did);
        }
        let actions =
            self.devices[di].request_group_declare(self.now_ms, gid, members, timeout_ms, mode, epoch);
        self.apply_actions(di, actions);
        true
    }

    /// 发起 CONFIG 配置项修改（FR-065）。
    pub fn request_config(
        &mut self,
        device: &str,
        peer: &str,
        index: u16,
        sub: u8,
        new_perm: u8,
        intent: &str,
    ) -> bool {
        let (Some(ci), Some(pi)) = (self.resolve(device), self.resolve(peer)) else {
            return false;
        };
        let peer_did = self.devices[pi].did;
        let actions =
            self.devices[ci].request_config(self.now_ms, peer_did, index, sub, new_perm, intent);
        self.apply_actions(ci, actions);
        true
    }

    /// 发起入网/配网请求（PROVISION，SEC-025 HMAC 保护）。
    pub fn request_provision(
        &mut self,
        device: &str,
        peer: &str,
        gid: u16,
        intent: &str,
    ) -> bool {
        let (Some(ci), Some(pi)) = (self.resolve(device), self.resolve(peer)) else {
            return false;
        };
        let peer_did = self.devices[pi].did;
        let actions = self.devices[ci].request_provision(self.now_ms, peer_did, gid, intent);
        self.apply_actions(ci, actions);
        true
    }

    /// 下发命令（FR-039：CMD → ACK → DONE）。
    #[allow(clippy::too_many_arguments)]
    pub fn request_command(
        &mut self,
        device: &str,
        peer: &str,
        index: u16,
        sub: u8,
        exec_ms: u32,
        fail: bool,
        intent: &str,
    ) -> bool {
        let (Some(ci), Some(pi)) = (self.resolve(device), self.resolve(peer)) else {
            return false;
        };
        let peer_did = self.devices[pi].did;
        let actions = self.devices[ci].request_command(
            self.now_ms,
            peer_did,
            index,
            sub,
            exec_ms,
            fail,
            intent,
        );
        self.apply_actions(ci, actions);
        true
    }

    /// 发起查询（Zenoh 风格）：默认广播，`peer` 非空时定向到单个提供者。
    pub fn request_query(
        &mut self,
        device: &str,
        peer: &str,
        selector: &str,
        mode: u8,
        hop_limit: u32,
    ) -> bool {
        if self.finished {
            return false;
        }
        let Some(ci) = self.resolve(device) else {
            return false;
        };
        let target = if peer.is_empty() {
            Did::broadcast()
        } else {
            match self.resolve(peer) {
                Some(pi) => self.devices[pi].did,
                None => return false,
            }
        };
        let actions = self.devices[ci].request_query(self.now_ms, target, selector, mode, hop_limit);
        self.apply_actions(ci, actions);
        // 查询会话有自己的截止时间，必须让发起设备重新进入定时器。
        self.schedule_wake(ci);
        true
    }

    // ------------------------------------------------------------ 查询

    pub fn stage_of(&self, device: &str, peer: &str) -> Option<Stage> {
        let d = self.device(device)?;
        let p = self.device(peer)?;
        d.sessions.get(&p.did).map(|s| s.stage)
    }

    /// 设备协议档：0=STD，1=RT。
    pub fn device_prof(&self, device: &str) -> Option<u8> {
        self.device(device).map(|d| d.prof)
    }

    pub fn session_role(&self, device: &str, peer: &str) -> Option<Role> {
        let d = self.device(device)?;
        let p = self.device(peer)?;
        d.sessions.get(&p.did).map(|s| s.role)
    }

    pub fn received_value(&self, device: &str, index: u16, sub: u8) -> Option<(f64, bool, u8)> {
        let d = self.device(device)?;
        d.recv.get(&(index, sub)).map(|v| (v.value, v.stale, v.quality))
    }

    pub fn total_binds_ok(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.binds_ok).sum()
    }

    pub fn total_binds_fail(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.binds_fail).sum()
    }

    pub fn total_resumes_ok(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.resumes_ok).sum()
    }

    pub fn total_group_ok(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.group_ok).sum()
    }

    pub fn total_group_missing(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.group_missing).sum()
    }

    pub fn total_group_rejects(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.group_rejects).sum()
    }

    pub fn total_config_ok(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.config_ok).sum()
    }

    pub fn total_config_rejects(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.config_rejects).sum()
    }

    pub fn total_reneg_ok(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.reneg_ok).sum()
    }

    pub fn total_cmds_sent(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.cmds_sent).sum()
    }

    pub fn total_cmd_acks(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.cmd_acks).sum()
    }

    pub fn total_done_rx(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.done_rx).sum()
    }

    pub fn total_done_errors(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.done_errors).sum()
    }

    pub fn total_commands_rx(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.commands_rx).sum()
    }

    pub fn total_done_sent(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.done_sent).sum()
    }

    pub fn total_link_ack_tx(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.link_ack_tx).sum()
    }

    pub fn total_dup_drops(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.dup_drops).sum()
    }

    pub fn total_provision_sent(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.provision_sent).sum()
    }

    pub fn total_provision_ok(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.provision_ok).sum()
    }

    pub fn total_provision_rejects(&self) -> u64 {
        self.devices
            .iter()
            .map(|d| d.counters.provision_rejects)
            .sum()
    }

    pub fn total_desc_frag_tx(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.desc_frag_tx).sum()
    }

    pub fn total_desc_frag_rx(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.desc_frag_rx).sum()
    }

    pub fn total_desc_reassemble_ok(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.desc_reassemble_ok).sum()
    }

    pub fn total_desc_crc_errors(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.desc_crc_errors).sum()
    }

    pub fn total_desc_oversize(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.desc_oversize).sum()
    }

    /// 某设备对 peer 的会话是否走了描述缓存复用路径（FR-028）。
    pub fn session_resumed(&self, device: &str, peer: &str) -> bool {
        let Some(d) = self.device(device) else {
            return false;
        };
        let Some(p) = self.device(peer) else {
            return false;
        };
        d.sessions.get(&p.did).map(|s| s.resumed).unwrap_or(false)
    }

    pub fn total_stale_events(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.stale_events).sum()
    }

    pub fn total_timeouts(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.session_timeouts).sum()
    }

    pub fn total_writes_ok(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.writes_ok).sum()
    }

    pub fn total_writes_rejected(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.writes_rejected).sum()
    }

    pub fn total_events_rx(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.events_rx).sum()
    }

    pub fn frame_type_count(&self, name: &str) -> u64 {
        let typ = (1u8..=ftype::MAX_TYPE).find(|t| ftype::name(*t) == name);
        match typ {
            Some(t) => self.type_counts.get(&t).copied().unwrap_or(0),
            None => 0,
        }
    }

    pub fn total_queries_sent(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.queries_sent).sum()
    }

    pub fn total_replies_rx(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.replies_rx).sum()
    }

    pub fn total_queries_answered(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.queries_answered).sum()
    }

    pub fn total_query_timeouts(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.query_timeouts).sum()
    }

    pub fn total_logic_fired(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.logic_fired).sum()
    }

    pub fn total_proto_rejects(&self) -> u64 {
        self.devices.iter().map(|d| d.counters.proto_rejects).sum()
    }

    /// 某设备最近一次查询聚合到的应答条数（断言/接口用）。
    pub fn query_reply_count(&self, device: &str) -> u64 {
        self.device(device)
            .map(|d| d.queries.values().map(|q| q.replies.len() as u64).sum())
            .unwrap_or(0)
    }

    pub fn trace_jsonl(&self) -> String {
        let mut s = String::new();
        for e in self.trace.entries() {
            s.push_str(&e.to_json());
            s.push('\n');
        }
        s
    }

    pub fn snapshot(&self, max_trace: usize) -> Snapshot {
        let mut devices = Vec::new();
        for d in &self.devices {
            let sessions = d
                .sessions
                .iter()
                .map(|(peer, s)| SessionView {
                    peer: self
                        .did_map
                        .get(peer)
                        .map(|i| self.devices[*i].name.clone())
                        .unwrap_or_else(|| peer.to_hex()),
                    role: s.role.name(),
                    stage: s.stage.name(),
                    t_pub_ms: s.contract.as_ref().map(|c| c.t_pub_ms).unwrap_or(0),
                    stale: s.stale,
                    resumed: s.resumed,
                    error: s.error.map(|e| e.name().to_string()),
                })
                .collect();
            let mut values = Vec::new();
            for ((idx, sub), p) in &d.points {
                let label = d.cap(*idx, *sub).map(|c| c.label.clone()).unwrap_or_default();
                let (dtype, dir, (lo, hi)) = d
                    .cap(*idx, *sub)
                    .map(|c| (c.dtype, c.dir, c.range))
                    .unwrap_or((idcell_core::consts::dtype::F64, 1, (-1e9, 1e9)));
                let (value, stale, quality, at) = match d.recv.get(&(*idx, *sub)) {
                    Some(v) => (v.value, v.stale, v.quality, v.received_ms),
                    None => (p.value, false, p.quality, p.ts_ms),
                };
                values.push(ValueView {
                    index: *idx,
                    sub: *sub,
                    label,
                    dtype,
                    dir,
                    lo,
                    hi,
                    value,
                    quality,
                    stale,
                    age_ms: self.now_ms.saturating_sub(at),
                });
            }
            for ((idx, sub), v) in &d.recv {
                if d.points.contains_key(&(*idx, *sub)) {
                    continue;
                }
                let label = d.cap(*idx, *sub).map(|c| c.label.clone()).unwrap_or_default();
                let (dtype, dir, (lo, hi)) = d
                    .cap(*idx, *sub)
                    .map(|c| (c.dtype, c.dir, c.range))
                    .unwrap_or((idcell_core::consts::dtype::F64, 1, (-1e9, 1e9)));
                values.push(ValueView {
                    index: *idx,
                    sub: *sub,
                    label,
                    dtype,
                    dir,
                    lo,
                    hi,
                    value: v.value,
                    quality: v.quality,
                    stale: v.stale,
                    age_ms: self.now_ms.saturating_sub(v.received_ms),
                });
            }
            let mut queries = Vec::new();
            for q in d.queries.values() {
                let replies = q
                    .replies
                    .iter()
                    .map(|r| QueryReplyView {
                        from: self
                            .did_map
                            .get(&r.from)
                            .map(|i| self.devices[*i].name.clone())
                            .unwrap_or_else(|| r.from.to_hex()),
                        index: r.index,
                        sub: r.sub,
                        label: r.label.clone(),
                        value: r.value,
                        quality: r.quality,
                    })
                    .collect();
                queries.push(QueryView {
                    id: q.id,
                    selector: q.selector.clone(),
                    mode: idcell_core::consts::query_mode::name(q.mode),
                    replies,
                    expected: q.expected,
                    ended: q.ended,
                    done: q.done,
                    elapsed_ms: self.now_ms.saturating_sub(q.started_ms),
                });
            }
            devices.push(DeviceView {
                name: d.name.clone(),
                did: d.did.to_hex(),
                profile: device_profile(d),
                prof: d.prof,
                rules: d.rules.len(),
                presence: d.presence,
                awake: d.awake,
                rx_on: d.rx_on,
                powered: d.powered,
                caps: d.caps.len(),
                reqs: d.reqs.len(),
                publishing: d.publishing,
                relay: d.relay,
                sessions,
                values,
                queries,
                counters: d.counters.clone(),
                owner_token: d.owner.as_ref().map(|o| o.token).unwrap_or(0),
                owner_peer: d.owner.as_ref().map(|o| {
                    self.did_map
                        .get(&o.peer)
                        .map(|i| self.devices[*i].name.clone())
                        .unwrap_or_else(|| o.peer.to_hex())
                }),
            });
        }
        let links = self
            .links
            .iter()
            .map(|l| LinkView {
                a: self.devices.get(l.a).map(|d| d.name.clone()).unwrap_or_default(),
                b: self.devices.get(l.b).map(|d| d.name.clone()).unwrap_or_default(),
                media: l.cfg.media.clone(),
                topology: l.cfg.topology.clone(),
                delay_ms: l.cfg.delay_ms,
                loss_ppm: l.cfg.loss_ppm,
                uplink_kbps: l.cfg.uplink_kbps,
                downlink_kbps: l.cfg.downlink_kbps,
                mtu: l.cfg.mtu,
                segment: l.cfg.segment,
                baud: l.cfg.baud,
                partitioned: l.partitioned,
                frames: l.frames,
                dropped: l.dropped,
            })
            .collect();
        Snapshot {
            now_ms: self.now_ms,
            duration_ms: self.duration_ms,
            running: !self.finished,
            devices,
            links,
            metrics: self.metrics.clone(),
            trace_total: self.trace.total,
            trace: self.trace.recent(max_trace).to_vec(),
            frames: {
                let skip = self.frames.len().saturating_sub(40);
                self.frames.iter().skip(skip).cloned().collect()
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionView {
    pub peer: String,
    pub role: &'static str,
    pub stage: &'static str,
    pub t_pub_ms: u32,
    pub stale: bool,
    /// 是否经描述缓存复用恢复（FR-028）。
    pub resumed: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ValueView {
    pub index: u16,
    pub sub: u8,
    pub label: String,
    /// 数据类型（dtype 常量）
    pub dtype: u8,
    /// 1=r 2=w 3=rw
    pub dir: u8,
    pub lo: f64,
    pub hi: f64,
    pub value: f64,
    pub quality: u8,
    pub stale: bool,
    pub age_ms: u64,
}

#[derive(Debug, Clone)]
pub struct QueryReplyView {
    pub from: String,
    pub index: u16,
    pub sub: u8,
    pub label: String,
    pub value: f64,
    pub quality: u8,
}

#[derive(Debug, Clone)]
pub struct QueryView {
    pub id: u32,
    pub selector: String,
    pub mode: &'static str,
    pub replies: Vec<QueryReplyView>,
    pub expected: u32,
    pub ended: u32,
    pub done: bool,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone)]
pub struct DeviceView {
    pub name: String,
    pub did: String,
    /// 派生出的设备画像：sensor / actuator / controller / gateway / monitor / node
    pub profile: &'static str,
    /// 协议档：0=STD，1=RT。
    pub prof: u8,
    pub rules: usize,
    pub presence: u8,
    pub awake: bool,
    pub rx_on: bool,
    pub powered: bool,
    pub caps: usize,
    pub reqs: usize,
    pub publishing: bool,
    pub relay: bool,
    pub sessions: Vec<SessionView>,
    pub values: Vec<ValueView>,
    pub queries: Vec<QueryView>,
    pub counters: DeviceCounters,
    pub owner_token: u32,
    pub owner_peer: Option<String>,
}

/// 由通用设备模型派生画像：同一套点位/链路/协议之上，按能力组合区分角色。
fn device_profile(d: &Device) -> &'static str {
    if d.relay {
        "gateway"
    } else if !d.rules.is_empty() {
        "controller"
    } else if d.caps.iter().any(|c| c.writable()) {
        "actuator"
    } else if !d.caps.is_empty() && !d.sims.is_empty() {
        "sensor"
    } else if !d.caps.is_empty() {
        "device"
    } else if !d.reqs.is_empty() {
        "monitor"
    } else {
        "node"
    }
}

#[derive(Debug, Clone)]
pub struct LinkView {
    pub a: String,
    pub b: String,
    pub media: String,
    pub topology: String,
    pub delay_ms: u32,
    pub loss_ppm: u32,
    pub uplink_kbps: u32,
    pub downlink_kbps: u32,
    pub mtu: u16,
    pub segment: bool,
    pub baud: u32,
    pub partitioned: bool,
    pub frames: u64,
    pub dropped: u64,
}

#[derive(Debug, Clone)]
pub struct FrameView {
    pub t_ms: u64,
    pub from: String,
    pub to: String,
    pub ftype: String,
    pub seq: u16,
    pub len: usize,
    /// 整帧十六进制（含 SYNC/CRC/TRAILER），用于面板帧详情
    pub hex: String,
}

impl FrameView {
    fn to_json(&self) -> String {
        format!(
            "{{\"t\":{},\"from\":\"{}\",\"to\":\"{}\",\"type\":\"{}\",\"seq\":{},\"len\":{},\"hex\":\"{}\"}}",
            self.t_ms,
            json_escape(&self.from),
            json_escape(&self.to),
            json_escape(&self.ftype),
            self.seq,
            self.len,
            self.hex
        )
    }
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub now_ms: u64,
    pub duration_ms: u64,
    pub running: bool,
    pub devices: Vec<DeviceView>,
    pub links: Vec<LinkView>,
    pub metrics: Metrics,
    pub trace_total: u64,
    pub trace: Vec<TraceEntry>,
    pub frames: Vec<FrameView>,
}

impl Snapshot {
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(4096);
        s.push_str(&format!(
            "{{\"now_ms\":{},\"duration_ms\":{},\"running\":{},\"trace_total\":{},",
            self.now_ms, self.duration_ms, self.running, self.trace_total
        ));
        s.push_str("\"metrics\":{");
        s.push_str(&format!(
            "\"frames_tx\":{},\"frames_rx\":{},\"bytes_tx\":{},\"bytes_rx\":{},\"drops\":{},\"duplicated\":{},\"crc_errors\":{},\"latency_samples\":{},\"avg_latency_ms\":{},\"max_latency_ms\":{},\"p50_latency_ms\":{},\"p95_latency_ms\":{},\"p99_latency_ms\":{},\"jitter_ms\":{},\"throughput_kbps\":{},\"queue_ms\":{},\"link_retx\":{},\"link_acks\":{},\"link_drops\":{}",
            self.metrics.frames_tx,
            self.metrics.frames_rx,
            self.metrics.bytes_tx,
            self.metrics.bytes_rx,
            self.metrics.drops,
            self.metrics.duplicated,
            self.metrics.crc_errors,
            self.metrics.latency_samples,
            json_num(round2(self.metrics.avg_latency_ms())),
            self.metrics.latency_max_ms,
            json_num(round2(self.metrics.percentile_ms(0.50))),
            json_num(round2(self.metrics.percentile_ms(0.95))),
            json_num(round2(self.metrics.percentile_ms(0.99))),
            json_num(round2(self.metrics.jitter_ms())),
            json_num(round2(self.metrics.throughput_kbps(self.now_ms.max(1)))),
            self.metrics.link_queue_ms,
            self.metrics.link_retx,
            self.metrics.link_acks,
            self.metrics.link_drops
        ));
        s.push_str("},\"devices\":[");
        for (i, d) in self.devices.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&format!(
                "{{\"name\":\"{}\",\"did\":\"{}\",\"profile\":\"{}\",\"prof\":{},\"rules\":{},\"presence\":{},\"awake\":{},\"rx_on\":{},\"powered\":{},\"caps\":{},\"reqs\":{},\"publishing\":{},\"relay\":{},\"owner_token\":{},\"owner_peer\":{},",
                json_escape(&d.name),
                d.did,
                d.profile,
                d.prof,
                d.rules,
                d.presence,
                d.awake,
                d.rx_on,
                d.powered,
                d.caps,
                d.reqs,
                d.publishing,
                d.relay,
                d.owner_token,
                match &d.owner_peer {
                    Some(p) => format!("\"{}\"", json_escape(p)),
                    None => "null".into(),
                }
            ));
            s.push_str("\"sessions\":[");
            for (j, sess) in d.sessions.iter().enumerate() {
                if j > 0 {
                    s.push(',');
                }
                s.push_str(&format!(
                    "{{\"peer\":\"{}\",\"role\":\"{}\",\"stage\":\"{}\",\"t_pub_ms\":{},\"stale\":{},\"resumed\":{},\"error\":{}}}",
                    json_escape(&sess.peer),
                    sess.role,
                    sess.stage,
                    sess.t_pub_ms,
                    sess.stale,
                    sess.resumed,
                    match &sess.error {
                        Some(e) => format!("\"{}\"", json_escape(e)),
                        None => "null".into(),
                    }
                ));
            }
            s.push_str("],\"values\":[");
            for (j, v) in d.values.iter().enumerate() {
                if j > 0 {
                    s.push(',');
                }
                s.push_str(&format!(
                    "{{\"index\":{},\"sub\":{},\"label\":\"{}\",\"dtype\":\"{}\",\"dir\":{},\"lo\":{},\"hi\":{},\"value\":{},\"quality\":{},\"stale\":{},\"age_ms\":{}}}",
                    v.index,
                    v.sub,
                    json_escape(&v.label),
                    idcell_core::consts::dtype::name(v.dtype),
                    v.dir,
                    json_num(v.lo),
                    json_num(v.hi),
                    json_num(round3(v.value)),
                    v.quality,
                    v.stale,
                    v.age_ms
                ));
            }
            s.push_str("],\"counters\":{");
            s.push_str(&format!(
                "\"tx\":{},\"rx\":{},\"binds_ok\":{},\"binds_fail\":{},\"retries\":{},\"stale_events\":{},\"session_timeouts\":{},\"writes_ok\":{},\"writes_rejected\":{},\"events_rx\":{},\"asleep_drops\":{},\"queries_sent\":{},\"replies_rx\":{},\"queries_answered\":{},\"query_timeouts\":{},\"proto_rejects\":{},\"resumes_ok\":{},\"group_rounds\":{},\"group_ok\":{},\"group_missing\":{},\"group_rejects\":{},\"config_ok\":{},\"config_rejects\":{},\"reneg_sent\":{},\"reneg_ok\":{},\"cmds_sent\":{},\"commands_rx\":{},\"cmd_acks\":{},\"done_sent\":{},\"done_rx\":{},\"done_errors\":{},\"cmd_rejects\":{},\"link_ack_tx\":{},\"dup_drops\":{},\"provision_sent\":{},\"provision_ok\":{},\"provision_rejects\":{},\"desc_frag_tx\":{},\"desc_frag_rx\":{},\"desc_reassemble_ok\":{},\"desc_crc_errors\":{},\"desc_oversize\":{},\"logic_fired\":{}",
                d.counters.tx,
                d.counters.rx,
                d.counters.binds_ok,
                d.counters.binds_fail,
                d.counters.retries,
                d.counters.stale_events,
                d.counters.session_timeouts,
                d.counters.writes_ok,
                d.counters.writes_rejected,
                d.counters.events_rx,
                d.counters.asleep_drops,
                d.counters.queries_sent,
                d.counters.replies_rx,
                d.counters.queries_answered,
                d.counters.query_timeouts,
                d.counters.proto_rejects,
                d.counters.resumes_ok,
                d.counters.group_rounds,
                d.counters.group_ok,
                d.counters.group_missing,
                d.counters.group_rejects,
                d.counters.config_ok,
                d.counters.config_rejects,
                d.counters.reneg_sent,
                d.counters.reneg_ok,
                d.counters.cmds_sent,
                d.counters.commands_rx,
                d.counters.cmd_acks,
                d.counters.done_sent,
                d.counters.done_rx,
                d.counters.done_errors,
                d.counters.cmd_rejects,
                d.counters.link_ack_tx,
                d.counters.dup_drops,
                d.counters.provision_sent,
                d.counters.provision_ok,
                d.counters.provision_rejects,
                d.counters.desc_frag_tx,
                d.counters.desc_frag_rx,
                d.counters.desc_reassemble_ok,
                d.counters.desc_crc_errors,
                d.counters.desc_oversize,
                d.counters.logic_fired
            ));
            s.push_str("},\"queries\":[");
            for (j, q) in d.queries.iter().enumerate() {
                if j > 0 {
                    s.push(',');
                }
                s.push_str(&format!(
                    "{{\"id\":{},\"selector\":\"{}\",\"mode\":\"{}\",\"expected\":{},\"ended\":{},\"done\":{},\"elapsed_ms\":{},\"replies\":[",
                    q.id,
                    json_escape(&q.selector),
                    q.mode,
                    q.expected,
                    q.ended,
                    q.done,
                    q.elapsed_ms
                ));
                for (k, r) in q.replies.iter().enumerate() {
                    if k > 0 {
                        s.push(',');
                    }
                    s.push_str(&format!(
                        "{{\"from\":\"{}\",\"index\":{},\"sub\":{},\"label\":\"{}\",\"value\":{},\"quality\":{}}}",
                        json_escape(&r.from),
                        r.index,
                        r.sub,
                        json_escape(&r.label),
                        json_num(round3(r.value)),
                        r.quality
                    ));
                }
                s.push(']');
                s.push('}');
            }
            s.push_str("]}");
        }
        s.push_str("],\"links\":[");
        for (i, l) in self.links.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&format!(
                "{{\"a\":\"{}\",\"b\":\"{}\",\"media\":\"{}\",\"topology\":\"{}\",\"delay_ms\":{},\"loss_ppm\":{},\"uplink_kbps\":{},\"downlink_kbps\":{},\"mtu\":{},\"segment\":{},\"baud\":{},\"partitioned\":{},\"frames\":{},\"dropped\":{}}}",
                json_escape(&l.a),
                json_escape(&l.b),
                json_escape(&l.media),
                json_escape(&l.topology),
                l.delay_ms,
                l.loss_ppm,
                l.uplink_kbps,
                l.downlink_kbps,
                l.mtu,
                l.segment,
                l.baud,
                l.partitioned,
                l.frames,
                l.dropped
            ));
        }
        s.push_str("],\"trace\":[");
        for (i, t) in self.trace.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&t.to_json());
        }
        s.push_str("],\"frames\":[");
        for (i, f) in self.frames.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&f.to_json());
        }
        s.push_str("]}");
        s
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

/// 把帧载荷里的 HOP_LIMIT 减一；耗尽（<=1）返回 None。
/// 缺失时按 `max_hops` 视为初始值。
fn decrement_hop_limit(payload: &[u8], max_hops: u8) -> Option<(Vec<u8>, u32)> {
    let tlvs = decode_tlvs(payload).ok()?;
    let mut found = false;
    let mut remaining = 0u32;
    let mut w = TlvWriter::new();
    for t in &tlvs {
        if t.typ == tlv_type::HOP_LIMIT {
            found = true;
            let v = t.as_u32().unwrap_or(max_hops as u32);
            if v <= 1 {
                return None;
            }
            remaining = v - 1;
            let _ = w.raw_put(t.idx, t.sub, t.typ, &remaining.to_be_bytes());
        } else {
            let _ = w.raw_put(t.idx, t.sub, t.typ, &t.value);
        }
    }
    if !found {
        if max_hops <= 1 {
            return None;
        }
        remaining = max_hops as u32 - 1;
        let _ = w.raw_put(0, 0, tlv_type::HOP_LIMIT, &remaining.to_be_bytes());
    }
    Some((w.finish(), remaining))
}

fn query_id_of(payload: &[u8]) -> u32 {
    decode_tlvs(payload)
        .ok()
        .and_then(|tlvs| {
            tlvs.iter()
                .find(|t| t.typ == tlv_type::QUERY_ID)
                .and_then(|t| t.as_u32())
        })
        .unwrap_or(0)
}

/// 判断 ACK 帧是否携带链路级确认标记（与业务 ACK 区分）。
fn has_link_ack(payload: &[u8]) -> bool {
    decode_tlvs(payload)
        .map(|tlvs| tlvs.iter().any(|t| t.typ == tlv_type::LINK_ACK))
        .unwrap_or(false)
}
