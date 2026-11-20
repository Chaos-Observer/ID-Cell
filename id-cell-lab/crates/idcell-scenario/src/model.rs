//! 场景模型与 JSON 映射。

use crate::json::{parse, Json};
use idcell_core::{consts::qty, Did};
use idcell_engine::{
    AlarmDef, DeviceSpec, LinkConfig, LogicKind, LogicRule, PointSim, RunMode, World, WorldConfig,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct LinkSpec {
    pub delay_ms: u32,
    pub jitter_ms: u32,
    pub loss_ppm: u32,
    pub dup_ppm: u32,
    pub reorder_ppm: u32,
    pub host_proxy: bool,
    pub mtu: u16,
    pub media: String,
    pub topology: String,
    pub t_link_min_ms: u32,
    pub uplink_kbps: u32,
    pub downlink_kbps: u32,
    pub segment: bool,
    /// 串口/CAN 的物理波特率/位速率；0 表示不适用。
    pub baud: u32,
    /// 主从轮询窗口（ms）；>0 启用半双工点名语义。
    pub poll_ms: u32,
    /// 半双工收发转向时间（ms）。
    pub turnaround_ms: u32,
    /// 帧间最小静默（ms）。
    pub inter_frame_ms: u32,
    /// 半双工自发自收。
    pub echo: bool,
}

impl Default for LinkSpec {
    fn default() -> Self {
        LinkSpec {
            delay_ms: 1,
            jitter_ms: 0,
            loss_ppm: 0,
            dup_ppm: 0,
            reorder_ppm: 0,
            host_proxy: false,
            mtu: 0,
            media: "loopback".into(),
            topology: "p2p".into(),
            t_link_min_ms: 1,
            uplink_kbps: 0,
            downlink_kbps: 0,
            segment: false,
            baud: 0,
            poll_ms: 0,
            turnaround_ms: 0,
            inter_frame_ms: 0,
            echo: false,
        }
    }
}

impl LinkSpec {
    pub fn to_link_config(&self) -> LinkConfig {
        LinkConfig {
            delay_ms: self.delay_ms,
            jitter_ms: self.jitter_ms,
            loss_ppm: self.loss_ppm,
            dup_ppm: self.dup_ppm,
            reorder_ppm: self.reorder_ppm,
            host_proxy: self.host_proxy,
            mtu: self.mtu,
            media: self.media.clone(),
            topology: self.topology.clone(),
            t_link_min_ms: self.t_link_min_ms,
            uplink_kbps: self.uplink_kbps,
            downlink_kbps: self.downlink_kbps,
            segment: self.segment,
            baud: self.baud,
            poll_ms: self.poll_ms,
            turnaround_ms: self.turnaround_ms,
            inter_frame_ms: self.inter_frame_ms,
            echo: self.echo,
        }
    }

    /// 先取媒体预设，再用场景里显式写的字段覆盖。
    fn parse(v: &Json) -> LinkSpec {
        let media = v.str_field("media").unwrap_or_else(|| "loopback".into());
        let p = LinkConfig::media_preset(&media);
        let baud = v.u64_field("baud").unwrap_or(p.baud as u64) as u32;
        // 串口按 8N1 折算有效带宽；CAN 按位速率折算（500 kbit/s ≈ 50 KB/s）。
        let serial_rate = if (media == "uart" || media == "rs485") && baud > 0 {
            ((baud as f64 * 0.8 / 1000.0).round() as u32).max(1)
        } else if media == "can" && baud > 0 {
            (baud / 1000).max(1)
        } else {
            p.uplink_kbps
        };
        let serial_rate_down = if (media == "uart" || media == "rs485") && baud > 0 {
            ((baud as f64 * 0.8 / 1000.0).round() as u32).max(1)
        } else if media == "can" && baud > 0 {
            (baud / 1000).max(1)
        } else {
            p.downlink_kbps
        };
        LinkSpec {
            delay_ms: v.u64_field("delay_ms").unwrap_or(p.delay_ms as u64) as u32,
            jitter_ms: v.u64_field("jitter_ms").unwrap_or(p.jitter_ms as u64) as u32,
            loss_ppm: v.u64_field("loss_ppm").unwrap_or(p.loss_ppm as u64) as u32,
            dup_ppm: v.u64_field("dup_ppm").unwrap_or(p.dup_ppm as u64) as u32,
            reorder_ppm: v.u64_field("reorder_ppm").unwrap_or(p.reorder_ppm as u64) as u32,
            host_proxy: v.bool_field("host_proxy").unwrap_or(p.host_proxy),
            mtu: v.u64_field("mtu").unwrap_or(p.mtu as u64) as u16,
            media: media.clone(),
            topology: v.str_field("topology").unwrap_or(p.topology),
            t_link_min_ms: v.u64_field("t_link_min_ms").unwrap_or(p.t_link_min_ms as u64) as u32,
            uplink_kbps: v.u64_field("uplink_kbps").unwrap_or(serial_rate as u64) as u32,
            downlink_kbps: v.u64_field("downlink_kbps").unwrap_or(serial_rate_down as u64) as u32,
            segment: v.bool_field("segment").unwrap_or(p.segment),
            baud,
            poll_ms: v.u64_field("poll_ms").unwrap_or(0) as u32,
            turnaround_ms: v.u64_field("turnaround_ms").unwrap_or(p.turnaround_ms as u64) as u32,
            inter_frame_ms: v.u64_field("inter_frame_ms").unwrap_or(p.inter_frame_ms as u64) as u32,
            echo: v.bool_field("echo").unwrap_or(p.echo),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LinkDef {
    pub a: String,
    pub b: String,
    pub spec: LinkSpec,
}

#[derive(Debug, Clone)]
pub struct CapDef {
    pub index: u16,
    pub sub: u8,
    pub label: String,
    pub qty: u8,
    pub unit: String,
    pub accept_units: Vec<String>,
    pub dtype: u8,
    pub scale_exp: u8,
    pub accept_types: Vec<(u8, u8)>,
    pub range: (f64, f64),
    pub perm: u8,
    pub dir: u8,
    pub kind: u8,
    pub t_prod_ms: u32,
    pub stale_ms: u32,
    pub load_cap: u32,
    pub trigger: u8,
    pub provenance: u8,
    pub conv_class: u8,
    /// 保持语义：0=立即 1=稳定保持(稳定满 T_pub 才发布) 2=按需(仅 READ/QUERY)。
    pub hold_semantics: u8,
    pub precision: f64,
    pub frame_ref: String,
    pub invertible: bool,
    pub fail_action: u8,
}

#[derive(Debug, Clone, Default)]
pub struct ReqDef {
    pub label: String,
    pub qty: u8,
    pub unit: String,
    pub accept_units: Vec<String>,
    pub accept_types: Vec<(u8, u8)>,
    pub perm: u8,
    pub index: Option<u16>,
    pub want_ms: u32,
    pub stale_ms: u32,
    pub range: (f64, f64),
    pub kind: u8,
}

#[derive(Debug, Clone)]
pub struct SimDef {
    pub index: u16,
    pub sub: u8,
    pub base: f64,
    pub amplitude: f64,
    pub period_ms: u64,
    pub noise: f64,
    pub phase: f64,
}

/// 应用层行为：阈值联动或聚合计算，可写本地能力点或直接控制远端执行器。
#[derive(Debug, Clone)]
pub struct LogicDef {
    pub name: String,
    /// "threshold" | "aggregate"
    pub kind: String,
    pub sources: Vec<(u16, u8)>,
    pub op: String,
    pub threshold: f64,
    pub threshold2: f64,
    pub on_value: f64,
    pub off_value: f64,
    /// "avg" | "sum" | "min" | "max" | "count"
    pub agg: String,
    pub target: String,
    pub output: (u16, u8),
    pub min_interval_ms: u64,
    /// 阈值死区。
    pub deadband: f64,
    /// 条件确认延时（ms）。
    pub on_delay_ms: u64,
}

impl LogicDef {
    fn to_rule(&self) -> LogicRule {
        LogicRule {
            name: self.name.clone(),
            kind: if self.kind.eq_ignore_ascii_case("aggregate") {
                LogicKind::Aggregate
            } else if self.kind.eq_ignore_ascii_case("rate") {
                LogicKind::Rate
            } else if self.kind.eq_ignore_ascii_case("integral") {
                LogicKind::Integral
            } else {
                LogicKind::Threshold
            },
            sources: self.sources.clone(),
            op: match self.op.trim() {
                ">" => 1,
                ">=" => 2,
                "<" => 3,
                "<=" => 4,
                "==" | "=" => 5,
                "between" => 6,
                _ => 2,
            },
            threshold: self.threshold,
            threshold2: self.threshold2,
            on_value: self.on_value,
            off_value: self.off_value,
            agg: match self.agg.as_str() {
                "sum" => 2,
                "min" => 3,
                "max" => 4,
                "count" => 5,
                _ => 1,
            },
            target: self.target.clone(),
            output: self.output,
            min_interval_ms: self.min_interval_ms,
            deadband: self.deadband,
            on_delay_ms: self.on_delay_ms,
        }
    }
}

fn parse_point(text: &str) -> Option<(u16, u8)> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    let (a, b) = t
        .split_once('.')
        .or_else(|| t.split_once('/'))
        .unwrap_or((t, "0"));
    Some((a.parse().ok()?, b.parse().ok()?))
}

fn parse_output(v: &Json) -> (u16, u8) {
    if let Some(s) = v.str_field("output").and_then(|s| parse_point(&s)) {
        return s;
    }
    if let Some(arr) = v.array_field("output") {
        if arr.len() >= 2 {
            return (
                arr[0].as_u64().unwrap_or(1) as u16,
                arr[1].as_u64().unwrap_or(0) as u8,
            );
        }
    }
    (1, 0)
}

fn parse_logic(v: &Json) -> LogicDef {
    let mut sources = Vec::new();
    if let Some(s) = v.str_field("input").and_then(|s| parse_point(&s)) {
        sources.push(s);
    }
    if let Some(items) = v.array_field("sources") {
        for it in items {
            if let Some(s) = it.as_str().and_then(parse_point) {
                sources.push(s);
            } else if let Some(arr) = it.as_array() {
                if arr.len() >= 2 {
                    sources.push((
                        arr[0].as_u64().unwrap_or(1) as u16,
                        arr[1].as_u64().unwrap_or(0) as u8,
                    ));
                }
            }
        }
    }
    LogicDef {
        name: v.str_field("name").unwrap_or_else(|| "rule".into()),
        kind: v
            .str_field("kind")
            .unwrap_or_else(|| "threshold".into()),
        sources,
        op: v.str_field("op").unwrap_or_else(|| ">=".into()),
        threshold: v
            .f64_field("threshold")
            .or_else(|| v.f64_field("value"))
            .unwrap_or(0.0),
        threshold2: v.f64_field("threshold2").unwrap_or(0.0),
        on_value: v
            .f64_field("on")
            .or_else(|| v.f64_field("write_value"))
            .unwrap_or(1.0),
        off_value: v.f64_field("off").unwrap_or(0.0),
        agg: v.str_field("agg").unwrap_or_else(|| "avg".into()),
        target: v.str_field("target").unwrap_or_default(),
        output: parse_output(v),
        min_interval_ms: v.u64_field("min_interval_ms").unwrap_or(0),
        deadband: v.f64_field("deadband").unwrap_or(0.0),
        on_delay_ms: v.u64_field("on_delay_ms").unwrap_or(0),
    }
}

/// 执行器物理模型：写入后按行程时间或速率到位。
#[derive(Debug, Clone)]
pub struct ActDef {
    pub index: u16,
    pub sub: u8,
    pub travel_ms: u32,
    pub rate: f64,
    pub min_on_ms: u64,
    pub min_off_ms: u64,
    pub initial: Option<f64>,
}

/// 点位报警：高高/高/低/低低阈值与死区、确认延时。
#[derive(Debug, Clone)]
pub struct AlarmSpec {
    pub index: u16,
    pub sub: u8,
    pub hh: f64,
    pub h: f64,
    pub l: f64,
    pub ll: f64,
    pub deadband: f64,
    pub delay_ms: u64,
    /// 高报警持续该时长后升级为高高报警（0 表示不升级）。
    pub escalate_ms: u64,
}

#[derive(Debug, Clone)]
pub struct DeviceDef {
    pub name: String,
    pub did: String,
    pub key: Option<String>,
    pub group: u16,
    pub start_ms: u64,
    /// 启动自检时长（ms）。
    pub boot_ms: u32,
    pub link_min_ms: u32,
    pub mode: RunMode,
    pub preempt: bool,
    /// 允许作为网关中继其它设备的帧。
    pub relay: bool,
    /// 协议档：0=STD，1=RT。
    pub prof: u8,
    /// 是否为共享总线的主站（RS-485/Modbus 轮询发起方）。
    pub bus_master: bool,
    /// 共享总线发送优先级（0 最高，默认 16）。
    pub bus_priority: u8,
    pub caps: Vec<CapDef>,
    pub reqs: Vec<ReqDef>,
    pub sims: Vec<SimDef>,
    pub logic: Vec<LogicDef>,
    pub actuators: Vec<ActDef>,
    pub alarms: Vec<AlarmSpec>,
    /// 点位历史缓存深度（0 关闭）。
    pub hist_cap: u32,
}

impl DeviceDef {
    pub fn to_spec(&self, index: usize, default_key: &[u8]) -> DeviceSpec {
        let did = Did::from_hex(&self.did).unwrap_or_else(|| Did::from_u64(index as u64 + 1));
        let mut spec = DeviceSpec::new(&self.name, did);
        spec.group = self.group;
        spec.start_ms = self.start_ms;
        spec.boot_ms = self.boot_ms;
        spec.hist_cap = self.hist_cap;
        spec.link_min_ms = self.link_min_ms;
        spec.preempt = self.preempt;
        spec.relay = self.relay;
        spec.prof = self.prof;
        spec.bus_master = self.bus_master;
        spec.bus_priority = self.bus_priority;
        spec.key = self
            .key
            .as_ref()
            .map(|k| k.as_bytes().to_vec())
            .unwrap_or_else(|| default_key.to_vec());
        for c in &self.caps {
            spec.caps.push(c.to_capability());
        }
        for r in &self.reqs {
            spec.reqs.push(r.to_requirement());
        }
        let mut sims: BTreeMap<(u16, u8), PointSim> = BTreeMap::new();
        for (i, s) in self.sims.iter().enumerate() {
            sims.insert(
                (s.index, s.sub),
                PointSim {
                    base: s.base,
                    amplitude: s.amplitude,
                    period_ms: s.period_ms,
                    noise: s.noise,
                    phase: if s.phase != 0.0 {
                        s.phase
                    } else {
                        i as f64 * 0.7
                    },
                    seed: (index as u64 + 1) * 977 + s.index as u64 * 31 + s.sub as u64,
                },
            );
        }
        spec.sims = sims;
        for l in &self.logic {
            spec.rules.push(l.to_rule());
        }
        for a in &self.actuators {
            spec.actuators.insert(
                (a.index, a.sub),
                idcell_engine::Actuator {
                    travel_ms: a.travel_ms,
                    rate: a.rate,
                    min_on_ms: a.min_on_ms,
                    min_off_ms: a.min_off_ms,
                    initial: a.initial,
                },
            );
        }
        for a in &self.alarms {
            spec.alarms.push(AlarmDef {
                index: a.index,
                sub: a.sub,
                hh: a.hh,
                h: a.h,
                l: a.l,
                ll: a.ll,
                deadband: a.deadband,
                delay_ms: a.delay_ms,
                escalate_ms: a.escalate_ms,
            });
        }
        spec
    }
}

impl CapDef {
    fn to_capability(&self) -> idcell_core::Capability {
        let mut c = idcell_core::Capability::default();
        c.index = self.index;
        c.sub = self.sub;
        c.label = self.label.clone();
        c.kind = self.kind;
        c.dir = self.dir;
        c.perm = self.perm;
        c.qty = self.qty;
        c.unit = self.unit.clone();
        c.accept_units = self.accept_units.clone();
        c.conv_class = self.conv_class;
        c.dtype = self.dtype;
        c.scale_exp = self.scale_exp;
        c.accept_types = self
            .accept_types
            .iter()
            .map(|(d, s)| idcell_core::TypePair::new(*d, *s))
            .collect();
        c.range = self.range;
        c.precision = self.precision;
        c.frame_ref = self.frame_ref.clone();
        c.invertible = self.invertible;
        c.t_prod_ms = self.t_prod_ms;
        c.stale_ms = self.stale_ms;
        c.load_cap = self.load_cap;
        c.trigger = self.trigger;
        c.provenance = self.provenance;
        c.fail_action = self.fail_action;
        c.hold_semantics = self.hold_semantics;
        c
    }
}

impl ReqDef {
    fn to_requirement(&self) -> idcell_core::Requirement {
        let mut r = idcell_core::Requirement::default();
        r.label = self.label.clone();
        r.qty = self.qty;
        r.unit = self.unit.clone();
        r.accept_units = self.accept_units.clone();
        r.accept_types = self
            .accept_types
            .iter()
            .map(|(d, s)| idcell_core::TypePair::new(*d, *s))
            .collect();
        r.perm = self.perm;
        r.index = self.index;
        r.want_ms = self.want_ms;
        r.stale_ms = self.stale_ms;
        r.range = self.range;
        r.kind = self.kind;
        r
    }
}

#[derive(Debug, Clone)]
pub struct FaultDef {
    pub at_ms: u64,
    pub kind: String,
    pub a: String,
    pub b: String,
    pub device: String,
    pub peer: String,
    pub index: u16,
    pub sub: u8,
    pub value: f64,
    pub intent: String,
    /// write 故障：来源单位（空表示按提供方规范单位写入）。
    pub unit: String,
    /// query 故障：选择器文本与模式
    pub selector: String,
    pub mode: u8,
    /// query 故障：显式跳数上限，0 表示用场景默认
    pub hop_limit: u32,
    /// raw_frame 故障：原始帧类型与标志位
    pub frame_type: u8,
    pub flags: u8,
    /// group_declare 故障：组号、期望成员（逗号分隔）、响应超时与成员纪元
    pub group_id: u16,
    pub expected: String,
    pub response_timeout_ms: u32,
    pub group_epoch: u32,
    pub response_mode: u8,
    /// cmd 故障：仿真执行耗时与是否失败（失败必须在 DONE 中给出原因）
    pub exec_ms: u32,
    pub fail: bool,
}

#[derive(Debug, Clone)]
pub struct AssertDef {
    pub kind: String,
    pub device: String,
    pub peer: String,
    pub stage: String,
    pub index: u16,
    pub sub: u8,
    pub op: String,
    pub value: f64,
    pub tolerance: f64,
    pub frame_type: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct Scenario {
    pub name: String,
    pub duration_ms: u64,
    pub seed: u64,
    pub tick_ms: u64,
    /// true 时只有显式连线可通信（画布编辑器的接线语义）。
    pub require_link: bool,
    /// 广播洪泛 / 中继选路的最大跳数。
    pub max_hops: u8,
    pub key: Vec<u8>,
    pub default_link: LinkSpec,
    pub devices: Vec<DeviceDef>,
    pub links: Vec<LinkDef>,
    pub faults: Vec<FaultDef>,
    pub asserts: Vec<AssertDef>,
    pub source: String,
}

impl Scenario {
    pub fn parse(text: &str) -> Result<Scenario, String> {
        let root = parse(text)?;
        Scenario::from_json(&root)
    }

    pub fn load(path: &std::path::Path) -> Result<Scenario, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("读取场景 {} 失败：{e}", path.display()))?;
        let mut sc = Scenario::parse(&text)?;
        sc.source = path.display().to_string();
        Ok(sc)
    }

    pub fn from_json(root: &Json) -> Result<Scenario, String> {
        let name = root.str_field("name").unwrap_or_else(|| "unnamed".into());
        let duration_ms = root.u64_field("duration_ms").unwrap_or(12_000);
        let seed = root.u64_field("seed").unwrap_or(42);
        // 0 = 纯事件驱动；场景不需要固定步长时不必声明 tick_ms
        let tick_ms = root.u64_field("tick_ms").unwrap_or(0);
        let require_link = root.bool_field("require_link").unwrap_or(false);
        let max_hops = root.u64_field("max_hops").unwrap_or(6).clamp(1, 32) as u8;
        let key = root
            .str_field("key")
            .map(|k| k.into_bytes())
            .unwrap_or_else(|| b"idcell-lab-key".to_vec());
        let default_link = root
            .get("link")
            .map(LinkSpec::parse)
            .unwrap_or_default();

        let devices_json = root.array_field("devices").ok_or("场景缺少 devices 数组")?;
        if devices_json.is_empty() {
            return Err("devices 不能为空".into());
        }
        let mut devices = Vec::new();
        for (i, dj) in devices_json.iter().enumerate() {
            devices.push(parse_device(dj, i)?);
        }

        let mut links = Vec::new();
        if let Some(items) = root.array_field("links") {
            for lj in items {
                let a = lj.str_field("a").ok_or("link 缺少 a")?;
                let b = lj.str_field("b").ok_or("link 缺少 b")?;
                links.push(LinkDef {
                    a,
                    b,
                    spec: LinkSpec::parse(lj),
                });
            }
        }

        let mut faults = Vec::new();
        if let Some(items) = root.array_field("faults") {
            for f in items {
                faults.push(parse_fault(f)?);
            }
        }
        faults.sort_by_key(|f| f.at_ms);

        let mut asserts = Vec::new();
        if let Some(items) = root.array_field("asserts") {
            for a in items {
                asserts.push(parse_assert(a)?);
            }
        }

        Ok(Scenario {
            name,
            duration_ms,
            seed,
            tick_ms,
            require_link,
            max_hops,
            key,
            default_link,
            devices,
            links,
            faults,
            asserts,
            source: String::new(),
        })
    }

    pub fn build_world(&self) -> World {
        let mut world = World::new(WorldConfig {
            seed: self.seed,
            duration_ms: self.duration_ms,
            tick_ms: self.tick_ms,
            trace_cap: 6000,
            require_link: self.require_link,
            max_hops: self.max_hops,
        });
        world.default_link = self.default_link.to_link_config();
        for (i, d) in self.devices.iter().enumerate() {
            let spec = d.to_spec(i, &self.key);
            world.add_device(spec, d.mode);
        }
        for l in &self.links {
            if let (Some(a), Some(b)) = (world.resolve(&l.a), world.resolve(&l.b)) {
                world.add_link(a, b, l.spec.to_link_config());
            }
        }
        world
    }
}

fn parse_device(v: &Json, index: usize) -> Result<DeviceDef, String> {
    let name = v
        .str_field("name")
        .ok_or_else(|| format!("第 {} 个设备缺少 name", index))?;
    let caps_json = v.array_field("caps").unwrap_or(&[]);
    let reqs_json = v.array_field("reqs").unwrap_or(&[]);
    let mode = match v.str_field("mode").as_deref() {
        Some("provider") => RunMode::Provider,
        Some("consumer") => RunMode::Consumer,
        Some("both") => RunMode::Both,
        _ => {
            if !caps_json.is_empty() && !reqs_json.is_empty() {
                RunMode::Both
            } else if !reqs_json.is_empty() {
                RunMode::Consumer
            } else {
                RunMode::Provider
            }
        }
    };
    let mut caps = Vec::new();
    for (i, c) in caps_json.iter().enumerate() {
        caps.push(parse_cap(c, i)?);
    }
    let mut reqs = Vec::new();
    for r in reqs_json {
        reqs.push(parse_req(r)?);
    }
    let mut sims = Vec::new();
    if let Some(items) = v.array_field("values") {
        for s in items {
            sims.push(parse_sim(s)?);
        }
    }
    let mut logic = Vec::new();
    if let Some(items) = v.array_field("logic") {
        for l in items {
            logic.push(parse_logic(l));
        }
    }
    let mut actuators = Vec::new();
    if let Some(items) = v.array_field("actuators") {
        for a in items {
            let point = a
                .str_field("point")
                .and_then(|p| parse_point(&p))
                .unwrap_or((1, 0));
            actuators.push(ActDef {
                index: a.u64_field("index").unwrap_or(point.0 as u64) as u16,
                sub: a.u64_field("sub").unwrap_or(point.1 as u64) as u8,
                travel_ms: a.u64_field("travel_ms").unwrap_or(0) as u32,
                rate: a.f64_field("rate").unwrap_or(0.0),
                min_on_ms: a.u64_field("min_on_ms").unwrap_or(0),
                min_off_ms: a.u64_field("min_off_ms").unwrap_or(0),
                initial: a.f64_field("initial"),
            });
        }
    }
    let mut alarms = Vec::new();
    if let Some(items) = v.array_field("alarms") {
        for a in items {
            let point = a
                .str_field("point")
                .and_then(|p| parse_point(&p))
                .unwrap_or((1, 0));
            alarms.push(AlarmSpec {
                index: a.u64_field("index").unwrap_or(point.0 as u64) as u16,
                sub: a.u64_field("sub").unwrap_or(point.1 as u64) as u8,
                hh: a.f64_field("hh").unwrap_or(f64::INFINITY),
                h: a.f64_field("h").unwrap_or(f64::INFINITY),
                l: a.f64_field("l").unwrap_or(f64::NEG_INFINITY),
                ll: a.f64_field("ll").unwrap_or(f64::NEG_INFINITY),
                deadband: a.f64_field("deadband").unwrap_or(0.0),
                delay_ms: a.u64_field("delay_ms").unwrap_or(0),
                escalate_ms: a.u64_field("escalate_ms").unwrap_or(0),
            });
        }
    }
    Ok(DeviceDef {
        name,
        did: v.str_field("did").unwrap_or_else(|| format!("{:016X}", index as u64 + 1)),
        key: v.str_field("key"),
        group: v.u64_field("group").unwrap_or(0) as u16,
        start_ms: v.u64_field("start_ms").unwrap_or(0),
        boot_ms: v.u64_field("boot_ms").unwrap_or(0) as u32,
        link_min_ms: v.u64_field("link_min_ms").unwrap_or(1) as u32,
        mode,
        preempt: v.bool_field("preempt").unwrap_or(false),
        relay: v.bool_field("relay").unwrap_or(false),
        prof: match v.str_field("protocol").as_deref() {
            Some("rt") | Some("RT") => 1,
            _ => v.u64_field("prof").unwrap_or(0).min(1) as u8,
        },
        bus_master: v.bool_field("bus_master").unwrap_or(false),
        bus_priority: v.u64_field("bus_priority").unwrap_or(16) as u8,
        caps,
        reqs,
        sims,
        logic,
        actuators,
        alarms,
        hist_cap: v.u64_field("hist_cap").unwrap_or(240) as u32,
    })
}

fn parse_cap(v: &Json, i: usize) -> Result<CapDef, String> {
    let q = parse_qty(v.get("qty").unwrap_or(&Json::Number(qty::RATIO as f64)));
    let unit = v
        .str_field("unit")
        .unwrap_or_else(|| idcell_core::units::base_unit(q).to_string());
    let mut range = (-1e9, 1e9);
    if let Some(r) = v.array_field("range") {
        if r.len() >= 2 {
            range = (
                r[0].as_f64().unwrap_or(range.0),
                r[1].as_f64().unwrap_or(range.1),
            );
        }
    }
    let mut accept_types = Vec::new();
    if let Some(items) = v.array_field("accept_types") {
        for t in items {
            if let Some(pair) = t.as_array() {
                if pair.len() >= 2 {
                    accept_types.push((
                        pair[0].as_u64().unwrap_or(8) as u8,
                        pair[1].as_u64().unwrap_or(0) as u8,
                    ));
                }
            }
        }
    }
    let dt = v.get("dtype").map(parse_dtype).unwrap_or(8);
    Ok(CapDef {
        index: v.u64_field("index").unwrap_or(1 + i as u64) as u16,
        sub: v.u64_field("sub").unwrap_or(0) as u8,
        label: v
            .str_field("label")
            .unwrap_or_else(|| format!("point{}", 1 + i)),
        qty: q,
        unit,
        accept_units: v
            .array_field("accept")
            .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default(),
        dtype: dt,
        scale_exp: v.u64_field("scale").unwrap_or(0) as u8,
        accept_types,
        range,
        perm: v.u64_field("perm").unwrap_or(0) as u8,
        dir: v.u64_field("dir").unwrap_or(1) as u8,
        kind: v.u64_field("kind").unwrap_or(0) as u8,
        t_prod_ms: v.u64_field("t_prod_ms").unwrap_or(10) as u32,
        stale_ms: v.u64_field("stale_ms").unwrap_or(1000) as u32,
        load_cap: v.u64_field("load_cap").unwrap_or(4) as u32,
        trigger: v.u64_field("trigger").unwrap_or(0) as u8,
        provenance: v.u64_field("prov").unwrap_or(0) as u8,
        conv_class: v.u64_field("conv").unwrap_or(1) as u8,
        hold_semantics: v.u64_field("hold").unwrap_or(0) as u8,
        precision: v.f64_field("precision").unwrap_or(0.0),
        frame_ref: v.str_field("frame").unwrap_or_default(),
        invertible: v.bool_field("invertible").unwrap_or(false),
        fail_action: v.u64_field("fail_action").unwrap_or(0) as u8,
    })
}

fn parse_req(v: &Json) -> Result<ReqDef, String> {
    let q = parse_qty(v.get("qty").unwrap_or(&Json::Number(qty::RATIO as f64)));
    let unit = v
        .str_field("unit")
        .unwrap_or_else(|| idcell_core::units::base_unit(q).to_string());
    let mut range = (-1e9, 1e9);
    if let Some(r) = v.array_field("range") {
        if r.len() >= 2 {
            range = (
                r[0].as_f64().unwrap_or(range.0),
                r[1].as_f64().unwrap_or(range.1),
            );
        }
    }
    let mut accept_types = Vec::new();
    if let Some(items) = v.array_field("accept_types") {
        for t in items {
            if let Some(pair) = t.as_array() {
                if pair.len() >= 2 {
                    accept_types.push((
                        pair[0].as_u64().unwrap_or(8) as u8,
                        pair[1].as_u64().unwrap_or(0) as u8,
                    ));
                }
            }
        }
    }
    Ok(ReqDef {
        label: v.str_field("label").unwrap_or_default(),
        qty: q,
        unit,
        accept_units: v
            .array_field("accept")
            .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default(),
        accept_types,
        perm: v.u64_field("perm").unwrap_or(0) as u8,
        index: v.u64_field("index").map(|i| i as u16),
        want_ms: v.u64_field("want_ms").unwrap_or(50) as u32,
        stale_ms: v.u64_field("stale_ms").unwrap_or(500) as u32,
        range,
        kind: v.u64_field("kind").unwrap_or(0) as u8,
    })
}

fn parse_sim(v: &Json) -> Result<SimDef, String> {
    Ok(SimDef {
        index: v.u64_field("index").unwrap_or(1) as u16,
        sub: v.u64_field("sub").unwrap_or(0) as u8,
        base: v.f64_field("base").unwrap_or(0.0),
        amplitude: v.f64_field("amplitude").unwrap_or(0.0),
        period_ms: v.u64_field("period_ms").unwrap_or(1000).max(1),
        noise: v.f64_field("noise").unwrap_or(0.0),
        phase: v.f64_field("phase").unwrap_or(0.0),
    })
}

fn parse_fault(v: &Json) -> Result<FaultDef, String> {
    Ok(FaultDef {
        at_ms: v.u64_field("at_ms").unwrap_or(0),
        kind: v.str_field("kind").ok_or("fault 缺少 kind")?,
        a: v.str_field("a").unwrap_or_default(),
        b: v.str_field("b").unwrap_or_default(),
        device: v.str_field("device").unwrap_or_default(),
        peer: v.str_field("peer").unwrap_or_default(),
        index: v.u64_field("index").unwrap_or(0) as u16,
        sub: v.u64_field("sub").unwrap_or(0) as u8,
        value: v.f64_field("value").unwrap_or(0.0),
        intent: v
            .str_field("intent")
            .unwrap_or_else(|| "scenario-write".to_string()),
        unit: v.str_field("unit").unwrap_or_default(),
        selector: v
            .str_field("selector")
            .unwrap_or_else(|| "*".to_string()),
        mode: match v.str_field("mode").as_deref() {
            Some("first") => idcell_core::consts::query_mode::FIRST,
            Some("all") => idcell_core::consts::query_mode::ALL,
            // 数字 mode 同时服务查询模式与采集故障模式（1..4），缺省按查询 ALL。
            _ => v
                .u64_field("mode")
                .or_else(|| v.u64_field("query_mode"))
                .unwrap_or(idcell_core::consts::query_mode::ALL as u64)
                as u8,
        },
        hop_limit: v.u64_field("hop_limit").unwrap_or(0) as u32,
        frame_type: v
            .u64_field("frame_type")
            .or_else(|| v.u64_field("ftype"))
            .unwrap_or(0) as u8,
        flags: v.u64_field("flags").unwrap_or(0) as u8,
        group_id: v.u64_field("group_id").unwrap_or(0) as u16,
        expected: v.str_field("expected").unwrap_or_default(),
        response_timeout_ms: v.u64_field("response_timeout_ms").unwrap_or(1000) as u32,
        group_epoch: v.u64_field("group_epoch").unwrap_or(1) as u32,
        response_mode: match v.str_field("response_mode").as_deref() {
            Some("none") => idcell_core::consts::response_mode::NONE,
            Some("required") => idcell_core::consts::response_mode::REQUIRED,
            _ => v
                .u64_field("response_mode")
                .unwrap_or(idcell_core::consts::response_mode::REQUIRED as u64)
                as u8,
        },
        exec_ms: v.u64_field("exec_ms").unwrap_or(200) as u32,
        fail: v
            .u64_field("fail")
            .map(|x| x != 0)
            .or_else(|| v.str_field("fail").map(|s| s == "true"))
            .unwrap_or(false),
    })
}

fn parse_assert(v: &Json) -> Result<AssertDef, String> {
    Ok(AssertDef {
        kind: v.str_field("kind").ok_or("assert 缺少 kind")?,
        device: v.str_field("device").unwrap_or_default(),
        peer: v.str_field("peer").unwrap_or_default(),
        stage: v.str_field("stage").unwrap_or_default(),
        index: v.u64_field("index").unwrap_or(0) as u16,
        sub: v.u64_field("sub").unwrap_or(0) as u8,
        op: v.str_field("op").unwrap_or_else(|| ">=".into()),
        value: v.f64_field("value").unwrap_or(0.0),
        tolerance: v.f64_field("tolerance").unwrap_or(0.5),
        frame_type: v.str_field("frame").unwrap_or_default(),
        description: v.str_field("description").unwrap_or_default(),
    })
}

fn parse_qty(v: &Json) -> u8 {
    if let Some(n) = v.as_u64() {
        return n as u8;
    }
    if let Some(s) = v.as_str() {
        for q in 0..qty::COUNT {
            if qty::name(q).eq_ignore_ascii_case(s) {
                return q;
            }
        }
    }
    qty::RATIO
}

fn parse_dtype(v: &Json) -> u8 {
    if let Some(n) = v.as_u64() {
        return n as u8;
    }
    if let Some(s) = v.as_str() {
        let s = s.to_ascii_lowercase();
        for d in 0..=12u8 {
            if idcell_core::consts::dtype::name(d) == s {
                return d;
            }
        }
    }
    8
}
