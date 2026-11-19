//! 虚拟链路：介质画像与损伤模型（时延/抖动/丢包/重排/重复/隔离）。

/// 链路介质画像：把“串口 / CAN / USB / 以太网 / Wi-Fi / BLE / IPC”等
/// 收敛成可配置的一等模型。字段含义与协议 L0 链路假设表一致。
#[derive(Debug, Clone, Copy)]
pub struct MediaSpec {
    pub id: &'static str,
    /// 界面展示名。
    pub label: &'static str,
    /// 介质分类：local / serial / bus / lan / wireless。
    pub class: &'static str,
    /// 链路单帧字节数；0 表示不限制。
    pub mtu: u16,
    pub delay_ms: u32,
    pub jitter_ms: u32,
    pub uplink_kbps: u32,
    pub downlink_kbps: u32,
    pub t_link_min_ms: u32,
    /// p2p / multi_drop / multi_master / star_host_proxy / switched
    pub topology: &'static str,
    pub host_proxy: bool,
    /// 适配层可分段/重组（如 CAN ISO-TP、USB 批量），仿真按整帧语义处理。
    pub segment: bool,
    /// 串口/CAN 的物理波特率/位速率；0 表示不适用。
    pub baud: u32,
}

/// 支持的链路类型目录。顺序即界面顺序。
pub const MEDIA_CATALOG: &[MediaSpec] = &[
    MediaSpec { id: "loopback", label: "本机回环", class: "local", mtu: 0, delay_ms: 0, jitter_ms: 0, uplink_kbps: 0, downlink_kbps: 0, t_link_min_ms: 0, topology: "p2p", host_proxy: false, segment: false, baud: 0 },
    MediaSpec { id: "ipc", label: "进程间 IPC", class: "local", mtu: 0, delay_ms: 0, jitter_ms: 0, uplink_kbps: 0, downlink_kbps: 0, t_link_min_ms: 0, topology: "p2p", host_proxy: false, segment: false, baud: 0 },
    MediaSpec { id: "uart", label: "串口 UART", class: "serial", mtu: 512, delay_ms: 2, jitter_ms: 0, uplink_kbps: 115, downlink_kbps: 115, t_link_min_ms: 5, topology: "p2p", host_proxy: false, segment: false, baud: 115_200 },
    MediaSpec { id: "rs485", label: "RS-485 总线", class: "serial", mtu: 512, delay_ms: 3, jitter_ms: 0, uplink_kbps: 115, downlink_kbps: 115, t_link_min_ms: 5, topology: "multi_drop", host_proxy: false, segment: false, baud: 115_200 },
    MediaSpec { id: "can", label: "CAN 总线", class: "bus", mtu: 8, delay_ms: 2, jitter_ms: 0, uplink_kbps: 1000, downlink_kbps: 1000, t_link_min_ms: 2, topology: "multi_master", host_proxy: false, segment: false, baud: 500_000 },
    MediaSpec { id: "usb", label: "USB", class: "bus", mtu: 1024, delay_ms: 1, jitter_ms: 0, uplink_kbps: 12_000, downlink_kbps: 12_000, t_link_min_ms: 1, topology: "p2p", host_proxy: true, segment: false, baud: 0 },
    MediaSpec { id: "ethernet", label: "以太网", class: "lan", mtu: 1500, delay_ms: 1, jitter_ms: 0, uplink_kbps: 0, downlink_kbps: 0, t_link_min_ms: 1, topology: "switched", host_proxy: false, segment: false, baud: 0 },
    MediaSpec { id: "wifi", label: "Wi-Fi", class: "wireless", mtu: 1400, delay_ms: 8, jitter_ms: 6, uplink_kbps: 2000, downlink_kbps: 2000, t_link_min_ms: 10, topology: "star_host_proxy", host_proxy: false, segment: false, baud: 0 },
    MediaSpec { id: "ble", label: "蓝牙 BLE", class: "wireless", mtu: 244, delay_ms: 12, jitter_ms: 4, uplink_kbps: 128, downlink_kbps: 128, t_link_min_ms: 20, topology: "p2p", host_proxy: false, segment: false, baud: 0 },
    MediaSpec { id: "sub1g", label: "Sub-1G", class: "wireless", mtu: 64, delay_ms: 20, jitter_ms: 5, uplink_kbps: 50, downlink_kbps: 50, t_link_min_ms: 30, topology: "p2p", host_proxy: false, segment: false, baud: 0 },
    MediaSpec { id: "lora", label: "LoRa", class: "wireless", mtu: 51, delay_ms: 120, jitter_ms: 20, uplink_kbps: 5, downlink_kbps: 5, t_link_min_ms: 150, topology: "p2p", host_proxy: false, segment: false, baud: 0 },
];

pub fn media_spec(id: &str) -> Option<&'static MediaSpec> {
    MEDIA_CATALOG.iter().find(|m| m.id == id)
}

/// 介质目录的 JSON（供前端与外部工具读取，避免前后端各维护一份）。
pub fn media_catalog_json() -> String {
    let mut s = String::from("[");
    for (i, m) in MEDIA_CATALOG.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!(
            "{{\"id\":\"{}\",\"label\":\"{}\",\"class\":\"{}\",\"mtu\":{},\"delay_ms\":{},\
             \"jitter_ms\":{},\"uplink_kbps\":{},\"downlink_kbps\":{},\"t_link_min_ms\":{},\
             \"topology\":\"{}\",\"host_proxy\":{},\"segment\":{},\"baud\":{}}}",
            m.id, m.label, m.class, m.mtu, m.delay_ms, m.jitter_ms, m.uplink_kbps,
            m.downlink_kbps, m.t_link_min_ms, m.topology, m.host_proxy, m.segment, m.baud
        ));
    }
    s.push(']');
    s
}

#[derive(Debug, Clone)]
pub struct LinkConfig {
    pub delay_ms: u32,
    pub jitter_ms: u32,
    pub loss_ppm: u32,
    pub dup_ppm: u32,
    /// 额外延迟制造乱序；真正的顺序由调度时间决定。
    pub reorder_ppm: u32,
    /// USB 主机代发：多一跳转发延迟。
    pub host_proxy: bool,
    pub mtu: u16,
    /// uart / can / ble / wifi / usb / ethernet / loopback / ipc ...
    pub media: String,
    /// p2p / multi_drop / multi_master / star_host_proxy / switched / mesh
    pub topology: String,
    /// 本机实测最小链路周期，参与 T_pub = max(T_prod, T_want, T_link_min)。
    pub t_link_min_ms: u32,
    /// 上行带宽（a → b），kbps；0 表示不限速。
    pub uplink_kbps: u32,
    /// 下行带宽（b → a），kbps；0 表示不限速。
    pub downlink_kbps: u32,
    /// 适配层支持分段/重组：链路 MTU 小于协议帧时仍按整帧语义传递。
    pub segment: bool,
    /// 串口/CAN 的物理波特率/位速率；0 表示不适用。
    pub baud: u32,
}

impl Default for LinkConfig {
    fn default() -> Self {
        LinkConfig {
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
        }
    }
}

impl LinkConfig {
    /// 按介质目录给出默认参数；未知介质回落为默认链路。
    pub fn media_preset(media: &str) -> LinkConfig {
        match media_spec(media) {
            Some(m) => LinkConfig {
                delay_ms: m.delay_ms,
                jitter_ms: m.jitter_ms,
                loss_ppm: 0,
                dup_ppm: 0,
                reorder_ppm: 0,
                host_proxy: m.host_proxy,
                mtu: m.mtu,
                media: media.to_string(),
                topology: m.topology.to_string(),
                t_link_min_ms: m.t_link_min_ms,
                uplink_kbps: m.uplink_kbps,
                downlink_kbps: m.downlink_kbps,
                segment: m.segment,
                baud: m.baud,
            },
            None => LinkConfig {
                media: media.to_string(),
                ..LinkConfig::default()
            },
        }
    }

    /// from 是否为链路 a 端（决定用上行还是下行带宽）。
    pub fn bandwidth_for(&self, from_is_a: bool) -> u32 {
        if from_is_a {
            self.uplink_kbps
        } else {
            self.downlink_kbps
        }
    }
}

#[derive(Debug, Clone)]
pub struct Link {
    pub a: usize,
    pub b: usize,
    pub cfg: LinkConfig,
    pub partitioned: bool,
    pub frames: u64,
    pub dropped: u64,
    pub duplicated: u64,
    pub bytes: u64,
    /// 最近一次传输占满链路后的空闲时刻（a→b / b→a）
    pub next_free_ab_ms: u64,
    pub next_free_ba_ms: u64,
}

impl Link {
    pub fn new(a: usize, b: usize, cfg: LinkConfig) -> Self {
        Link {
            a,
            b,
            cfg,
            partitioned: false,
            frames: 0,
            dropped: 0,
            duplicated: 0,
            bytes: 0,
            next_free_ab_ms: 0,
            next_free_ba_ms: 0,
        }
    }

    pub fn connects(&self, x: usize, y: usize) -> bool {
        (self.a == x && self.b == y) || (self.a == y && self.b == x)
    }
}
