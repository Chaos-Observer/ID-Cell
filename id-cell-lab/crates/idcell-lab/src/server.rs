//! 极简 HTTP/1.1 + SSE 服务：零外部依赖。
//!
//! 路由：
//!   GET  /                内嵌面板
//!   GET  /editor          画布编辑器（拖拽设备、手动连线、属性配置）
//!   GET  /api/state       当前快照（JSON）
//!   GET  /api/stream      SSE 实时快照
//!   GET  /api/scenario    当前场景原始 JSON
//!   POST /api/scenario    应用画布拓扑（场景 JSON）
//!   POST /api/control     暂停/继续/步进/重置/倍速
//!   POST /api/fault       运行中注入故障
//!   POST /api/query       发起一次查询（device/peer/selector/mode/hop_limit）
//!   POST /api/write       面板写值（provider/index/sub/value，开关或模拟量）

use crate::Sim;
use idcell_scenario::{apply_fault, parse_json, FaultDef, Scenario};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const PANEL_HTML: &str = include_str!("panel.html");
const EDITOR_HTML: &str = include_str!("editor.html");

pub fn serve(
    scenario: Scenario,
    scenario_json: String,
    port: u16,
    speed: f64,
) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| format!("监听 127.0.0.1:{port} 失败：{e}"))?;

    let sim = Arc::new(Mutex::new(Sim::new(scenario, scenario_json, speed)));
    spawn_ticker(Arc::clone(&sim));

    println!("ID-CELL 仿真面板已启动：http://127.0.0.1:{port}/");
    println!("画布编辑器：http://127.0.0.1:{port}/editor");
    println!("按 Ctrl+C 结束。");

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let sim = Arc::clone(&sim);
                std::thread::spawn(move || {
                    if let Err(e) = handle_client(s, sim) {
                        eprintln!("连接处理失败：{e}");
                    }
                });
            }
            Err(e) => eprintln!("接受连接失败：{e}"),
        }
    }
    Ok(())
}

/// 每 20ms 推进一次仿真；倍速以毫秒增量体现。
fn spawn_ticker(sim: Arc<Mutex<Sim>>) {
    std::thread::spawn(move || {
        let mut acc = 0.0f64;
        loop {
            std::thread::sleep(Duration::from_millis(20));
            let mut guard = match sim.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            if guard.paused || guard.world.finished {
                acc = 0.0;
                continue;
            }
            acc += 20.0 * guard.speed;
            let step = acc.floor() as u64;
            if step > 0 {
                acc -= step as f64;
                guard.advance(step);
            }
        }
    });
}

fn handle_client(mut stream: TcpStream, sim: Arc<Mutex<Sim>>) -> std::io::Result<()> {
    stream.set_nodelay(true).ok();
    let mut reader = BufReader::new(stream.try_clone()?);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 {
            break;
        }
        if header == "\r\n" || header == "\n" {
            break;
        }
        if let Some((k, v)) = header.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    match (method.as_str(), path.split('?').next().unwrap_or("/")) {
        ("GET", "/") | ("GET", "/index.html") => {
            respond(
                &mut stream,
                "200 OK",
                "text/html; charset=utf-8",
                PANEL_HTML.as_bytes(),
            )?;
        }
        ("GET", "/editor") | ("GET", "/editor.html") => {
            respond(
                &mut stream,
                "200 OK",
                "text/html; charset=utf-8",
                EDITOR_HTML.as_bytes(),
            )?;
        }
        ("GET", "/api/media") => {
            let json = idcell_engine::media_catalog_json();
            respond(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                json.as_bytes(),
            )?;
        }
        ("GET", "/api/scenario") => {
            let text = match sim.lock() {
                Ok(g) => g.scenario_json.clone(),
                Err(_) => "{\"error\":\"状态锁损坏\"}".to_string(),
            };
            respond(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                text.as_bytes(),
            )?;
        }
        ("POST", "/api/scenario") => {
            let reply = apply_scenario(&sim, &body);
            let (code, payload) = match reply {
                Ok(msg) => ("200 OK", format!("{{\"ok\":true,\"msg\":\"{msg}\"}}")),
                Err(e) => (
                    "400 Bad Request",
                    format!("{{\"ok\":false,\"msg\":\"{}\"}}", idcell_engine::json_escape(&e)),
                ),
            };
            respond(
                &mut stream,
                code,
                "application/json; charset=utf-8",
                payload.as_bytes(),
            )?;
        }
        ("GET", "/api/state") => {
            let json = snapshot_json(&sim);
            respond(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                json.as_bytes(),
            )?;
        }
        ("GET", "/api/stream") => {
            stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\n\
                  Cache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n",
            )?;
            loop {
                let json = snapshot_json(&sim);
                if stream
                    .write_all(format!("data: {json}\n\n").as_bytes())
                    .is_err()
                {
                    break;
                }
                if stream.flush().is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }
        ("POST", "/api/control") => {
            let reply = control(&sim, &body);
            let (code, payload) = match reply {
                Ok(msg) => ("200 OK", format!("{{\"ok\":true,\"msg\":\"{msg}\"}}")),
                Err(e) => ("400 Bad Request", format!("{{\"ok\":false,\"msg\":\"{e}\"}}")),
            };
            respond(
                &mut stream,
                code,
                "application/json; charset=utf-8",
                payload.as_bytes(),
            )?;
        }
        ("POST", "/api/fault") => {
            let reply = inject_fault(&sim, &body);
            let (code, payload) = match reply {
                Ok(msg) => ("200 OK", format!("{{\"ok\":true,\"msg\":\"{msg}\"}}")),
                Err(e) => ("400 Bad Request", format!("{{\"ok\":false,\"msg\":\"{e}\"}}")),
            };
            respond(
                &mut stream,
                code,
                "application/json; charset=utf-8",
                payload.as_bytes(),
            )?;
        }
        ("POST", "/api/query") => {
            let reply = request_query(&sim, &body);
            let (code, payload) = match reply {
                Ok(msg) => ("200 OK", format!("{{\"ok\":true,\"msg\":\"{msg}\"}}")),
                Err(e) => ("400 Bad Request", format!("{{\"ok\":false,\"msg\":\"{e}\"}}")),
            };
            respond(
                &mut stream,
                code,
                "application/json; charset=utf-8",
                payload.as_bytes(),
            )?;
        }
        ("POST", "/api/write") => {
            let reply = write_point(&sim, &body);
            let (code, payload) = match reply {
                Ok(msg) => ("200 OK", format!("{{\"ok\":true,\"msg\":\"{msg}\"}}")),
                Err(e) => (
                    "400 Bad Request",
                    format!(
                        "{{\"ok\":false,\"msg\":\"{}\"}}",
                        idcell_engine::json_escape(&e)
                    ),
                ),
            };
            respond(
                &mut stream,
                code,
                "application/json; charset=utf-8",
                payload.as_bytes(),
            )?;
        }
        _ => {
            respond(&mut stream, "404 Not Found", "text/plain", b"not found")?;
        }
    }
    Ok(())
}

fn respond(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn snapshot_json(sim: &Arc<Mutex<Sim>>) -> String {
    match sim.lock() {
        Ok(g) => {
            let mut s = g.world.snapshot(80).to_json();
            // 顶层补充面板需要的运行参数与断言实时预览
            s.insert_str(
                1,
                &format!(
                    "\"paused\":{},\"speed\":{},\"scenario\":\"{}\",",
                    g.paused,
                    g.speed,
                    idcell_engine::json_escape(&g.scenario.name)
                ),
            );
            let assertions = idcell_scenario::evaluate_all(&g.world, &g.scenario.asserts);
            let mut tail = String::from(",\"assertions\":[");
            for (i, a) in assertions.iter().enumerate() {
                if i > 0 {
                    tail.push(',');
                }
                tail.push_str(&a.to_json());
            }
            tail.push_str("],\"final\":");
            tail.push_str(if g.world.now_ms >= g.world.duration_ms {
                "true"
            } else {
                "false"
            });
            if s.ends_with('}') {
                s.pop();
            }
            s.push_str(&tail);
            s.push('}');
            s
        }
        Err(_) => "{\"error\":\"状态锁损坏\"}".to_string(),
    }
}

fn apply_scenario(sim: &Arc<Mutex<Sim>>, body: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(body).map_err(|_| "请求体不是 UTF-8".to_string())?;
    let scenario = Scenario::parse(text)?;
    let devices = scenario.devices.len();
    let links = scenario.links.len();
    let mut guard = sim.lock().map_err(|_| "状态锁损坏".to_string())?;
    guard.apply_scenario(scenario, text.to_string());
    Ok(format!("已应用拓扑：{devices} 台设备、{links} 条连线"))
}

fn control(sim: &Arc<Mutex<Sim>>, body: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(body).map_err(|_| "请求体不是 UTF-8".to_string())?;
    let json = parse_json(text)?;
    let cmd = json.str_field("cmd").ok_or("缺少 cmd")?;
    let mut guard = sim.lock().map_err(|_| "状态锁损坏".to_string())?;
    match cmd.as_str() {
        "pause" => {
            guard.paused = true;
            Ok("已暂停".into())
        }
        "resume" => {
            guard.paused = false;
            Ok("已继续".into())
        }
        "toggle" => {
            guard.paused = !guard.paused;
            Ok(if guard.paused { "已暂停" } else { "已继续" }.into())
        }
        "step" => {
            guard.paused = true;
            guard.world.step_event();
            Ok("已步进一个事件".into())
        }
        "reset" => {
            guard.reset();
            Ok("已重置".into())
        }
        "speed" => {
            let v = json.f64_field("value").ok_or("缺少 value")?;
            if !(0.05..=64.0).contains(&v) {
                return Err("倍速需在 0.05~64 之间".into());
            }
            guard.speed = v;
            Ok(format!("倍速 = {v}"))
        }
        other => Err(format!("未知命令 {other}")),
    }
}

fn inject_fault(sim: &Arc<Mutex<Sim>>, body: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(body).map_err(|_| "请求体不是 UTF-8".to_string())?;
    let json = parse_json(text)?;
    let fault = FaultDef {
        // 运行中注入的故障立即生效
        at_ms: 0,
        kind: json.str_field("kind").ok_or("缺少 kind")?,
        a: json.str_field("a").unwrap_or_default(),
        b: json.str_field("b").unwrap_or_default(),
        device: json.str_field("device").unwrap_or_default(),
        peer: json.str_field("peer").unwrap_or_default(),
        index: json.u64_field("index").unwrap_or(0) as u16,
        sub: json.u64_field("sub").unwrap_or(0) as u8,
        value: json.f64_field("value").unwrap_or(0.0),
        intent: json
            .str_field("intent")
            .unwrap_or_else(|| "panel-write".into()),
        selector: json.str_field("selector").unwrap_or_else(|| "*".into()),
        mode: match json.str_field("mode").as_deref() {
            Some("first") => idcell_core::consts::query_mode::FIRST,
            Some("all") => idcell_core::consts::query_mode::ALL,
            _ => json
                .u64_field("query_mode")
                .unwrap_or(idcell_core::consts::query_mode::ALL as u64)
                as u8,
        },
        hop_limit: json.u64_field("hop_limit").unwrap_or(0) as u32,
        frame_type: json.u64_field("frame_type").unwrap_or(0) as u8,
        flags: json.u64_field("flags").unwrap_or(0) as u8,
        group_id: json.u64_field("group_id").unwrap_or(0) as u16,
        expected: json.str_field("expected").unwrap_or_default(),
        response_timeout_ms: json.u64_field("response_timeout_ms").unwrap_or(1000) as u32,
        group_epoch: json.u64_field("group_epoch").unwrap_or(1) as u32,
        response_mode: match json.str_field("response_mode").as_deref() {
            Some("none") => idcell_core::consts::response_mode::NONE,
            Some("required") => idcell_core::consts::response_mode::REQUIRED,
            _ => json
                .u64_field("response_mode")
                .unwrap_or(idcell_core::consts::response_mode::REQUIRED as u64)
                as u8,
        },
        exec_ms: json.u64_field("exec_ms").unwrap_or(200) as u32,
        fail: json.u64_field("fail").map(|x| x != 0).unwrap_or(false),
    };
    let mut guard = sim.lock().map_err(|_| "状态锁损坏".to_string())?;
    apply_fault(&mut guard.world, &fault)?;
    Ok(format!("已注入 {}", fault.kind))
}

/// 面板写值：开关量传 0/1，模拟量传目标值；服务端负责量程校验。
fn write_point(sim: &Arc<Mutex<Sim>>, body: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(body).map_err(|_| "请求体不是 UTF-8".to_string())?;
    let json = parse_json(text)?;
    let provider = json.str_field("device").ok_or("缺少 device")?;
    let index = json.u64_field("index").ok_or("缺少 index")? as u16;
    let sub = json.u64_field("sub").unwrap_or(0) as u8;
    let value = json.f64_field("value").ok_or("缺少 value")?;
    let intent = json
        .str_field("intent")
        .unwrap_or_else(|| "panel-write".into());
    let mut guard = sim.lock().map_err(|_| "状态锁损坏".to_string())?;
    guard.world.panel_write(&provider, index, sub, value, &intent)
}

/// 运行中发起一次查询（无需等到场景里预设的故障时刻）。
fn request_query(sim: &Arc<Mutex<Sim>>, body: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(body).map_err(|_| "请求体不是 UTF-8".to_string())?;
    let json = parse_json(text)?;
    let device = json.str_field("device").ok_or("缺少 device")?;
    let selector = json.str_field("selector").unwrap_or_else(|| "*".into());
    let peer = json.str_field("peer").unwrap_or_default();
    let mode = match json.str_field("mode").as_deref() {
        Some("first") => idcell_core::consts::query_mode::FIRST,
        Some("all") => idcell_core::consts::query_mode::ALL,
        _ => idcell_core::consts::query_mode::ALL,
    };
    let hop_limit = json.u64_field("hop_limit").unwrap_or(0) as u32;
    let mut guard = sim.lock().map_err(|_| "状态锁损坏".to_string())?;
    let ok = guard
        .world
        .request_query(&device, &peer, &selector, mode, hop_limit);
    if ok {
        Ok(format!("{device} 已发起查询 selector={selector}"))
    } else {
        Err(format!("查询未生效：设备/对端无法解析，或仿真已结束（{device} / {peer}）"))
    }
}
