//! ID-CELL 仿真平台命令行入口。
//!
//! 用法：
//!   idcell-lab run   <scenario.json> [--trace out.jsonl] [--json]
//!   idcell-lab serve <scenario.json> [--port 8787] [--speed 1]
//!
//! run   —— 一次性跑完场景，评估断言，进程退出码反映成败（适合 CI）。
//! serve —— 启动本地 Web 仿真控制台：画布拓扑为主界面，底部融合数据帧与介质监控。

mod server;

use idcell_engine::World;
use idcell_scenario::{apply_fault, Scenario};
use std::process::ExitCode;

/// 面板与定时线程共享的仿真状态。
pub struct Sim {
    pub world: World,
    pub scenario: Scenario,
    /// 当前场景的原始 JSON（画布编辑器用于恢复拓扑）。
    pub scenario_json: String,
    pub paused: bool,
    pub speed: f64,
    /// 下一条待自动注入的定时故障（按 at_ms 升序）。
    next_fault: usize,
}

impl Sim {
    pub fn new(scenario: Scenario, scenario_json: String, speed: f64) -> Sim {
        let world = scenario.build_world();
        Sim {
            world,
            scenario,
            scenario_json,
            paused: false,
            speed,
            next_fault: 0,
        }
    }

    /// 画布编辑器应用新拓扑：整体替换场景并回到 0 时刻。
    pub fn apply_scenario(&mut self, scenario: Scenario, scenario_json: String) {
        self.scenario = scenario;
        self.scenario_json = scenario_json;
        self.reset();
    }

    /// 推进 `step_ms`，期间按时间线自动注入故障。
    pub fn advance(&mut self, step_ms: u64) {
        if self.world.finished {
            return;
        }
        let target = (self.world.now_ms + step_ms).min(self.scenario.duration_ms);
        while self.next_fault < self.scenario.faults.len() {
            let f = self.scenario.faults[self.next_fault].clone();
            if f.at_ms > target {
                break;
            }
            self.world.advance_to(f.at_ms);
            apply_fault(&mut self.world, &f).ok();
            self.next_fault += 1;
        }
        self.world.advance_to(target);
        if self.world.now_ms >= self.scenario.duration_ms {
            self.world.finished = true;
        }
    }

    pub fn reset(&mut self) {
        self.world = self.scenario.build_world();
        self.next_fault = 0;
        self.paused = false;
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
        return ExitCode::from(2);
    }
    let result = match args[0].as_str() {
        "run" => cmd_run(&args[1..]),
        "serve" => cmd_serve(&args[1..]),
        "-h" | "--help" | "help" => {
            usage();
            Ok(true)
        }
        other => {
            eprintln!("未知子命令 {other}\n");
            usage();
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("错误：{e}");
            ExitCode::from(2)
        }
    }
}

fn usage() {
    println!(
        "ID-CELL 仿真平台

用法:
  idcell-lab run   <scenario.json> [--trace out.jsonl] [--json]
      一次性运行场景并评估断言；断言失败时退出码为 1。

  idcell-lab serve <scenario.json> [--port 8787] [--speed 1]
      启动本地 Web 仿真控制台；画布为主界面，底部融合帧详情与介质传播。
"
    );
}

fn cmd_run(args: &[String]) -> Result<bool, String> {
    let mut scenario_path: Option<String> = None;
    let mut trace_path: Option<String> = None;
    let mut json_mode = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--trace" => {
                i += 1;
                trace_path = Some(args.get(i).ok_or("--trace 缺少路径")?.clone());
            }
            "--json" => json_mode = true,
            flag if flag.starts_with("--") => return Err(format!("未知参数 {flag}")),
            path => scenario_path = Some(path.to_string()),
        }
        i += 1;
    }
    let path = scenario_path.ok_or("缺少场景文件路径")?;
    let scenario = Scenario::load(std::path::Path::new(&path))?;
    let outcome = idcell_scenario::run(
        &scenario,
        trace_path.as_ref().map(|p| std::path::Path::new(p.as_str())),
    )?;

    if json_mode {
        println!("{}", outcome.to_json());
    } else {
        println!(
            "场景：{}（{} 台设备、{} 条链路，仿真 {:.1}s）",
            outcome.scenario,
            scenario.devices.len(),
            scenario.links.len(),
            outcome.now_ms as f64 / 1000.0
        );
        let passed = outcome.assertions.iter().filter(|a| a.passed).count();
        println!("断言：{}/{} 通过\n", passed, outcome.assertions.len());
        for a in &outcome.assertions {
            println!(
                "  [{}] {:<24} {}",
                if a.passed { "PASS" } else { "FAIL" },
                a.description,
                a.detail
            );
        }
        let m = &outcome.snapshot.metrics;
        println!(
            "\n指标：帧 {} 发 / {} 收，丢包 {}，重复 {}，CRC 错误 {}，平均时延 {:.2}ms",
            m.frames_tx,
            m.frames_rx,
            m.drops,
            m.duplicated,
            m.crc_errors,
            m.avg_latency_ms()
        );
        if let Some(t) = &trace_path {
            println!("trace 已写入 {t}");
        }
        println!("\n结果：{}", if outcome.passed { "通过" } else { "未通过" });
    }
    Ok(outcome.passed)
}

fn cmd_serve(args: &[String]) -> Result<bool, String> {
    let mut scenario_path: Option<String> = None;
    let mut port: u16 = 8787;
    let mut speed = 1.0f64;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                i += 1;
                port = args
                    .get(i)
                    .ok_or("--port 缺少端口")?
                    .parse()
                    .map_err(|_| "端口必须是整数".to_string())?;
            }
            "--speed" => {
                i += 1;
                speed = args
                    .get(i)
                    .ok_or("--speed 缺少倍速")?
                    .parse()
                    .map_err(|_| "倍速必须是数字".to_string())?;
            }
            flag if flag.starts_with("--") => return Err(format!("未知参数 {flag}")),
            path => scenario_path = Some(path.to_string()),
        }
        i += 1;
    }
    let path = scenario_path.ok_or("缺少场景文件路径")?;
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("读取场景 {path} 失败：{e}"))?;
    let scenario = Scenario::parse(&text)?;
    server::serve(scenario, text, port, speed)?;
    Ok(true)
}
