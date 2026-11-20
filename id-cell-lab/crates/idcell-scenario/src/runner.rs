//! 场景运行器：注入故障、推进时间线、评估断言。

use crate::checks::{evaluate_all, AssertResult};
use crate::model::{FaultDef, Scenario};
use idcell_engine::{json_escape, json_num, Snapshot, World};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct RunOutcome {
    pub scenario: String,
    pub now_ms: u64,
    pub passed: bool,
    pub assertions: Vec<AssertResult>,
    pub snapshot: Snapshot,
}

impl RunOutcome {
    /// 运行结果 JSON（不含完整快照，仅摘要 + 断言）。
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(2048);
        s.push_str(&format!(
            "{{\"scenario\":\"{}\",\"now_ms\":{},\"passed\":{},\"assertions\":[",
            json_escape(&self.scenario),
            self.now_ms,
            self.passed
        ));
        for (i, a) in self.assertions.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&a.to_json());
        }
        let m = &self.snapshot.metrics;
        s.push_str(&format!(
            "],\"metrics\":{{\"frames_tx\":{},\"frames_rx\":{},\"drops\":{},\"duplicated\":{},\"crc_errors\":{},\"avg_latency_ms\":{},\"max_latency_ms\":{},\"binds_ok\":{},\"binds_fail\":{},\"resumes_ok\":{},\"group_ok\":{},\"group_missing\":{},\"group_rejects\":{},\"config_ok\":{},\"config_rejects\":{},\"reneg_ok\":{},\"cmds_sent\":{},\"cmd_acks\":{},\"done_rx\":{},\"done_errors\":{},\"desc_frag_tx\":{},\"desc_frag_rx\":{},\"desc_reassemble_ok\":{},\"desc_crc_errors\":{},\"desc_oversize\":{},\"stale_events\":{},\"timeouts\":{},\"writes_ok\":{},\"writes_rejected\":{},\"events_rx\":{},\"queries_sent\":{},\"replies_rx\":{},\"queries_answered\":{},\"query_timeouts\":{}}}}}",
            m.frames_tx,
            m.frames_rx,
            m.drops,
            m.duplicated,
            m.crc_errors,
            json_num(m.avg_latency_ms()),
            m.latency_max_ms,
            bind_sum(&self.snapshot, |c| c.binds_ok),
            bind_sum(&self.snapshot, |c| c.binds_fail),
            bind_sum(&self.snapshot, |c| c.resumes_ok),
            bind_sum(&self.snapshot, |c| c.group_ok),
            bind_sum(&self.snapshot, |c| c.group_missing),
            bind_sum(&self.snapshot, |c| c.group_rejects),
            bind_sum(&self.snapshot, |c| c.config_ok),
            bind_sum(&self.snapshot, |c| c.config_rejects),
            bind_sum(&self.snapshot, |c| c.reneg_ok),
            bind_sum(&self.snapshot, |c| c.cmds_sent),
            bind_sum(&self.snapshot, |c| c.cmd_acks),
            bind_sum(&self.snapshot, |c| c.done_rx),
            bind_sum(&self.snapshot, |c| c.done_errors),
            bind_sum(&self.snapshot, |c| c.desc_frag_tx),
            bind_sum(&self.snapshot, |c| c.desc_frag_rx),
            bind_sum(&self.snapshot, |c| c.desc_reassemble_ok),
            bind_sum(&self.snapshot, |c| c.desc_crc_errors),
            bind_sum(&self.snapshot, |c| c.desc_oversize),
            bind_sum(&self.snapshot, |c| c.stale_events),
            bind_sum(&self.snapshot, |c| c.session_timeouts),
            bind_sum(&self.snapshot, |c| c.writes_ok),
            bind_sum(&self.snapshot, |c| c.writes_rejected),
            bind_sum(&self.snapshot, |c| c.events_rx),
            bind_sum(&self.snapshot, |c| c.queries_sent),
            bind_sum(&self.snapshot, |c| c.replies_rx),
            bind_sum(&self.snapshot, |c| c.queries_answered),
            bind_sum(&self.snapshot, |c| c.query_timeouts),
        ));
        s
    }
}

fn bind_sum(snap: &Snapshot, f: impl Fn(&idcell_engine::DeviceCounters) -> u64) -> u64 {
    snap.devices.iter().map(|d| f(&d.counters)).sum()
}

/// 应用一条故障注入。返回错误说明用于定位场景文件写错。
pub fn apply_fault(world: &mut World, f: &FaultDef) -> Result<(), String> {
    let ok = match f.kind.as_str() {
        "partition" => world.set_partition(&f.a, &f.b, true),
        "heal" | "reconnect" => world.set_partition(&f.a, &f.b, false),
        "stop_publish" => world.set_device_publishing(&f.device, false),
        "resume_publish" => world.set_device_publishing(&f.device, true),
        "sleep" => world.set_device_asleep(&f.device, true),
        "wake" => world.set_device_asleep(&f.device, false),
        "rx_off" => world.set_device_rx(&f.device, false),
        "rx_on" => world.set_device_rx(&f.device, true),
        "power_off" => world.set_device_power(&f.device, false),
        "power_on" => world.set_device_power(&f.device, true),
        "read" => world.request_read(&f.device, &f.peer, f.index, f.sub),
        "write" => world.request_write(
            &f.device,
            &f.peer,
            f.index,
            f.sub,
            f.value,
            &f.intent,
        ),
        "renegotiate" => world.request_renegotiate(&f.device, &f.peer, f.value as u32),
        "unsubscribe" => world.request_unsubscribe(&f.device, &f.peer, f.index, f.sub),
        "query" => world.request_query(
            &f.device,
            &f.peer,
            &f.selector,
            f.mode,
            f.hop_limit,
        ),
        "group_declare" => {
            let members: Vec<&str> = f
                .expected
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
            world.request_group_declare(
                &f.device,
                f.group_id,
                &members,
                f.response_timeout_ms,
                f.response_mode,
                f.group_epoch,
            )
        }
        "config" => world.request_config(
            &f.device,
            &f.peer,
            f.index,
            f.sub,
            f.value as u8,
            &f.intent,
        ),
        "cmd" => world.request_command(
            &f.device,
            &f.peer,
            f.index,
            f.sub,
            f.exec_ms,
            f.fail,
            &f.intent,
        ),
        "raw_frame" => {
            world.inject_raw_frame(&f.device, &f.peer, f.frame_type, f.flags)
        }
        other => return Err(format!("未知故障类型 {other}")),
    };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "故障 {} 目标解析失败（a={} b={} device={} peer={}）",
            f.kind, f.a, f.b, f.device, f.peer
        ))
    }
}

/// 按时间线注入故障并运行完整场景。
///
/// 时间推进采用 `advance_to`，因此故障在目标毫秒处、且在该时刻所有已排队
/// 事件处理完之后才生效——与真实世界“先发生再改变介质”的直觉一致。
pub fn run(scenario: &Scenario, trace_path: Option<&Path>) -> Result<RunOutcome, String> {
    let mut world = scenario.build_world();

    for f in &scenario.faults {
        if f.at_ms >= scenario.duration_ms {
            continue;
        }
        world.advance_to(f.at_ms);
        apply_fault(&mut world, f)?;
    }
    world.run();

    let snapshot = world.snapshot(400);
    let assertions = evaluate_all(&world, &scenario.asserts);
    let passed = assertions.iter().all(|a| a.passed);

    if let Some(path) = trace_path {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("创建目录 {} 失败：{e}", parent.display()))?;
            }
        }
        std::fs::write(path, world.trace_jsonl())
            .map_err(|e| format!("写入 trace {} 失败：{e}", path.display()))?;
    }

    Ok(RunOutcome {
        scenario: scenario.name.clone(),
        now_ms: world.now_ms,
        passed,
        assertions,
        snapshot,
    })
}
