//! 场景断言评估。
//!
//! 断言在仿真结束后对最终状态求值，避免依赖中间瞬时状态。
//! 支持的 kind：
//!   stage        —— device 对 peer 的会话阶段（含 pipeline_done 别名）
//!   role         —— device 对 peer 的会话角色
//!   bound        —— binds_ok 至少一次（value 可指定最少次数）
//!   binds_ok / binds_fail / stale_events / timeouts /
//!   writes_ok / writes_rejected / events_rx —— 全局计数器阈值
//!   resumes_ok —— 断链重连复用绑定/描述缓存的次数（FR-028）
//!   resumed       —— device 对 peer 的会话是否经描述缓存复用恢复（device/peer 字段）
//!   queries_sent / replies_rx / queries_answered / query_timeouts —— 查询计数器
//!   query_replies —— 指定 device 聚合到的应答条数（device 字段）
//!   value        —— device 收到的点值（index/sub），带容差
//!   point        —— device 本地维护的点值（index/sub），带容差
//!   frame        —— 帧类型计数，frame 字段为类型名（如 EVENT）

use crate::model::AssertDef;
use idcell_engine::{json_escape, Stage, World};

#[derive(Debug, Clone)]
pub struct AssertResult {
    pub description: String,
    pub kind: String,
    pub passed: bool,
    pub detail: String,
}

impl AssertResult {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"kind\":\"{}\",\"description\":\"{}\",\"passed\":{},\"detail\":\"{}\"}}",
            json_escape(&self.kind),
            json_escape(&self.description),
            self.passed,
            json_escape(&self.detail)
        )
    }
}

fn compare(op: &str, actual: f64, expected: f64, tolerance: f64) -> bool {
    match op {
        ">" => actual > expected,
        ">=" => actual >= expected,
        "<" => actual < expected,
        "<=" => actual <= expected,
        "==" | "=" => (actual - expected).abs() <= tolerance.max(f64::EPSILON),
        "!=" => (actual - expected).abs() > tolerance.max(f64::EPSILON),
        _ => false,
    }
}

fn counter(world: &World, kind: &str) -> Option<u64> {
    let m = &world.metrics;
    Some(match kind {
        "binds_ok" => world.total_binds_ok(),
        "binds_fail" => world.total_binds_fail(),
        "stale_events" => world.total_stale_events(),
        "timeouts" => world.total_timeouts(),
        "writes_ok" => world.total_writes_ok(),
        "writes_rejected" => world.total_writes_rejected(),
        "writes_converted" => world.total_writes_converted(),
        "writes_unit_rejected" => world.total_writes_unit_rejected(),
        "fail_safe_actions" => world.total_fail_safe_actions(),
        "hold_suppressed" => world.total_hold_suppressed(),
        "events_rx" => world.total_events_rx(),
        "queries_sent" => world.total_queries_sent(),
        "replies_rx" => world.total_replies_rx(),
        "queries_answered" => world.total_queries_answered(),
        "query_timeouts" => world.total_query_timeouts(),
        "logic" => world.total_logic_fired(),
        "proto_rejects" => world.total_proto_rejects(),
        "resumes_ok" => world.total_resumes_ok(),
        "group_ok" => world.total_group_ok(),
        "group_missing" => world.total_group_missing(),
        "group_rejects" => world.total_group_rejects(),
        "config_ok" => world.total_config_ok(),
        "config_rejects" => world.total_config_rejects(),
        "reneg_ok" => world.total_reneg_ok(),
        "cmds_sent" => world.total_cmds_sent(),
        "cmd_acks" => world.total_cmd_acks(),
        "commands_rx" => world.total_commands_rx(),
        "done_sent" => world.total_done_sent(),
        "done_rx" => world.total_done_rx(),
        "done_errors" => world.total_done_errors(),
        "desc_frag_tx" => world.total_desc_frag_tx(),
        "desc_frag_rx" => world.total_desc_frag_rx(),
        "desc_reassemble_ok" => world.total_desc_reassemble_ok(),
        "desc_crc_errors" => world.total_desc_crc_errors(),
        "desc_oversize" => world.total_desc_oversize(),
        "link_retx" => world.metrics.link_retx,
        "link_acks" => world.metrics.link_acks,
        "link_drops" => world.metrics.link_drops,
        "bus_contention" => world.metrics.bus_contention,
        "bus_deferrals" => world.metrics.bus_deferrals,
        "bus_poll_drops" => world.metrics.bus_poll_drops,
        "bus_busy_ms" => world.metrics.bus_busy_ms,
        "actuator_moves" => world.total_actuator_moves(),
        "state_changes" => world.total_state_changes(),
        "alarms_raised" => world.total_alarms_raised(),
        "alarms_cleared" => world.total_alarms_cleared(),
        "link_ack_tx" => world.total_link_ack_tx(),
        "dup_drops" => world.total_dup_drops(),
        "provision_sent" => world.total_provision_sent(),
        "provision_ok" => world.total_provision_ok(),
        "provision_rejects" => world.total_provision_rejects(),
        "frames_tx" => m.frames_tx,
        "frames_rx" => m.frames_rx,
        "drops" => m.drops,
        "duplicated" => m.duplicated,
        "crc_errors" => m.crc_errors,
        "bytes_tx" => m.bytes_tx,
        "bytes_rx" => m.bytes_rx,
        "latency_samples" => m.latency_samples,
        _ => return None,
    })
}

fn stage_matches(expected: &str, stage: Stage) -> bool {
    let want = expected.trim().to_ascii_lowercase();
    match want.as_str() {
        "" => stage == Stage::Active,
        "pipeline_done" | "done" => stage.is_pipeline_done(),
        other => stage.name().eq_ignore_ascii_case(other),
    }
}

/// 评估单条断言。
pub fn evaluate_one(world: &World, def: &AssertDef) -> AssertResult {
    let mut result = AssertResult {
        description: if def.description.is_empty() {
            format!("{} {}", def.kind, def.device)
        } else {
            def.description.clone()
        },
        kind: def.kind.clone(),
        passed: false,
        detail: String::new(),
    };

    let kind = def.kind.as_str();
    match kind {
        "stage" => {
            let Some(stage) = world.stage_of(&def.device, &def.peer) else {
                result.detail = format!("{}/{} 无会话", def.device, def.peer);
                return result;
            };
            result.passed = stage_matches(&def.stage, stage);
            result.detail = format!(
                "{}/{} 当前阶段 {}，期望 {}",
                def.device, def.peer, stage.name(), def.stage
            );
        }
        "role" => {
            let Some(role) = world.session_role(&def.device, &def.peer) else {
                result.detail = format!("{}/{} 无会话", def.device, def.peer);
                return result;
            };
            result.passed = role.name().eq_ignore_ascii_case(&def.stage);
            result.detail = format!("{}/{} 角色 {}，期望 {}", def.device, def.peer, role.name(), def.stage);
        }
        "prof" => {
            let Some(prof) = world.device_prof(&def.device) else {
                result.detail = format!("{} 不存在", def.device);
                return result;
            };
            result.passed = prof as f64 == def.value;
            result.detail = format!(
                "{} 协议档 {}，期望 {}",
                def.device,
                if prof == 1 { "RT" } else { "STD" },
                def.value
            );
        }
        "bound" => {
            let ok = world.total_binds_ok() as f64;
            let need = if def.value > 0.0 { def.value } else { 1.0 };
            result.passed = ok >= need;
            result.detail = format!("binds_ok={ok}，期望 >= {need}");
        }
        "history_count" => {
            let n = world.history_count(&def.device, def.index, def.sub);
            result.passed = compare(&def.op, n as f64, def.value, def.tolerance);
            result.detail = format!(
                "{} 点 ({},{}) 历史 {} 条 {} {}",
                def.device, def.index, def.sub, n, def.op, def.value
            );
        }
        "history_avg" => {
            let avg = world.history_avg(&def.device, def.index, def.sub);
            result.passed = compare(&def.op, avg, def.value, def.tolerance);
            result.detail = format!(
                "{} 点 ({},{}) 历史均值 {:.3} {} {:.3}",
                def.device, def.index, def.sub, avg, def.op, def.value
            );
        }
        "alarm" => {
            let level = world.alarm_level(&def.device, def.index, def.sub) as f64;
            result.passed = compare(&def.op, level, def.value, def.tolerance);
            result.detail = format!(
                "{} 点 ({},{}) 报警等级 {} {} {}",
                def.device, def.index, def.sub, level, def.op, def.value
            );
        }
        "point" => {
            let Some(p) = world
                .device(&def.device)
                .and_then(|d| d.points.get(&(def.index, def.sub)))
            else {
                result.detail = format!("{} 无本地点 ({},{})", def.device, def.index, def.sub);
                return result;
            };
            result.passed = compare(&def.op, p.value, def.value, def.tolerance);
            result.detail = format!(
                "{} 本地点 ({},{}) 值 {:.3} {} {:.3}（质量 {}）",
                def.device, def.index, def.sub, p.value, def.op, def.value, p.quality
            );
        }
        "value" => {
            let Some((v, stale, quality)) = world.received_value(&def.device, def.index, def.sub)
            else {
                result.detail = format!(
                    "{} 未收到点 ({},{})",
                    def.device, def.index, def.sub
                );
                return result;
            };
            result.passed = compare(&def.op, v, def.value, def.tolerance);
            result.detail = format!(
                "{} 点 ({},{}) 实际 {:.3} {} {:.3}{}",
                def.device,
                def.index,
                def.sub,
                v,
                def.op,
                def.value,
                if stale { "（已过期）" } else { "" }
            );
            let _ = quality;
        }
        "query_replies" => {
            let count = world.query_reply_count(&def.device) as f64;
            result.passed = compare(&def.op, count, def.value, def.tolerance);
            result.detail = format!(
                "{} 查询应答 {count} {} {}",
                def.device, def.op, def.value
            );
        }
        "resumed" => {
            let resumed = world.session_resumed(&def.device, &def.peer);
            result.passed = resumed;
            result.detail = format!(
                "{}/{} 会话{}复用描述缓存",
                def.device,
                def.peer,
                if resumed { "已" } else { "未" }
            );
        }
        "frame" => {
            let name = if def.frame_type.is_empty() {
                def.stage.as_str()
            } else {
                def.frame_type.as_str()
            };
            let count = world.frame_type_count(name) as f64;
            result.passed = compare(&def.op, count, def.value, def.tolerance);
            result.detail = format!("帧 {name} 计数 {count} {} {}", def.op, def.value);
        }
        other => {
            let Some(actual) = counter(world, other) else {
                result.detail = format!("未知断言类型 {other}");
                return result;
            };
            let actual_f = actual as f64;
            result.passed = compare(&def.op, actual_f, def.value, def.tolerance);
            result.detail = format!("{other}={actual} {} {}", def.op, def.value);
        }
    }
    result
}

pub fn evaluate_all(world: &World, defs: &[AssertDef]) -> Vec<AssertResult> {
    defs.iter().map(|d| evaluate_one(world, d)).collect()
}
