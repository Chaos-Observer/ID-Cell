//! 场景层：JSON 场景 DSL 的解析、构建、运行与断言。
//!
//! 典型用法：
//! ```no_run
//! let sc = idcell_scenario::Scenario::load(std::path::Path::new("scenarios/basic.json"))?;
//! let outcome = idcell_scenario::run(&sc, None)?;
//! assert!(outcome.passed);
//! # Ok::<(), String>(())
//! ```

pub mod checks;
pub mod json;
pub mod model;
pub mod runner;

pub use checks::{evaluate_all, evaluate_one, AssertResult};
pub use json::{parse as parse_json, Json};
pub use model::{
    AssertDef, CapDef, DeviceDef, FaultDef, LinkDef, LinkSpec, ReqDef, Scenario, SimDef,
};
pub use runner::{apply_fault, run, RunOutcome};
