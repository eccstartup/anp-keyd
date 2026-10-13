//! 审计：append-only 的 JSONL，带哈希链与链外锚。
//!
//! 拒绝也要留痕 —— 一次被挡掉的跨 uid 探测，在日志里不能和"什么都没发生"
//! 长得一样。

pub mod log;

pub use log::{export_tripwire, last_export, AuditLog, Event, ExportRecord};
