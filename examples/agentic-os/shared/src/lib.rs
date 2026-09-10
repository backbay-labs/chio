pub mod events;
pub mod host;
pub mod model;
pub mod web;

pub use anyhow;
pub use async_trait::async_trait;
pub use events::Run;
pub use serde_json::{json, Value};

#[async_trait]
pub trait Application: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn title(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn sample(&self) -> Value;
    async fn execute(&self, input: Value, run: Run) -> anyhow::Result<Value>;
}

pub mod client;

pub mod graph;
