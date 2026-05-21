#[path = "pheromone/alerts.rs"]
mod alerts;
#[path = "pheromone/assurance.rs"]
mod assurance;
#[path = "pheromone/delivery.rs"]
mod delivery;
#[path = "pheromone/directory.rs"]
mod directory;
#[path = "pheromone/relay.rs"]
mod relay;
#[path = "pheromone/root.rs"]
mod root;

pub(crate) use self::alerts::ChioPheromoneRelayAlertCommands;
pub(crate) use self::assurance::{
    ChioPheromoneRelayAlertAssuranceArchiveCommands,
    ChioPheromoneRelayAlertAssuranceCloseoutCommands, ChioPheromoneRelayAlertAssuranceCommands,
    ChioPheromoneRelayAlertAssuranceRetentionCommands,
};
pub(crate) use self::delivery::ChioPheromoneRelayAlertDeliveryCommands;
pub(crate) use self::directory::{
    ChioPheromoneRelayDirectoryCommands, ChioPheromoneRelaySupervisorCommands,
};
#[cfg(test)]
pub(crate) use self::relay::RelayMetricsFormatArg;
pub(crate) use self::relay::{ChioPheromoneRelayCommands, RelayProfileArg};
pub(crate) use self::root::ChioPheromoneCommands;

pub(crate) type ChiodosPheromoneCommands = ChioPheromoneCommands;
pub(crate) type ChiodosPheromoneRelayAlertCommands = ChioPheromoneRelayAlertCommands;
pub(crate) type ChiodosPheromoneRelayAlertAssuranceArchiveCommands =
    ChioPheromoneRelayAlertAssuranceArchiveCommands;
pub(crate) type ChiodosPheromoneRelayAlertAssuranceCloseoutCommands =
    ChioPheromoneRelayAlertAssuranceCloseoutCommands;
pub(crate) type ChiodosPheromoneRelayAlertAssuranceCommands =
    ChioPheromoneRelayAlertAssuranceCommands;
pub(crate) type ChiodosPheromoneRelayAlertAssuranceRetentionCommands =
    ChioPheromoneRelayAlertAssuranceRetentionCommands;
pub(crate) type ChiodosPheromoneRelayAlertDeliveryCommands =
    ChioPheromoneRelayAlertDeliveryCommands;
pub(crate) type ChiodosPheromoneRelayDirectoryCommands = ChioPheromoneRelayDirectoryCommands;
pub(crate) type ChiodosPheromoneRelayCommands = ChioPheromoneRelayCommands;
pub(crate) type ChiodosPheromoneRelaySupervisorCommands = ChioPheromoneRelaySupervisorCommands;
