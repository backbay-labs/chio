mod amount;
mod close;
mod dispute;
mod funding;
mod lifecycle;
mod open;
mod projection;
mod rail;
mod replay;
mod reservation;
mod signed;
mod state;
mod terminal;
mod terminal_outcome;
mod validation;

pub use chio_core::web3::trust_profile::Web3FinalityMode;

pub use amount::*;
pub use close::*;
pub use dispute::*;
pub use funding::*;
pub use lifecycle::*;
pub use open::*;
pub use projection::*;
pub use rail::*;
pub use replay::*;
pub use reservation::*;
pub use signed::*;
pub use state::*;
pub use terminal::*;
pub use terminal_outcome::*;

#[cfg(test)]
mod tests;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ChannelError {
    #[error("invalid channel field `{0}`")]
    InvalidField(&'static str),
    #[error("channel arithmetic overflow")]
    ArithmeticOverflow,
    #[error("channel amount conversion is not exact")]
    InexactAmount,
    #[error("channel authority verification failed")]
    AuthorityVerification,
    #[error("illegal channel lifecycle transition")]
    IllegalTransition,
    #[error("channel canonicalization failed: {0}")]
    Canonicalization(String),
}
