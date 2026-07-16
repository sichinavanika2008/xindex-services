//! Fail-closed native swap catalog, quote, payload and route-selection core.
//!
//! Discovery is informational. A provider asset becomes eligible only after
//! its live provider state, governance mapping, independent reference amount
//! and exact dispatch payload all pass validation.

pub mod catalog;
pub mod chainflip;
pub mod eip712;
pub mod error;
pub mod governance;
mod http;
mod math;
pub mod maya;
pub mod payload;
pub mod planner;
pub mod selection;

pub use error::NativeRouterError;
