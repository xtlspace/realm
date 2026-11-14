pub mod cmd;
pub mod conf;
pub mod consts;
pub use realm_core as core;

pub const VERSION: &str = match option_env!("REALM_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};
pub const ENV_CONFIG: &str = "REALM_CONF";
