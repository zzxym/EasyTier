pub mod messages;
pub mod options;
pub mod parsing;

use rand::Rng;

pub use self::options::SearchOptions;

pub fn random_port() -> u16 {
    rand::thread_rng().gen_range(32_768_u16..65_535_u16)
}
