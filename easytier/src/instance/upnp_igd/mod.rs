mod common;
mod gateway;
mod search;

use std::fmt;

pub(crate) const MAX_RESPONSE_SIZE: usize = 1500;
pub(crate) const HEADER_NAME: &str = "SOAPAction";

/// Trait to allow abstracting over `tokio`.
#[async_trait::async_trait]
pub trait Provider {
    /// Send an async request over the executor.
    async fn send_async(url: &str, action: &str, body: &str) -> anyhow::Result<String>;
}

/// Represents the protocols available for port mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortMappingProtocol {
    /// TCP protocol
    Tcp,
    /// UDP protocol
    Udp,
}

impl fmt::Display for PortMappingProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                PortMappingProtocol::Tcp => "TCP",
                PortMappingProtocol::Udp => "UDP",
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::instance::upnp_igd::{
        common::SearchOptions, search::search_gateway, PortMappingProtocol,
    };

    #[tokio::test]
    async fn test_search_device() {
        let ret = search_gateway(SearchOptions::default()).await.unwrap();
        println!("{:?}", ret);
        let external_ip = ret.get_external_ip().await.unwrap();
        println!("{:?}", external_ip);

        let add_port_ret = ret
            .add_port(
                PortMappingProtocol::Tcp,
                51010,
                "10.147.223.128:11010".parse().unwrap(),
                1000,
                "test",
            )
            .await;

        println!("{:?}", add_port_ret);
    }
}
