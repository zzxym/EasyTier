use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};

use super::Provider;

use super::common::{self, messages, parsing, parsing::RequestReponse};
use super::PortMappingProtocol;

/// This structure represents a gateway found by the search functions.
#[derive(Clone, Debug)]
pub struct Gateway<P> {
    /// Socket address of the gateway
    pub addr: SocketAddr,
    /// Root url of the device
    pub root_url: String,
    /// Control url of the device
    pub control_url: String,
    /// Url to get schema data from
    pub control_schema_url: String,
    /// Control schema for all actions
    pub control_schema: HashMap<String, Vec<String>>,
    /// Executor provider
    pub provider: P,
}

impl<P: Provider> Gateway<P> {
    async fn perform_request(
        &self,
        header: &str,
        body: &str,
        ok: &str,
    ) -> anyhow::Result<RequestReponse> {
        let url = format!("{self}");
        let text = P::send_async(&url, header, body).await?;
        parsing::parse_response(text, ok)
    }

    /// Get the external IP address of the gateway in a tokio compatible way
    pub async fn get_external_ip(&self) -> anyhow::Result<Option<IpAddr>> {
        let result = self
            .perform_request(
                messages::GET_EXTERNAL_IP_HEADER,
                &messages::format_get_external_ip_message(),
                "GetExternalIPAddressResponse",
            )
            .await;
        parsing::parse_get_external_ip_response(result)
    }

    /// Get an external socket address with our external ip and any port. This is a convenience
    /// function that calls `get_external_ip` followed by `add_any_port`
    ///
    /// The local_addr is the address where the traffic is sent to.
    /// The lease_duration parameter is in seconds. A value of 0 is infinite.
    ///
    /// # Returns
    ///
    /// The external address that was mapped on success. Otherwise an error.
    pub async fn get_any_address(
        &self,
        protocol: PortMappingProtocol,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> anyhow::Result<SocketAddr> {
        let description = description.to_owned();
        let ip = self
            .get_external_ip()
            .await?
            .ok_or_else(|| anyhow::anyhow!("Router does not have an external IP address"))?;
        let port = self
            .add_any_port(protocol, local_addr, lease_duration, &description)
            .await?;
        Ok(SocketAddr::new(ip, port))
    }

    /// Add a port mapping.with any external port.
    ///
    /// The local_addr is the address where the traffic is sent to.
    /// The lease_duration parameter is in seconds. A value of 0 is infinite.
    ///
    /// # Returns
    ///
    /// The external port that was mapped on success. Otherwise an error.
    pub async fn add_any_port(
        &self,
        protocol: PortMappingProtocol,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> anyhow::Result<u16> {
        // This function first attempts to call AddAnyPortMapping on the IGD with a random port
        // number. If that fails due to the method being unknown it attempts to call AddPortMapping
        // instead with a random port number. If that fails due to ConflictInMappingEntry it retrys
        // with another port up to a maximum of 20 times. If it fails due to SamePortValuesRequired
        // it retrys once with the same port values.

        if local_addr.port() == 0 {
            return Err(anyhow::anyhow!("Internal port zero is invalid"));
        }

        let schema = self.control_schema.get("AddAnyPortMapping");
        if let Some(schema) = schema {
            let external_port = common::random_port();

            let description = description.to_owned();

            let resp = self
                .perform_request(
                    messages::ADD_ANY_PORT_MAPPING_HEADER,
                    &messages::format_add_any_port_mapping_message(
                        schema,
                        protocol,
                        external_port,
                        local_addr,
                        lease_duration,
                        &description,
                    ),
                    "AddAnyPortMappingResponse",
                )
                .await;
            parsing::parse_add_any_port_mapping_response(resp)
        } else {
            // The router does not have the AddAnyPortMapping method.
            // Fall back to using AddPortMapping with a random port.
            self.retry_add_random_port_mapping(protocol, local_addr, lease_duration, description)
                .await
        }
    }

    async fn retry_add_random_port_mapping(
        &self,
        protocol: PortMappingProtocol,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> anyhow::Result<u16> {
        for _ in 0u8..20u8 {
            match self
                .add_random_port_mapping(protocol, local_addr, lease_duration, description)
                .await
            {
                Ok(port) => return Ok(port),
                Err(_) => continue,
            }
        }
        Err(anyhow::anyhow!("No ports available"))
    }

    async fn add_random_port_mapping(
        &self,
        protocol: PortMappingProtocol,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> anyhow::Result<u16> {
        let description = description.to_owned();
        let external_port = common::random_port();
        let res = self
            .add_port_mapping(
                protocol,
                external_port,
                local_addr,
                lease_duration,
                &description,
            )
            .await;

        match res {
            Ok(_) => Ok(external_port),
            Err(_) => {
                self.add_same_port_mapping(protocol, local_addr, lease_duration, &description)
                    .await
            }
        }
    }

    async fn add_same_port_mapping(
        &self,
        protocol: PortMappingProtocol,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> anyhow::Result<u16> {
        let res = self
            .add_port_mapping(
                protocol,
                local_addr.port(),
                local_addr,
                lease_duration,
                description,
            )
            .await;
        match res {
            Ok(_) => Ok(local_addr.port()),
            Err(err) => Err(anyhow::anyhow!("Add same port mapping failed: {}", err)),
        }
    }

    async fn add_port_mapping(
        &self,
        protocol: PortMappingProtocol,
        external_port: u16,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> anyhow::Result<()> {
        self.perform_request(
            messages::ADD_PORT_MAPPING_HEADER,
            &messages::format_add_port_mapping_message(
                self.control_schema
                    .get("AddPortMapping")
                    .ok_or_else(|| anyhow::anyhow!("Unsupported action: AddPortMapping"))?,
                protocol,
                external_port,
                local_addr,
                lease_duration,
                description,
            ),
            "AddPortMappingResponse",
        )
        .await?;
        Ok(())
    }

    /// Add a port mapping.
    ///
    /// The local_addr is the address where the traffic is sent to.
    /// The lease_duration parameter is in seconds. A value of 0 is infinite.
    pub async fn add_port(
        &self,
        protocol: PortMappingProtocol,
        external_port: u16,
        local_addr: SocketAddr,
        lease_duration: u32,
        description: &str,
    ) -> anyhow::Result<()> {
        if external_port == 0 {
            return Err(anyhow::anyhow!("External port zero is invalid"));
        }
        if local_addr.port() == 0 {
            return Err(anyhow::anyhow!("Internal port zero is invalid"));
        }

        let res = self
            .add_port_mapping(
                protocol,
                external_port,
                local_addr,
                lease_duration,
                description,
            )
            .await;
        if let Err(err) = res {
            return Err(anyhow::anyhow!("Add port mapping failed: {}", err));
        };
        Ok(())
    }

    /// Remove a port mapping.
    pub async fn remove_port(
        &self,
        protocol: PortMappingProtocol,
        external_port: u16,
    ) -> anyhow::Result<()> {
        let res = self
            .perform_request(
                messages::DELETE_PORT_MAPPING_HEADER,
                &messages::format_delete_port_message(
                    self.control_schema
                        .get("DeletePortMapping")
                        .ok_or_else(|| anyhow::anyhow!("Unsupported action: DeletePortMapping"))?,
                    protocol,
                    external_port,
                ),
                "DeletePortMappingResponse",
            )
            .await;
        parsing::parse_delete_port_mapping_response(res)
    }

    /// Get one port mapping entry
    ///
    /// Gets one port mapping entry by its index.
    /// Not all existing port mappings might be visible to this client.
    /// If the index is out of bound, GetGenericPortMappingEntryError::SpecifiedArrayIndexInvalid will be returned
    pub async fn get_generic_port_mapping_entry(
        &self,
        index: u32,
    ) -> anyhow::Result<parsing::PortMappingEntry> {
        let result = self
            .perform_request(
                messages::GET_GENERIC_PORT_MAPPING_ENTRY,
                &messages::formate_get_generic_port_mapping_entry_message(index),
                "GetGenericPortMappingEntryResponse",
            )
            .await;
        parsing::parse_get_generic_port_mapping_entry(result)
    }
}

impl<P> fmt::Display for Gateway<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "http://{}{}", self.addr, self.control_url)
    }
}

impl<P> PartialEq for Gateway<P> {
    fn eq(&self, other: &Gateway<P>) -> bool {
        self.addr == other.addr && self.control_url == other.control_url
    }
}

impl<P> Eq for Gateway<P> {}

impl<P> Hash for Gateway<P> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
        self.control_url.hash(state);
    }
}
