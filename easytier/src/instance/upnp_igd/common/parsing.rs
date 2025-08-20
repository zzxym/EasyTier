use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};

use anyhow::Context;
use url::Url;
use xmltree::{self, Element};

use super::super::PortMappingProtocol;

// Parse the result.
pub fn parse_search_result(text: &str) -> anyhow::Result<(SocketAddr, String)> {
    for line in text.lines() {
        let line = line.trim();
        if line.to_ascii_lowercase().starts_with("location:") {
            if let Some(colon) = line.find(':') {
                let url_text = &line[colon + 1..].trim();
                let url = Url::parse(url_text).map_err(|_| anyhow::anyhow!("Invalid response"))?;
                let addr: IpAddr = url
                    .host_str()
                    .ok_or_else(|| anyhow::anyhow!("Invalid response"))
                    .and_then(|s| s.parse().map_err(|_| anyhow::anyhow!("Invalid response")))?;
                let port: u16 = url
                    .port_or_known_default()
                    .ok_or_else(|| anyhow::anyhow!("Invalid response"))?;

                return Ok((SocketAddr::new(addr, port), url.path().to_string()));
            }
        }
    }
    Err(anyhow::anyhow!("Invalid response"))
}

pub fn parse_control_urls<R>(resp: R) -> anyhow::Result<(String, String)>
where
    R: io::Read,
{
    let root = Element::parse(resp)?;

    let mut urls = root.children.iter().filter_map(|child| {
        let child = child.as_element()?;
        if child.name == "device" {
            Some(parse_device(child)?)
        } else {
            None
        }
    });

    urls.next()
        .ok_or_else(|| anyhow::anyhow!("Invalid response"))
}

fn parse_device(device: &Element) -> Option<(String, String)> {
    let services = device.get_child("serviceList").and_then(|service_list| {
        service_list
            .children
            .iter()
            .filter_map(|child| {
                let child = child.as_element()?;
                if child.name == "service" {
                    parse_service(child)
                } else {
                    None
                }
            })
            .next()
    });
    let devices = device.get_child("deviceList").and_then(parse_device_list);
    services.or(devices)
}

fn parse_device_list(device_list: &Element) -> Option<(String, String)> {
    device_list
        .children
        .iter()
        .filter_map(|child| {
            let child = child.as_element()?;
            if child.name == "device" {
                parse_device(child)
            } else {
                None
            }
        })
        .next()
}

fn parse_service(service: &Element) -> Option<(String, String)> {
    let service_type = service.get_child("serviceType")?;
    let service_type = service_type
        .get_text()
        .map(|s| s.into_owned())
        .unwrap_or_else(|| "".into());
    if [
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANIPConnection:2",
    ]
    .contains(&service_type.as_str())
    {
        let scpd_url = service.get_child("SCPDURL");
        let control_url = service.get_child("controlURL");
        if let (Some(scpd_url), Some(control_url)) = (scpd_url, control_url) {
            Some((
                scpd_url
                    .get_text()
                    .map(|s| s.into_owned())
                    .unwrap_or_else(|| "".into()),
                control_url
                    .get_text()
                    .map(|s| s.into_owned())
                    .unwrap_or_else(|| "".into()),
            ))
        } else {
            None
        }
    } else {
        None
    }
}

pub fn parse_schemas<R>(resp: R) -> anyhow::Result<HashMap<String, Vec<String>>>
where
    R: io::Read,
{
    let root = Element::parse(resp)?;

    let mut schema = root.children.iter().filter_map(|child| {
        let child = child.as_element()?;
        if child.name == "actionList" {
            parse_action_list(child)
        } else {
            None
        }
    });

    schema
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid response"))
}

fn parse_action_list(action_list: &Element) -> Option<HashMap<String, Vec<String>>> {
    Some(
        action_list
            .children
            .iter()
            .filter_map(|child| {
                let child = child.as_element()?;
                if child.name == "action" {
                    parse_action(child)
                } else {
                    None
                }
            })
            .collect(),
    )
}

fn parse_action(action: &Element) -> Option<(String, Vec<String>)> {
    Some((
        action.get_child("name")?.get_text()?.into_owned(),
        parse_argument_list(action.get_child("argumentList")?)?,
    ))
}

fn parse_argument_list(argument_list: &Element) -> Option<Vec<String>> {
    Some(
        argument_list
            .children
            .iter()
            .filter_map(|child| {
                let child = child.as_element()?;
                if child.name == "argument" {
                    parse_argument(child)
                } else {
                    None
                }
            })
            .collect(),
    )
}

fn parse_argument(action: &Element) -> Option<String> {
    if action
        .get_child("direction")?
        .get_text()?
        .into_owned()
        .as_str()
        == "in"
    {
        Some(action.get_child("name")?.get_text()?.into_owned())
    } else {
        None
    }
}

pub struct RequestReponse {
    text: String,
    xml: xmltree::Element,
}

pub type RequestResult = anyhow::Result<RequestReponse>;

pub fn parse_response(text: String, ok: &str) -> RequestResult {
    let mut xml = match xmltree::Element::parse(text.as_bytes()) {
        Ok(xml) => xml,
        Err(..) => return Err(anyhow::anyhow!("Invalid response: {}", text)),
    };
    let body = match xml.get_mut_child("Body") {
        Some(body) => body,
        None => return Err(anyhow::anyhow!("Invalid response: {}", text)),
    };
    if let Some(ok) = body.take_child(ok) {
        return Ok(RequestReponse { text, xml: ok });
    }
    let upnp_error = match body
        .get_child("Fault")
        .and_then(|e| e.get_child("detail"))
        .and_then(|e| e.get_child("UPnPError"))
    {
        Some(upnp_error) => upnp_error,
        None => return Err(anyhow::anyhow!("Invalid response: {}", text)),
    };

    match (
        upnp_error.get_child("errorCode"),
        upnp_error.get_child("errorDescription"),
    ) {
        (Some(e), Some(d)) => match (e.get_text().as_ref(), d.get_text().as_ref()) {
            (Some(et), Some(dt)) => match et.parse::<u16>() {
                Ok(en) => Err(anyhow::anyhow!("Error code {}: {}", en, dt)),
                Err(..) => Err(anyhow::anyhow!("Invalid response: {}", text)),
            },
            _ => Err(anyhow::anyhow!("Invalid response: {}", text)),
        },
        _ => Err(anyhow::anyhow!("Invalid response: {}", text)),
    }
}

pub fn parse_get_external_ip_response(result: RequestResult) -> anyhow::Result<Option<IpAddr>> {
    if let Ok(resp) = &result {
        let child = resp.xml.get_child("NewExternalIPAddress");
        if let Some(child) = child {
            let text = child.get_text();
            println!("text {:?}", text);
        }

        let child_empty = resp.xml.get_child("NewExternalIPAddressFuck");
        println!("child_empty {:?}", child_empty);
    }
    match result {
        Ok(resp) => {
            let child = resp.xml.get_child("NewExternalIPAddress");
            if let Some(child) = child {
                match child.get_text() {
                    Some(text) => {
                        Ok(Some(text.parse::<IpAddr>().with_context(|| {
                            format!("Invalid IP address: {}", text)
                        })?))
                    }
                    None => Ok(None),
                }
            } else {
                anyhow::bail!("Invalid response: {}", resp.text);
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("Error code 606") {
                Err(anyhow::anyhow!("Action not authorized"))
            } else {
                Err(e)
            }
        }
    }
}

pub fn parse_add_any_port_mapping_response(result: RequestResult) -> anyhow::Result<u16> {
    match result {
        Ok(resp) => {
            match resp
                .xml
                .get_child("NewReservedPort")
                .and_then(|e| e.get_text())
                .and_then(|t| t.parse::<u16>().ok())
            {
                Some(port) => Ok(port),
                None => Err(anyhow::anyhow!("Invalid response: {}", resp.text)),
            }
        }
        Err(err) => {
            let error_msg = err.to_string();
            if error_msg.contains("Error code 605") {
                Err(anyhow::anyhow!("Description too long"))
            } else if error_msg.contains("Error code 606") {
                Err(anyhow::anyhow!("Action not authorized"))
            } else if error_msg.contains("Error code 728") {
                Err(anyhow::anyhow!("No ports available"))
            } else {
                Err(err)
            }
        }
    }
}

pub fn convert_add_random_port_mapping_error(error: anyhow::Error) -> Option<anyhow::Error> {
    let error_msg = error.to_string();
    if error_msg.contains("Error code 724") {
        None
    } else if error_msg.contains("Error code 605") {
        Some(anyhow::anyhow!("Description too long"))
    } else if error_msg.contains("Error code 606") {
        Some(anyhow::anyhow!("Action not authorized"))
    } else if error_msg.contains("Error code 718") {
        Some(anyhow::anyhow!("No ports available"))
    } else if error_msg.contains("Error code 725") {
        Some(anyhow::anyhow!("Only permanent leases supported"))
    } else {
        Some(error)
    }
}

pub fn convert_add_same_port_mapping_error(error: anyhow::Error) -> anyhow::Error {
    let error_msg = error.to_string();
    if error_msg.contains("Error code 606") {
        anyhow::anyhow!("Action not authorized")
    } else if error_msg.contains("Error code 718") {
        anyhow::anyhow!("External port in use")
    } else if error_msg.contains("Error code 725") {
        anyhow::anyhow!("Only permanent leases supported")
    } else {
        error
    }
}

pub fn convert_add_port_error(err: anyhow::Error) -> anyhow::Error {
    let error_msg = err.to_string();
    if error_msg.contains("Error code 605") {
        anyhow::anyhow!("Description too long")
    } else if error_msg.contains("Error code 606") {
        anyhow::anyhow!("Action not authorized")
    } else if error_msg.contains("Error code 718") {
        anyhow::anyhow!("Port in use")
    } else if error_msg.contains("Error code 724") {
        anyhow::anyhow!("Same port values required")
    } else if error_msg.contains("Error code 725") {
        anyhow::anyhow!("Only permanent leases supported")
    } else {
        err
    }
}

pub fn parse_delete_port_mapping_response(result: RequestResult) -> anyhow::Result<()> {
    match result {
        Ok(_) => Ok(()),
        Err(err) => {
            let error_msg = err.to_string();
            if error_msg.contains("Error code 606") {
                Err(anyhow::anyhow!("Action not authorized"))
            } else if error_msg.contains("Error code 714") {
                Err(anyhow::anyhow!("No such port mapping"))
            } else {
                Err(err)
            }
        }
    }
}

/// One port mapping entry as returned by GetGenericPortMappingEntry
pub struct PortMappingEntry {
    /// The remote host for which the mapping is valid
    /// Can be an IP address or a host name
    pub remote_host: String,
    /// The external port of the mapping
    pub external_port: u16,
    /// The protocol of the mapping
    pub protocol: PortMappingProtocol,
    /// The internal (local) port
    pub internal_port: u16,
    /// The internal client of the port mapping
    /// Can be an IP address or a host name
    pub internal_client: String,
    /// A flag whether this port mapping is enabled
    pub enabled: bool,
    /// A description for this port mapping
    pub port_mapping_description: String,
    /// The lease duration of this port mapping in seconds
    pub lease_duration: u32,
}

pub fn parse_get_generic_port_mapping_entry(
    result: RequestResult,
) -> anyhow::Result<PortMappingEntry> {
    let response = result?;
    let xml = response.xml;
    let make_err = |msg: String| move || anyhow::anyhow!("Invalid response: {}", msg);
    let extract_field = |field: &str| {
        xml.get_child(field)
            .ok_or_else(make_err(format!("{field} is missing")))
    };
    let remote_host = extract_field("NewRemoteHost")?
        .get_text()
        .map(|c| c.into_owned())
        .unwrap_or_else(|| "".into());
    let external_port = extract_field("NewExternalPort")?
        .get_text()
        .and_then(|t| t.parse::<u16>().ok())
        .ok_or_else(make_err("Field NewExternalPort is invalid".into()))?;
    let protocol = match extract_field("NewProtocol")?.get_text() {
        Some(std::borrow::Cow::Borrowed("UDP")) => PortMappingProtocol::Udp,
        Some(std::borrow::Cow::Borrowed("TCP")) => PortMappingProtocol::Tcp,
        _ => {
            return Err(anyhow::anyhow!(
                "Invalid response: Field NewProtocol is invalid"
            ))
        }
    };
    let internal_port = extract_field("NewInternalPort")?
        .get_text()
        .and_then(|t| t.parse::<u16>().ok())
        .ok_or_else(make_err("Field NewInternalPort is invalid".into()))?;
    let internal_client = extract_field("NewInternalClient")?
        .get_text()
        .map(|c| c.into_owned())
        .ok_or_else(make_err("Field NewInternalClient is empty".into()))?;
    let enabled = match extract_field("NewEnabled")?
        .get_text()
        .and_then(|t| t.parse::<u16>().ok())
        .ok_or_else(make_err("Field Enabled is invalid".into()))?
    {
        0 => false,
        1 => true,
        _ => {
            return Err(anyhow::anyhow!(
                "Invalid response: Field NewEnabled is invalid"
            ))
        }
    };
    let port_mapping_description = extract_field("NewPortMappingDescription")?
        .get_text()
        .map(|c| c.into_owned())
        .unwrap_or_else(|| "".into());
    let lease_duration = extract_field("NewLeaseDuration")?
        .get_text()
        .and_then(|t| t.parse::<u32>().ok())
        .ok_or_else(make_err("Field NewLeaseDuration is invalid".into()))?;
    Ok(PortMappingEntry {
        remote_host,
        external_port,
        protocol,
        internal_port,
        internal_client,
        enabled,
        port_mapping_description,
        lease_duration,
    })
}

#[test]
fn test_parse_search_result_case_insensitivity() {
    assert!(parse_search_result("location:http://0.0.0.0:0/control_url").is_ok());
    assert!(parse_search_result("LOCATION:http://0.0.0.0:0/control_url").is_ok());
}

#[test]
fn test_parse_search_result_ok() {
    let result = parse_search_result("location:http://0.0.0.0:0/control_url").unwrap();
    assert_eq!(
        result.0.ip(),
        IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))
    );
    assert_eq!(result.0.port(), 0);
    assert_eq!(&result.1[..], "/control_url");
}

#[test]
fn test_parse_search_result_fail() {
    assert!(parse_search_result("content-type:http://0.0.0.0:0/control_url").is_err());
}

#[test]
fn test_parse_device1() {
    let text = r#"<?xml version="1.0" encoding="UTF-8"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
   <specVersion>
      <major>1</major>
      <minor>0</minor>
   </specVersion>
   <device>
      <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
      <friendlyName></friendlyName>
      <manufacturer></manufacturer>
      <manufacturerURL></manufacturerURL>
      <modelDescription></modelDescription>
      <modelName></modelName>
      <modelNumber>1</modelNumber>
      <serialNumber>00000000</serialNumber>
      <UDN></UDN>
      <serviceList>
         <service>
            <serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
            <serviceId>urn:upnp-org:serviceId:Layer3Forwarding1</serviceId>
            <controlURL>/ctl/L3F</controlURL>
            <eventSubURL>/evt/L3F</eventSubURL>
            <SCPDURL>/L3F.xml</SCPDURL>
         </service>
      </serviceList>
      <deviceList>
         <device>
            <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
            <friendlyName>WANDevice</friendlyName>
            <manufacturer>MiniUPnP</manufacturer>
            <manufacturerURL>http://miniupnp.free.fr/</manufacturerURL>
            <modelDescription>WAN Device</modelDescription>
            <modelName>WAN Device</modelName>
            <modelNumber>20180615</modelNumber>
            <modelURL>http://miniupnp.free.fr/</modelURL>
            <serialNumber>00000000</serialNumber>
            <UDN>uuid:804e2e56-7bfe-4733-bae0-04bf6d569692</UDN>
            <UPC>MINIUPNPD</UPC>
            <serviceList>
               <service>
                  <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
                  <serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId>
                  <controlURL>/ctl/CmnIfCfg</controlURL>
                  <eventSubURL>/evt/CmnIfCfg</eventSubURL>
                  <SCPDURL>/WANCfg.xml</SCPDURL>
               </service>
            </serviceList>
            <deviceList>
               <device>
                  <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
                  <friendlyName>WANConnectionDevice</friendlyName>
                  <manufacturer>MiniUPnP</manufacturer>
                  <manufacturerURL>http://miniupnp.free.fr/</manufacturerURL>
                  <modelDescription>MiniUPnP daemon</modelDescription>
                  <modelName>MiniUPnPd</modelName>
                  <modelNumber>20180615</modelNumber>
                  <modelURL>http://miniupnp.free.fr/</modelURL>
                  <serialNumber>00000000</serialNumber>
                  <UDN>uuid:804e2e56-7bfe-4733-bae0-04bf6d569692</UDN>
                  <UPC>MINIUPNPD</UPC>
                  <serviceList>
                     <service>
                        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                        <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
                        <controlURL>/ctl/IPConn</controlURL>
                        <eventSubURL>/evt/IPConn</eventSubURL>
                        <SCPDURL>/WANIPCn.xml</SCPDURL>
                     </service>
                  </serviceList>
               </device>
            </deviceList>
         </device>
      </deviceList>
      <presentationURL>http://192.168.0.1/</presentationURL>
   </device>
</root>"#;

    let (control_schema_url, control_url) = parse_control_urls(text.as_bytes()).unwrap();
    assert_eq!(control_url, "/ctl/IPConn");
    assert_eq!(control_schema_url, "/WANIPCn.xml");
}

#[test]
fn test_parse_device2() {
    let text = r#"<?xml version="1.0" encoding="UTF-8"?>
    <root xmlns="urn:schemas-upnp-org:device-1-0">
        <specVersion>
            <major>1</major>
            <minor>0</minor>
        </specVersion>
        <device>
            <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
            <friendlyName>FRITZ!Box 7430</friendlyName>
            <manufacturer>AVM Berlin</manufacturer>
            <manufacturerURL>http://www.avm.de</manufacturerURL>
            <modelDescription>FRITZ!Box 7430</modelDescription>
            <modelName>FRITZ!Box 7430</modelName>
            <modelNumber>avm</modelNumber>
            <modelURL>http://www.avm.de</modelURL>
            <UDN>uuid:00000000-0000-0000-0000-000000000000</UDN>
            <iconList>
                <icon>
                    <mimetype>image/gif</mimetype>
                    <width>118</width>
                    <height>119</height>
                    <depth>8</depth>
                    <url>/ligd.gif</url>
                </icon>
            </iconList>
            <serviceList>
                <service>
                    <serviceType>urn:schemas-any-com:service:Any:1</serviceType>
                    <serviceId>urn:any-com:serviceId:any1</serviceId>
                    <controlURL>/igdupnp/control/any</controlURL>
                    <eventSubURL>/igdupnp/control/any</eventSubURL>
                    <SCPDURL>/any.xml</SCPDURL>
                </service>
            </serviceList>
            <deviceList>
                <device>
                    <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
                    <friendlyName>WANDevice - FRITZ!Box 7430</friendlyName>
                    <manufacturer>AVM Berlin</manufacturer>
                    <manufacturerURL>www.avm.de</manufacturerURL>
                    <modelDescription>WANDevice - FRITZ!Box 7430</modelDescription>
                    <modelName>WANDevice - FRITZ!Box 7430</modelName>
                    <modelNumber>avm</modelNumber>
                    <modelURL>www.avm.de</modelURL>
                    <UDN>uuid:00000000-0000-0000-0000-000000000000</UDN>
                    <UPC>AVM IGD</UPC>
                    <serviceList>
                        <service>
                            <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
                            <serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId>
                            <controlURL>/igdupnp/control/WANCommonIFC1</controlURL>
                            <eventSubURL>/igdupnp/control/WANCommonIFC1</eventSubURL>
                            <SCPDURL>/igdicfgSCPD.xml</SCPDURL>
                        </service>
                    </serviceList>
                    <deviceList>
                        <device>
                            <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
                            <friendlyName>WANConnectionDevice - FRITZ!Box 7430</friendlyName>
                            <manufacturer>AVM Berlin</manufacturer>
                            <manufacturerURL>www.avm.de</manufacturerURL>
                            <modelDescription>WANConnectionDevice - FRITZ!Box 7430</modelDescription>
                            <modelName>WANConnectionDevice - FRITZ!Box 7430</modelName>
                            <modelNumber>avm</modelNumber>
                            <modelURL>www.avm.de</modelURL>
                            <UDN>uuid:00000000-0000-0000-0000-000000000000</UDN>
                            <UPC>AVM IGD</UPC>
                            <serviceList>
                                <service>
                                    <serviceType>urn:schemas-upnp-org:service:WANDSLLinkConfig:1</serviceType>
                                    <serviceId>urn:upnp-org:serviceId:WANDSLLinkC1</serviceId>
                                    <controlURL>/igdupnp/control/WANDSLLinkC1</controlURL>
                                    <eventSubURL>/igdupnp/control/WANDSLLinkC1</eventSubURL>
                                    <SCPDURL>/igddslSCPD.xml</SCPDURL>
                                </service>
                                <service>
                                    <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                                    <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
                                    <controlURL>/igdupnp/control/WANIPConn1</controlURL>
                                    <eventSubURL>/igdupnp/control/WANIPConn1</eventSubURL>
                                    <SCPDURL>/igdconnSCPD.xml</SCPDURL>
                                </service>
                                <service>
                                    <serviceType>urn:schemas-upnp-org:service:WANIPv6FirewallControl:1</serviceType>
                                    <serviceId>urn:upnp-org:serviceId:WANIPv6Firewall1</serviceId>
                                    <controlURL>/igd2upnp/control/WANIPv6Firewall1</controlURL>
                                    <eventSubURL>/igd2upnp/control/WANIPv6Firewall1</eventSubURL>
                                    <SCPDURL>/igd2ipv6fwcSCPD.xml</SCPDURL>
                                </service>
                            </serviceList>
                        </device>
                    </deviceList>
                </device>
            </deviceList>
            <presentationURL>http://fritz.box</presentationURL>
        </device>
    </root>
    "#;
    let result = parse_control_urls(text.as_bytes());
    assert!(result.is_ok());
    let (control_schema_url, control_url) = result.unwrap();
    assert_eq!(control_url, "/igdupnp/control/WANIPConn1");
    assert_eq!(control_schema_url, "/igdconnSCPD.xml");
}

#[test]
fn test_parse_device3() {
    let text = r#"<?xml version="1.0" encoding="UTF-8"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
<specVersion>
    <major>1</major>
    <minor>0</minor>
</specVersion>
<device xmlns="urn:schemas-upnp-org:device-1-0">
   <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
   <friendlyName></friendlyName>
   <manufacturer></manufacturer>
   <manufacturerURL></manufacturerURL>
   <modelDescription></modelDescription>
   <modelName></modelName>
   <modelNumber></modelNumber>
   <serialNumber></serialNumber>
   <presentationURL>http://192.168.1.1</presentationURL>
   <UDN>uuid:00000000-0000-0000-0000-000000000000</UDN>
   <UPC>999999999001</UPC>
   <iconList>
      <icon>
         <mimetype>image/png</mimetype>
         <width>16</width>
         <height>16</height>
         <depth>8</depth>
         <url>/ligd.png</url>
      </icon>
   </iconList>
   <deviceList>
      <device>
         <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
         <friendlyName></friendlyName>
         <manufacturer></manufacturer>
         <manufacturerURL></manufacturerURL>
         <modelDescription></modelDescription>
         <modelName></modelName>
         <modelNumber></modelNumber>
         <modelURL></modelURL>
         <serialNumber></serialNumber>
         <presentationURL>http://192.168.1.254</presentationURL>
         <UDN>uuid:00000000-0000-0000-0000-000000000000</UDN>
         <UPC>999999999001</UPC>
         <serviceList>
            <service>
               <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
               <serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId>
               <controlURL>/upnp/control/WANCommonIFC1</controlURL>
               <eventSubURL>/upnp/control/WANCommonIFC1</eventSubURL>
               <SCPDURL>/332b484d/wancomicfgSCPD.xml</SCPDURL>
            </service>
         </serviceList>
         <deviceList>
            <device>
               <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
               <friendlyName></friendlyName>
               <manufacturer></manufacturer>
               <manufacturerURL></manufacturerURL>
               <modelDescription></modelDescription>
               <modelName></modelName>
               <modelNumber></modelNumber>
               <modelURL></modelURL>
               <serialNumber></serialNumber>
               <presentationURL>http://192.168.1.254</presentationURL>
               <UDN>uuid:00000000-0000-0000-0000-000000000000</UDN>
               <UPC>999999999001</UPC>
               <serviceList>
                  <service>
                     <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                     <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
                     <controlURL>/upnp/control/WANIPConn1</controlURL>
                     <eventSubURL>/upnp/control/WANIPConn1</eventSubURL>
                     <SCPDURL>/332b484d/wanipconnSCPD.xml</SCPDURL>
                  </service>
               </serviceList>
            </device>
         </deviceList>
      </device>
   </deviceList>
</device>
</root>"#;

    let (control_schema_url, control_url) = parse_control_urls(text.as_bytes()).unwrap();
    assert_eq!(control_url, "/upnp/control/WANIPConn1");
    assert_eq!(control_schema_url, "/332b484d/wanipconnSCPD.xml");
}
