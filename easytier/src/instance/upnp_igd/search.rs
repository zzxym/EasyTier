//! Tokio abstraction for the aio [`Gateway`].

use std::collections::HashMap;
use std::net::SocketAddr;

use http_req::response::Headers;
use tokio::{net::UdpSocket, time::timeout};

use super::common::options::{DEFAULT_TIMEOUT, RESPONSE_TIMEOUT};
use super::common::{messages, parsing, SearchOptions};
use super::gateway::Gateway;
use super::{Provider, HEADER_NAME, MAX_RESPONSE_SIZE};
use tracing::debug;

/// Tokio provider for the [`Gateway`].
#[derive(Debug, Clone)]
pub struct Tokio;

#[async_trait::async_trait]
impl Provider for Tokio {
    async fn send_async(url: &str, action: &str, body: &str) -> anyhow::Result<String> {
        use http_req::request;

        // Run the blocking HTTP request in a separate thread to avoid blocking the async runtime
        let url_owned = url.to_string();
        let body_clone = body.to_string();
        let action_clone = action.to_string();

        let (response, response_body) = tokio::task::spawn_blocking(move || {
            let uri = http_req::uri::Uri::try_from(url_owned.as_str())
                .map_err(|e| anyhow::anyhow!("URI parse error: {}", e))?;

            println!("body: {body_clone}, action: {action_clone}");

            let mut response_body = Vec::new();
            let response = request::Request::new(&uri)
                .method(request::Method::POST)
                .header(HEADER_NAME, &action_clone)
                .header("Content-Type", "text/xml; charset=\"utf-8\"")
                .body(body_clone.as_bytes())
                .send(&mut response_body);

            if response.is_err() {
                if response_body.is_empty() {
                    anyhow::bail!("HTTP request error: {}", response.unwrap_err());
                } else {
                    anyhow::bail!(
                        "HTTP request error: {} with response body: {}",
                        response.unwrap_err(),
                        String::from_utf8_lossy(&response_body)
                    );
                }
            }

            let response = response.unwrap();
            Ok::<_, anyhow::Error>((response, response_body))
        })
        .await
        .map_err(|e| anyhow::anyhow!("Task join error: {}", e))??;

        if !response.status_code().is_success() {
            if response_body.is_empty() {
                return Err(anyhow::anyhow!(
                    "HTTP error with empty body: {}",
                    response.status_code()
                ));
            }
        }

        let string = String::from_utf8(response_body)
            .map_err(|e| anyhow::anyhow!("UTF-8 conversion error: {}", e))?;
        Ok(string)
    }
}

/// Search for a gateway with the provided options.
pub async fn search_gateway(options: SearchOptions) -> anyhow::Result<Gateway<Tokio>> {
    let search_timeout = options.timeout.unwrap_or(DEFAULT_TIMEOUT);
    match timeout(search_timeout, search_gateway_inner(options)).await {
        Ok(Ok(gateway)) => Ok(gateway),
        Ok(Err(err)) => Err(err),
        Err(_err) => {
            // Timeout
            Err(anyhow::anyhow!("No response within timeout"))
        }
    }
}

async fn search_gateway_inner(options: SearchOptions) -> anyhow::Result<Gateway<Tokio>> {
    // Create socket for future calls
    let mut socket = UdpSocket::bind(&options.bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind socket: {}", e))?;

    send_search_request(&mut socket, options.broadcast_address).await?;
    let response_timeout = options.single_search_timeout.unwrap_or(RESPONSE_TIMEOUT);

    loop {
        let search_response = receive_search_response(&mut socket);

        // Receive search response
        let (response_body, from) = match timeout(response_timeout, search_response).await {
            Ok(Ok(v)) => v,
            Ok(Err(err)) => {
                debug!("error while receiving broadcast response: {err}");
                continue;
            }
            Err(_) => {
                debug!("timeout while receiving broadcast response");
                continue;
            }
        };

        let (addr, root_url) = match handle_broadcast_resp(&from, &response_body) {
            Ok(v) => v,
            Err(e) => {
                debug!("error handling broadcast response: {}", e);
                continue;
            }
        };

        let (control_schema_url, control_url) = match get_control_urls(&addr, &root_url).await {
            Ok(v) => v,
            Err(e) => {
                debug!("error getting control URLs: {}", e);
                continue;
            }
        };

        let control_schema = match get_control_schemas(&addr, &control_schema_url).await {
            Ok(v) => v,
            Err(e) => {
                debug!("error getting control schemas: {}", e);
                continue;
            }
        };

        return Ok(Gateway {
            addr,
            root_url,
            control_url,
            control_schema_url,
            control_schema,
            provider: Tokio,
        });
    }
}

// Create a new search.
async fn send_search_request(socket: &mut UdpSocket, addr: SocketAddr) -> anyhow::Result<()> {
    debug!(
        "sending broadcast request to: {} on interface: {:?}",
        addr,
        socket.local_addr()
    );
    socket
        .send_to(messages::SEARCH_REQUEST.as_bytes(), &addr)
        .await
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("Failed to send search request: {}", e))
}

async fn receive_search_response(socket: &mut UdpSocket) -> anyhow::Result<(Vec<u8>, SocketAddr)> {
    let mut buff = [0u8; MAX_RESPONSE_SIZE];
    let (n, from) = socket
        .recv_from(&mut buff)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to receive response: {}", e))?;
    debug!("received broadcast response from: {}", from);
    Ok((buff[..n].to_vec(), from))
}

// Handle a UDP response message.
fn handle_broadcast_resp(from: &SocketAddr, data: &[u8]) -> anyhow::Result<(SocketAddr, String)> {
    debug!("handling broadcast response from: {}", from);

    // Convert response to text.
    let text =
        std::str::from_utf8(data).map_err(|e| anyhow::anyhow!("UTF-8 conversion error: {}", e))?;

    // Parse socket address and path.
    let (addr, root_url) = parsing::parse_search_result(text)?;

    Ok((addr, root_url))
}

async fn get_control_urls(addr: &SocketAddr, path: &str) -> anyhow::Result<(String, String)> {
    use http_req::request;

    let url = format!("http://{addr}{path}");
    debug!("requesting control url from: {}", url);

    // Run the blocking HTTP request in a separate thread to avoid blocking the async runtime
    let (response, response_body) = tokio::task::spawn_blocking(move || {
        let uri = http_req::uri::Uri::try_from(url.as_str())
            .map_err(|e| anyhow::anyhow!("URI parse error: {}", e))?;

        let mut response_body = Vec::new();
        let response = request::Request::new(&uri)
            .method(request::Method::GET)
            .send(&mut response_body)
            .map_err(|e| anyhow::anyhow!("HTTP GET error: {}", e))?;

        Ok::<_, anyhow::Error>((response, response_body))
    })
    .await
    .map_err(|e| anyhow::anyhow!("Task join error: {}", e))??;

    if !response.status_code().is_success() {
        return Err(anyhow::anyhow!("HTTP error: {}", response.status_code()));
    }

    debug!("handling control response from: {addr}");
    let c = std::io::Cursor::new(&response_body);
    parsing::parse_control_urls(c)
}

async fn get_control_schemas(
    addr: &SocketAddr,
    control_schema_url: &str,
) -> anyhow::Result<HashMap<String, Vec<String>>> {
    use http_req::request;

    let url = format!("http://{addr}{control_schema_url}");
    debug!("requesting control schema from: {}", url);

    // Run the blocking HTTP request in a separate thread to avoid blocking the async runtime
    let (response, response_body) = tokio::task::spawn_blocking(move || {
        let uri = http_req::uri::Uri::try_from(url.as_str())
            .map_err(|e| anyhow::anyhow!("URI parse error: {}", e))?;

        let mut response_body = Vec::new();
        let response = request::Request::new(&uri)
            .method(request::Method::GET)
            .send(&mut response_body)
            .map_err(|e| anyhow::anyhow!("HTTP GET error: {}", e))?;

        Ok::<_, anyhow::Error>((response, response_body))
    })
    .await
    .map_err(|e| anyhow::anyhow!("Task join error: {}", e))??;

    if !response.status_code().is_success() {
        return Err(anyhow::anyhow!("HTTP error: {}", response.status_code()));
    }

    debug!("handling schema response from: {addr}");
    let c = std::io::Cursor::new(&response_body);
    parsing::parse_schemas(c)
}
