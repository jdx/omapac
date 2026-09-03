//! A minimal HTTP server for tests. `serve` answers GETs from a route
//! table; `serve_with` hands every request (method, path, body) to a
//! handler, which is how the fake transparency log computes its answers.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

pub type Handler = dyn Fn(&str, &str, &[u8]) -> (u16, String) + Send + Sync;

pub fn serve_with(handler: Arc<Handler>) -> String {
    serve_with_at("127.0.0.1:0", handler)
}

/// Serve on a chosen address (`host:port`), for a test that needs to know
/// its base URL before building the content.
pub fn serve_with_at(addr: &str, handler: Arc<Handler>) -> String {
    let listener = TcpListener::bind(addr).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                continue;
            };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() {
                continue;
            }
            let mut length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() || line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; length];
            if length > 0 {
                let _ = reader.read_exact(&mut body);
            }
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or("GET").to_string();
            let path = parts.next().unwrap_or("/").to_string();
            let (status, response) = handler(&method, &path, &body);
            let reason = match status {
                200 => "OK",
                201 => "Created",
                404 => "Not Found",
                _ => "Error",
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                response.len()
            );
            let _ = stream.flush();
        }
    });
    base
}

/// Serve exact paths from a table.
pub fn serve(routes: Vec<(String, String)>) -> String {
    serve_with(table(routes))
}

/// Serve exact paths from a table at a base URL chosen earlier.
pub fn serve_at(base: &str, routes: Vec<(String, String)>) -> String {
    let addr = base.trim_start_matches("http://");
    serve_with_at(addr, table(routes))
}

fn table(routes: Vec<(String, String)>) -> Arc<Handler> {
    Arc::new(
        move |_method, path, _body| match routes.iter().find(|(p, _)| p == path) {
            Some((_, body)) => (200, body.clone()),
            None => (404, "{}".to_string()),
        },
    )
}
