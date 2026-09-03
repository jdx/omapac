//! A minimal HTTP server for tests: answers each request with a canned
//! body chosen by a prefix of the request path. Enough for the AUR RPC.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::thread;

/// Serve `routes` (path prefix, body) until the process exits; returns the
/// base URL.
pub fn serve(routes: Vec<(&'static str, String)>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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
            // Drain headers.
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() || line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            let path = request_line.split_whitespace().nth(1).unwrap_or("/");
            let (status, body) = match routes.iter().find(|(prefix, _)| path.starts_with(prefix)) {
                Some((_, body)) => ("200 OK", body.clone()),
                None => ("404 Not Found", "{}".to_string()),
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.flush();
        }
    });
    base
}
