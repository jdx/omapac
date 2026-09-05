//! Downloading upstream artifacts: streamed to disk while every digest a
//! PKGBUILD might carry is computed, so a multi-hundred-megabyte `.deb`
//! never sits in memory.

use std::io::{Read as _, Write as _};
use std::path::Path;
use std::time::Duration;

use eyre::{Context as _, Result, bail};
use sha2::Digest as _;

/// Larger than any desktop app we repackage; a guard, not a budget.
const MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// What a download produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// Lowercase hex.
    pub sha256: String,
    /// Lowercase hex.
    pub sha512: String,
    /// Lowercase hex, BLAKE2b-512 as makepkg's `b2sums` uses.
    pub blake2b: String,
    pub size: u64,
}

/// Download `url` to `dest`, replacing it, and return its digests.
pub fn fetch_to_file(url: &str, dest: &Path) -> Result<Fetched> {
    let agent = download_agent(Duration::from_secs(30), Duration::from_secs(15 * 60));
    fetch_with_agent(url, dest, &agent)
}

fn download_agent(setup: Duration, body: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .user_agent(concat!("pacvamp-repo/", env!("CARGO_PKG_VERSION")))
        .timeout_resolve(Some(setup))
        .timeout_connect(Some(setup))
        .timeout_send_request(Some(setup))
        .timeout_recv_response(Some(setup))
        .timeout_recv_body(Some(body))
        .timeout_global(Some(setup + body))
        .build()
        .into()
}

fn fetch_with_agent(url: &str, dest: &Path, agent: &ureq::Agent) -> Result<Fetched> {
    let mut response = agent
        .get(url)
        .call()
        .wrap_err_with(|| format!("fetching {url}"))?;
    let mut reader = response.body_mut().with_config().limit(MAX_BYTES).reader();
    let parent = dest
        .parent()
        .ok_or_else(|| eyre::eyre!("download destination has no parent"))?;
    let mut file = tempfile::NamedTempFile::new_in(parent)
        .wrap_err_with(|| format!("staging {}", dest.display()))?;
    let mut sha256 = sha2::Sha256::new();
    let mut sha512 = sha2::Sha512::new();
    let mut blake2b = blake2::Blake2b512::new();
    let mut size = 0u64;
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = reader
            .read(&mut buf)
            .wrap_err_with(|| format!("reading {url}"))?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])
            .wrap_err_with(|| format!("writing {}", dest.display()))?;
        sha256.update(&buf[..n]);
        sha512.update(&buf[..n]);
        blake2b.update(&buf[..n]);
        size += n as u64;
    }
    file.flush()?;
    if size == 0 {
        bail!("{url} is empty");
    }
    file.persist(dest)
        .wrap_err_with(|| format!("publishing {}", dest.display()))?;
    Ok(Fetched {
        sha256: format!("{:x}", sha256.finalize()),
        sha512: format!("{:x}", sha512.finalize()),
        blake2b: format!("{:x}", blake2b.finalize()),
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead as _, BufReader};
    use std::net::TcpListener;
    use std::sync::mpsc;

    #[test]
    fn stalled_headers_and_bodies_time_out_without_replacing_cached_files() {
        for send_headers in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}/artifact", listener.local_addr().unwrap());
            let (done, wait) = mpsc::channel();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                        break;
                    }
                }
                if send_headers {
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\na")
                        .unwrap();
                    stream.flush().unwrap();
                }
                let _ = wait.recv_timeout(Duration::from_secs(5));
            });
            let dir = tempfile::tempdir().unwrap();
            let dest = dir.path().join("artifact");
            std::fs::write(&dest, b"cached").unwrap();
            let agent = download_agent(Duration::from_millis(250), Duration::from_millis(250));
            let result = fetch_with_agent(&url, &dest, &agent);
            done.send(()).unwrap();
            server.join().unwrap();
            let error = format!("{:#}", result.unwrap_err()).to_ascii_lowercase();
            assert!(
                error.contains("timeout") || error.contains("timed out"),
                "{error}"
            );
            assert_eq!(std::fs::read(&dest).unwrap(), b"cached");
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }
}
