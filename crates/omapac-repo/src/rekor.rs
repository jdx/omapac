//! Rekor, the public transparency log: uploading a DSSE envelope as a
//! `dsse` entry and checking a stored entry against the envelope beside a
//! package. See `docs/spec/provenance.md`, "Transparency".

use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use eyre::{Context as _, Result, bail};
use packslip::dsse::Envelope;
use packslip::minisign::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// The sidecar suffix for a stored log entry.
pub const SIDECAR: &str = ".rekor.json";

/// What we keep of a log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub log_url: String,
    pub uuid: String,
    pub log_index: u64,
    pub log_id: String,
    pub integrated_time: u64,
    /// The canonical entry body, base64 as the log returns it.
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inclusion_proof: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_entry_timestamp: Option<String>,
}

/// `<package>.rekor.json`.
pub fn sidecar_path(package: &Path) -> PathBuf {
    let mut name = package.as_os_str().to_owned();
    name.push(SIDECAR);
    PathBuf::from(name)
}

/// Lowercase hex sha256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// An Ed25519 public key as SPKI PEM, which is how Rekor wants verifiers.
pub fn spki_pem(key: &PublicKey) -> String {
    const PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let mut der = PREFIX.to_vec();
    der.extend_from_slice(key.key.as_bytes());
    let b64 = BASE64.encode(der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

/// Upload `envelope` as a `dsse` entry verified by `key`.
pub fn upload(log_url: &str, envelope: &Envelope, key: &PublicKey) -> Result<Entry> {
    let proposed = serde_json::json!({
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "proposedContent": {
                "envelope": serde_json::to_string(envelope)?,
                "verifiers": [BASE64.encode(spki_pem(key))],
            }
        }
    });
    let url = format!("{}/api/v1/log/entries", log_url.trim_end_matches('/'));
    let body = serde_json::to_vec(&proposed)?;
    let mut response = ureq::post(&url)
        .config()
        .http_status_as_error(false)
        .build()
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .send(body.as_slice())
        .wrap_err_with(|| format!("uploading to {url}"))?;
    let status = response.status().as_u16();
    if !(response.status().is_success() || status == 409) {
        bail!("uploading to {url}: HTTP {status}");
    }
    let text = if status == 409 {
        let location = response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| eyre::eyre!("the log reported an existing entry without a Location"))?;
        let location = if location.starts_with("http://") || location.starts_with("https://") {
            location
        } else if location.starts_with('/') {
            format!("{}{}", log_url.trim_end_matches('/'), location)
        } else {
            format!("{}/{}", log_url.trim_end_matches('/'), location)
        };
        ureq::get(&location)
            .header("Accept", "application/json")
            .call()
            .wrap_err_with(|| format!("fetching existing log entry from {location}"))?
            .body_mut()
            .read_to_string()
            .wrap_err("reading the existing log entry")?
    } else {
        response
            .body_mut()
            .read_to_string()
            .wrap_err("reading the log's response")?
    };
    let response: serde_json::Value =
        serde_json::from_str(&text).wrap_err("parsing the log's response")?;
    let Some((uuid, entry)) = response.as_object().and_then(|m| m.iter().next()) else {
        bail!("the log returned no entry");
    };
    let required_u64 = |name: &str| {
        entry
            .get(name)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| eyre::eyre!("the log entry has no numeric {name}"))
    };
    let required_str = |name: &str| {
        entry
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| eyre::eyre!("the log entry has no string {name}"))
    };
    Ok(Entry {
        log_url: log_url.trim_end_matches('/').to_string(),
        uuid: uuid.clone(),
        log_index: required_u64("logIndex")?,
        log_id: required_str("logID")?,
        integrated_time: required_u64("integratedTime")?,
        body: required_str("body")?,
        inclusion_proof: entry
            .get("verification")
            .and_then(|v| v.get("inclusionProof"))
            .cloned(),
        signed_entry_timestamp: entry
            .get("verification")
            .and_then(|v| v.get("signedEntryTimestamp"))
            .and_then(|v| v.as_str())
            .map(str::to_string),
    })
}

/// Read a stored entry, if any.
pub fn read(path: &Path) -> Result<Option<Entry>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(
            serde_json::from_str(&text).wrap_err_with(|| format!("parsing {}", path.display()))?,
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).wrap_err_with(|| format!("reading {}", path.display())),
    }
}

/// Check that a stored entry is about `envelope`: its body is a `dsse`
/// entry whose payload hash is the envelope's payload, and it carries an
/// inclusion proof.
pub fn check(entry: &Entry, envelope: &Envelope) -> Result<()> {
    let body = BASE64
        .decode(&entry.body)
        .wrap_err("entry body is not base64")?;
    let body: serde_json::Value =
        serde_json::from_slice(&body).wrap_err("entry body is not JSON")?;
    if body["kind"] != "dsse" {
        bail!("entry kind is {}, not dsse", body["kind"]);
    }
    let payload = envelope.payload_bytes()?;
    let expected = sha256_hex(&payload);
    let actual = body["spec"]["payloadHash"]["value"]
        .as_str()
        .unwrap_or_default();
    if !actual.eq_ignore_ascii_case(&expected) {
        bail!("entry payload hash {actual} is not the envelope's {expected}");
    }
    if entry.inclusion_proof.is_none() {
        bail!("entry has no inclusion proof");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};
    use std::net::TcpListener;

    #[test]
    fn pem_is_spki_ed25519() {
        let key = packslip::minisign::SecretKey::from_seed([1u8; 32]).public_key();
        let pem = spki_pem(&key);
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA"));
        assert!(pem.ends_with("-----END PUBLIC KEY-----\n"));
    }

    #[test]
    fn check_matches_payload_hash_and_proof() {
        let key = packslip::minisign::SecretKey::from_seed([2u8; 32]);
        let envelope = Envelope::sign("t", b"payload", &key);
        let body = serde_json::json!({"apiVersion":"0.0.1","kind":"dsse","spec":{"payloadHash":{"algorithm":"sha256","value":sha256_hex(b"payload")}}});
        let mut entry = Entry {
            log_url: "http://log".into(),
            uuid: "u".into(),
            log_index: 1,
            log_id: "l".into(),
            integrated_time: 1,
            body: BASE64.encode(serde_json::to_vec(&body).unwrap()),
            inclusion_proof: Some(serde_json::json!({"logIndex":1})),
            signed_entry_timestamp: None,
        };
        check(&entry, &envelope).unwrap();
        entry.inclusion_proof = None;
        assert!(
            check(&entry, &envelope)
                .unwrap_err()
                .to_string()
                .contains("inclusion proof")
        );
        let other = Envelope::sign("t", b"other", &key);
        entry.inclusion_proof = Some(serde_json::json!({}));
        assert!(
            check(&entry, &other)
                .unwrap_err()
                .to_string()
                .contains("payload hash")
        );
    }

    #[test]
    fn upload_accepts_an_existing_entry() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let response = serde_json::json!({
            "existing": {
                "logIndex": 7,
                "logID": "log",
                "integratedTime": 9,
                "body": "body",
                "verification": {"inclusionProof": {"logIndex": 7}}
            }
        })
        .to_string();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let mut length = 0;
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            write!(
                stream,
                "HTTP/1.1 409 Conflict\r\nLocation: /api/v1/log/entries/existing\r\nContent-Type: application/json\r\nContent-Length: 18\r\nConnection: close\r\n\r\n{{\"code\":\"409\"}}"
            )
            .unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
            }
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                response.len()
            )
            .unwrap();
        });
        let key = packslip::minisign::SecretKey::from_seed([3u8; 32]);
        let envelope = Envelope::sign("t", b"payload", &key);
        let entry = upload(&url, &envelope, &key.public_key()).unwrap();
        assert_eq!(entry.uuid, "existing");
        assert_eq!(entry.log_index, 7);
    }
}
