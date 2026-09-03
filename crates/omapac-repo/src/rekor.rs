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

/// An inclusion proof as the log returns it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct InclusionProof {
    #[serde(rename = "logIndex")]
    pub log_index: u64,
    #[serde(rename = "treeSize")]
    pub tree_size: u64,
    /// Hex.
    #[serde(rename = "rootHash")]
    pub root_hash: String,
    /// Hex sibling hashes, leaf to root.
    #[serde(default)]
    pub hashes: Vec<String>,
    /// The signed checkpoint (a signed note) the proof leads to.
    #[serde(default)]
    pub checkpoint: Option<String>,
}

/// RFC 6962 leaf hash: `SHA256(0x00 || leaf)`.
pub fn leaf_hash(leaf: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0u8]);
    hasher.update(leaf);
    hasher.finalize().into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([1u8]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// The root a leaf at `index` in a tree of `size` reaches through
/// `proof`, per RFC 6962 as transparency-dev computes it.
pub fn root_from_inclusion(
    index: u64,
    size: u64,
    leaf: [u8; 32],
    proof: &[[u8; 32]],
) -> Result<[u8; 32]> {
    if index >= size {
        bail!("leaf index {index} is outside a tree of size {size}");
    }
    let inner = 64 - (index ^ (size - 1)).leading_zeros() as usize;
    let border = index.checked_shr(inner as u32).unwrap_or(0).count_ones() as usize;
    if proof.len() != inner + border {
        bail!(
            "inclusion proof has {} hashes, expected {}",
            proof.len(),
            inner + border
        );
    }
    let mut hash = leaf;
    for (i, sibling) in proof[..inner].iter().enumerate() {
        hash = if (index >> i) & 1 == 0 {
            node_hash(&hash, sibling)
        } else {
            node_hash(sibling, &hash)
        };
    }
    for sibling in &proof[inner..] {
        hash = node_hash(sibling, &hash);
    }
    Ok(hash)
}

/// A parsed checkpoint: the signed note's origin, size, root, and the
/// signature lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub origin: String,
    pub size: u64,
    pub root: [u8; 32],
    /// The text the signatures cover.
    pub body: String,
    /// `(name, key hint, DER signature)`.
    pub signatures: Vec<(String, [u8; 4], Vec<u8>)>,
}

impl Checkpoint {
    pub fn parse(text: &str) -> Result<Checkpoint> {
        let Some((body, sigs)) = text.split_once("\n\n") else {
            bail!("checkpoint has no signature section");
        };
        let mut lines = body.lines();
        let origin = lines.next().unwrap_or_default().to_string();
        let size: u64 = lines
            .next()
            .unwrap_or_default()
            .trim()
            .parse()
            .wrap_err("checkpoint tree size")?;
        let root = BASE64
            .decode(lines.next().unwrap_or_default().trim())
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| eyre::eyre!("checkpoint root hash is not 32 base64 bytes"))?;
        let mut signatures = Vec::new();
        for line in sigs.lines() {
            let Some(rest) = line.strip_prefix("\u{2014} ") else {
                continue;
            };
            let Some((name, sig)) = rest.split_once(' ') else {
                continue;
            };
            let bytes = BASE64.decode(sig.trim()).wrap_err("checkpoint signature")?;
            if bytes.len() < 5 {
                bail!("checkpoint signature is too short");
            }
            let mut hint = [0u8; 4];
            hint.copy_from_slice(&bytes[..4]);
            signatures.push((name.to_string(), hint, bytes[4..].to_vec()));
        }
        Ok(Checkpoint {
            origin,
            size,
            root,
            body: format!("{body}\n"),
            signatures,
        })
    }

    /// Verify a signature line with the log's ECDSA P-256 key.
    pub fn verify(&self, key: &p256::ecdsa::VerifyingKey) -> Result<()> {
        use p256::ecdsa::signature::Verifier as _;
        if self.signatures.is_empty() {
            bail!("checkpoint carries no signature");
        }
        for (_, _, der) in &self.signatures {
            if let Ok(sig) = p256::ecdsa::Signature::from_der(der)
                && key.verify(self.body.as_bytes(), &sig).is_ok()
            {
                return Ok(());
            }
        }
        bail!("no checkpoint signature verifies with the log key")
    }
}

/// Parse a log's public key from SPKI PEM.
pub fn log_key(pem: &str) -> Result<p256::ecdsa::VerifyingKey> {
    use p256::pkcs8::DecodePublicKey as _;
    p256::ecdsa::VerifyingKey::from_public_key_pem(pem).map_err(|e| eyre::eyre!("log key: {e}"))
}

/// Verify the entry's inclusion proof: the leaf is the entry body, the
/// proof reaches the stated root, the checkpoint (when present) commits
/// to that root and size, and, with `key`, the checkpoint is signed by
/// the log.
pub fn verify_inclusion(entry: &Entry, key: Option<&p256::ecdsa::VerifyingKey>) -> Result<()> {
    let Some(raw) = &entry.inclusion_proof else {
        bail!("entry has no inclusion proof");
    };
    let proof: InclusionProof = serde_json::from_value(raw.clone()).wrap_err("inclusion proof")?;
    let body = BASE64
        .decode(&entry.body)
        .wrap_err("entry body is not base64")?;
    let mut hashes = Vec::new();
    for h in &proof.hashes {
        let bytes = decode_hash(h)?;
        hashes.push(bytes);
    }
    let root = root_from_inclusion(proof.log_index, proof.tree_size, leaf_hash(&body), &hashes)?;
    let root_hex: String = root.iter().map(|b| format!("{b:02x}")).collect();
    if !root_hex.eq_ignore_ascii_case(&proof.root_hash) {
        bail!(
            "inclusion proof reaches root {root_hex}, not the stated {}",
            proof.root_hash
        );
    }
    match &proof.checkpoint {
        Some(text) => {
            let checkpoint = Checkpoint::parse(text)?;
            if checkpoint.size != proof.tree_size {
                bail!(
                    "checkpoint is for tree size {}, proof for {}",
                    checkpoint.size,
                    proof.tree_size
                );
            }
            if checkpoint.root != root {
                bail!("checkpoint root does not match the proof's root");
            }
            if let Some(key) = key {
                checkpoint.verify(key)?;
            }
        }
        None => {
            if key.is_some() {
                bail!("entry has no checkpoint to verify the log signature on");
            }
        }
    }
    Ok(())
}

fn decode_hash(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        bail!("inclusion proof hash is not 32 hex bytes");
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| eyre::eyre!("inclusion proof hash is not 32 hex bytes"))?;
    }
    Ok(bytes)
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

    /// RFC 6962 reference: MTH and PATH by recursive splitting.
    fn mth(leaves: &[Vec<u8>]) -> [u8; 32] {
        match leaves.len() {
            0 => Sha256::digest(b"").into(),
            1 => leaf_hash(&leaves[0]),
            n => {
                let k = (n - 1).next_power_of_two().max(1);
                let k = if k >= n { k / 2 } else { k };
                node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
            }
        }
    }

    fn path(m: usize, leaves: &[Vec<u8>]) -> Vec<[u8; 32]> {
        let n = leaves.len();
        if n <= 1 {
            return Vec::new();
        }
        let k = (n - 1).next_power_of_two().max(1);
        let k = if k >= n { k / 2 } else { k };
        if m < k {
            let mut p = path(m, &leaves[..k]);
            p.push(mth(&leaves[k..]));
            p
        } else {
            let mut p = path(m - k, &leaves[k..]);
            p.push(mth(&leaves[..k]));
            p
        }
    }

    #[test]
    fn inclusion_proofs_reach_the_reference_root() {
        for size in 1..=17u64 {
            let leaves: Vec<Vec<u8>> = (0..size)
                .map(|i| format!("leaf {i}").into_bytes())
                .collect();
            let root = mth(&leaves);
            for index in 0..size {
                let proof = path(index as usize, &leaves);
                let got =
                    root_from_inclusion(index, size, leaf_hash(&leaves[index as usize]), &proof)
                        .unwrap();
                assert_eq!(got, root, "size {size} index {index}");
                if !proof.is_empty() {
                    let mut wrong = proof.clone();
                    wrong[0][0] ^= 1;
                    assert_ne!(
                        root_from_inclusion(
                            index,
                            size,
                            leaf_hash(&leaves[index as usize]),
                            &wrong
                        )
                        .unwrap(),
                        root
                    );
                }
            }
        }
        assert!(root_from_inclusion(3, 3, [0; 32], &[]).is_err());
        assert!(
            root_from_inclusion(0, 2, [0; 32], &[]).is_err(),
            "proof length is checked"
        );
    }

    #[test]
    fn full_width_proof_depth_does_not_overflow_the_shift() {
        let err = root_from_inclusion(0, u64::MAX, leaf_hash(b"leaf"), &[]).unwrap_err();
        assert!(err.to_string().contains("expected 64"), "{err}");
    }

    #[test]
    fn inclusion_proof_parses_rekor_hex_siblings() {
        let leaves = [b"left".to_vec(), b"right".to_vec()];
        let sibling = leaf_hash(&leaves[1]);
        let root = node_hash(&leaf_hash(&leaves[0]), &sibling);
        let hex = |hash: [u8; 32]| {
            hash.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let entry = Entry {
            log_url: "http://log".into(),
            uuid: "u".into(),
            log_index: 0,
            log_id: "l".into(),
            integrated_time: 1,
            body: BASE64.encode(&leaves[0]),
            inclusion_proof: Some(serde_json::json!({
                "logIndex": 0,
                "treeSize": 2,
                "rootHash": hex(root),
                "hashes": [hex(sibling)]
            })),
            signed_entry_timestamp: None,
        };
        verify_inclusion(&entry, None).unwrap();
    }

    #[test]
    fn checkpoints_parse_and_verify() {
        use p256::ecdsa::signature::Signer as _;
        let signing = p256::ecdsa::SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let root = [9u8; 32];
        let body = format!("rekor.example - 123\n42\n{}\n", BASE64.encode(root));
        let sig: p256::ecdsa::Signature = signing.sign(body.as_bytes());
        let mut line = vec![1, 2, 3, 4];
        line.extend_from_slice(sig.to_der().as_bytes());
        let text = format!("{body}\n\u{2014} rekor.example {}\n", BASE64.encode(&line));
        let checkpoint = Checkpoint::parse(&text).unwrap();
        assert_eq!(checkpoint.size, 42);
        assert_eq!(checkpoint.root, root);
        assert_eq!(checkpoint.origin, "rekor.example - 123");
        let key = signing.verifying_key();
        checkpoint.verify(key).unwrap();
        let other = p256::ecdsa::SigningKey::from_bytes(&[8u8; 32].into()).unwrap();
        assert!(checkpoint.verify(other.verifying_key()).is_err());
        let mut tampered = checkpoint.clone();
        tampered.body = tampered.body.replace("42", "43");
        assert!(tampered.verify(key).is_err());
        use p256::pkcs8::EncodePublicKey as _;
        let pem = key.to_public_key_pem(p256::pkcs8::LineEnding::LF).unwrap();
        log_key(&pem).unwrap();
    }

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
