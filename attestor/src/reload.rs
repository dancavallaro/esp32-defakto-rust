//! Picks up a changed enrollment file or TLS pair without a restart. Files are polled rather
//! than watched, because Kubernetes updates a Secret volume by swapping a symlink, which
//! inotify-style watchers on the file itself miss.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum_server::tls_rustls::RustlsConfig;

use crate::enrollment;
use crate::verifier::Verifier;

/// One file, compared by content with the last version seen.
pub struct FileWatcher {
    path: PathBuf,
    last: Vec<u8>,
}

pub enum Change {
    Unchanged,
    Changed(Vec<u8>),
    Unreadable(io::Error),
}

impl FileWatcher {
    /// `initial` is the content already in use, so it doesn't count as a change.
    pub fn new(path: PathBuf, initial: Vec<u8>) -> Self {
        FileWatcher { path, last: initial }
    }

    /// Reads the file again. An unreadable file leaves the last content in place, so the same
    /// content coming back is no change.
    pub fn poll(&mut self) -> Change {
        match std::fs::read(&self.path) {
            Err(e) => Change::Unreadable(e),
            Ok(bytes) if bytes == self.last => Change::Unchanged,
            Ok(bytes) => {
                self.last.clone_from(&bytes);
                Change::Changed(bytes)
            }
        }
    }
}

/// Polls every `interval`, forever. A bad file is logged and the one in use is kept.
pub async fn run(
    verifier: Arc<Verifier>,
    mut enrollment: FileWatcher,
    tls: RustlsConfig,
    cert: PathBuf,
    key: PathBuf,
    interval: Duration,
) {
    let mut tls_files = [watch_tls(cert.clone()), watch_tls(key.clone())];
    loop {
        tokio::time::sleep(interval).await;
        reload_enrollment(&verifier, &mut enrollment);
        // Either file changing reloads both, so a renewal that writes them one at a time
        // reloads again once the second has been seen.
        let mut changed = false;
        for file in &mut tls_files {
            match file.poll() {
                Change::Unchanged => {}
                Change::Changed(_) => changed = true,
                Change::Unreadable(e) => println!("keeping TLS pair: reading {}: {e}", file.path.display()),
            }
        }
        if changed {
            match tls.reload_from_pem_file(&cert, &key).await {
                Ok(()) => println!("TLS pair reloaded from {}", cert.display()),
                Err(e) => println!("keeping TLS pair: reloading {}: {e}", cert.display()),
            }
        }
    }
}

// An unreadable file starts as empty, so its first successful read counts as a change.
fn watch_tls(path: PathBuf) -> FileWatcher {
    let initial = std::fs::read(&path).unwrap_or_default();
    FileWatcher::new(path, initial)
}

fn reload_enrollment(verifier: &Verifier, watcher: &mut FileWatcher) {
    let change = watcher.poll();
    let path = watcher.path.display();
    match change {
        Change::Unchanged => {}
        Change::Unreadable(e) => println!("keeping enrollment: reading {path}: {e}"),
        Change::Changed(bytes) => match enrollment::parse(&bytes) {
            Ok(devices) => {
                println!("enrollment reloaded: {} devices", devices.len());
                verifier.set_devices(devices);
            }
            Err(e) => println!("keeping enrollment: loading {path}: {e:#}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::{engine::general_purpose::STANDARD, Engine};
    use esp_attest::hmac::{evidence_json, sign};

    use super::*;
    use crate::verifier::Outcome;

    /// A fresh directory per test, under the system temp dir.
    fn temp_dir(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("esp32-attestor-{}-{test}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn watch(path: &Path, initial: &[u8]) -> FileWatcher {
        fs::write(path, initial).unwrap();
        FileWatcher::new(path.to_owned(), initial.to_vec())
    }

    #[test]
    fn watcher_unchanged_then_changed() {
        let path = temp_dir("unchanged").join("enrollment.json");
        let mut watcher = watch(&path, b"one");

        assert!(matches!(watcher.poll(), Change::Unchanged));
        fs::write(&path, b"two").unwrap();
        assert!(matches!(watcher.poll(), Change::Changed(b) if b == b"two"));
        assert!(matches!(watcher.poll(), Change::Unchanged));
    }

    #[test]
    fn watcher_keeps_last_good_on_missing_file() {
        let path = temp_dir("missing").join("enrollment.json");
        let mut watcher = watch(&path, b"one");

        fs::remove_file(&path).unwrap();
        assert!(matches!(watcher.poll(), Change::Unreadable(_)));
        fs::write(&path, b"one").unwrap();
        assert!(matches!(watcher.poll(), Change::Unchanged));
    }

    #[test]
    fn watcher_recovers_after_invalid() {
        let path = temp_dir("invalid").join("enrollment.json");
        let mut watcher = watch(&path, b"good");

        fs::write(&path, b"{").unwrap();
        assert!(matches!(watcher.poll(), Change::Changed(b) if b == b"{"));
        fs::write(&path, b"good").unwrap();
        assert!(matches!(watcher.poll(), Change::Changed(b) if b == b"good"));
    }

    // Kubernetes updates a Secret volume by pointing its `..data` symlink at a new directory.
    #[test]
    fn watcher_follows_symlink_swap() {
        let dir = temp_dir("symlink");
        for (version, body) in [("v1", "one"), ("v2", "two")] {
            fs::create_dir(dir.join(version)).unwrap();
            fs::write(dir.join(version).join("enrollment.json"), body).unwrap();
        }
        std::os::unix::fs::symlink("v1", dir.join("..data")).unwrap();
        let path = dir.join("enrollment.json");
        std::os::unix::fs::symlink("..data/enrollment.json", &path).unwrap();
        let mut watcher = FileWatcher::new(path, b"one".to_vec());

        assert!(matches!(watcher.poll(), Change::Unchanged));
        std::os::unix::fs::symlink("v2", dir.join("..data_tmp")).unwrap();
        fs::rename(dir.join("..data_tmp"), dir.join("..data")).unwrap();
        assert!(matches!(watcher.poll(), Change::Changed(b) if b == b"two"));
    }

    const NOW: i64 = 1789200000;
    const SECRET_A: [u8; 32] = *b"0123456789abcdef0123456789abcdef";
    const SECRET_B: [u8; 32] = *b"fedcba9876543210fedcba9876543210";

    fn entry(id: &str, secret: &[u8; 32]) -> String {
        format!(r#""{id}":{{"secret":"{}"}}"#, STANDARD.encode(secret))
    }

    fn attests(verifier: &Verifier, id: &str, secret: &[u8; 32]) -> bool {
        let nonce = format!("{:016x}", rand_nonce());
        let evidence = evidence_json(id, NOW, &nonce, &sign(id, NOW, &nonce, secret));
        let now = UNIX_EPOCH + Duration::from_secs(NOW as u64);
        verifier.attest(&evidence, now).1.outcome == Outcome::Accepted
    }

    // A fresh nonce per call, so the replay cache never answers for the verifier.
    fn rand_nonce() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
    }

    #[test]
    fn bad_enrollment_update_keeps_last_good_list() {
        let path = temp_dir("keep-last-good").join("enrollment.json");
        let first = format!("{{{}}}", entry("device-a", &SECRET_A));
        let mut watcher = watch(&path, first.as_bytes());
        let verifier = Verifier::new(enrollment::parse(first.as_bytes()).unwrap(), Duration::from_secs(60));
        assert!(attests(&verifier, "device-a", &SECRET_A));

        fs::write(&path, b"{").unwrap();
        reload_enrollment(&verifier, &mut watcher);
        assert!(attests(&verifier, "device-a", &SECRET_A));

        let both = format!("{{{},{}}}", entry("device-a", &SECRET_A), entry("device-b", &SECRET_B));
        fs::write(&path, both).unwrap();
        reload_enrollment(&verifier, &mut watcher);
        assert!(attests(&verifier, "device-b", &SECRET_B));
        assert!(attests(&verifier, "device-a", &SECRET_A));
    }
}
