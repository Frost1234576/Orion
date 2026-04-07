use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use futures_util::{SinkExt, StreamExt};
use rand::distr::Alphanumeric;
use rand::{rng, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs, net::SocketAddr, path::{Component, Path, PathBuf}, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use walkdir::WalkDir;
use rand::RngExt;

const KEYS_FILE: &str = "orion_keys.json";
const ADDR: &str = "0.0.0.0:8080";
const WORKSPACE: &str = "./workspace";

// ── Keys ─────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
struct Keys {
    admin_key: String,
    user_key: String,
}

fn generate_key() -> String {
    let random: String = rng()
        .sample_iter(&Alphanumeric)
        .take(48)
        .map(char::from)
        .collect();
    format!("orion_{}", random)
}

fn load_or_generate_keys() -> Keys {
    if Path::new(KEYS_FILE).exists() {
        let data = fs::read_to_string(KEYS_FILE).expect("Failed to read keys file");
        serde_json::from_str(&data).expect("Keys file is malformed")
    } else {
        let keys = Keys {
            admin_key: generate_key(),
            user_key: generate_key(),
        };
        fs::write(KEYS_FILE, serde_json::to_string_pretty(&keys).unwrap())
            .expect("Failed to save keys file");

        println!("╔══════════════════════════════════════╗");
        println!("║         ORION — FIRST RUN            ║");
        println!("╠══════════════════════════════════════╣");
        println!("║ Admin key: {}  ║", keys.admin_key);
        println!("║ User key:  {}  ║", keys.user_key);
        println!("╠══════════════════════════════════════╣");
        println!("║ Saved to: {:28} ║", KEYS_FILE);
        println!("║ Add this file to .gitignore!         ║");
        println!("╚══════════════════════════════════════╝");

        keys
    }
}

// ── Auth ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Role {
    Admin,
    User,
}

fn authenticate(provided_key: &str, keys: &Keys) -> Option<Role> {
    if provided_key == keys.admin_key {
        Some(Role::Admin)
    } else if provided_key == keys.user_key {
        Some(Role::User)
    } else {
        None
    }
}

// ── Protocol ──────────────────────────────────────────────────────────────────
//
// Sync flow (like git):
//   1. Celestia sends Manifest { path -> sha256 } for all local files
//   2. Orion replies ManifestResponse { needs: [...] } — files that differ or are missing
//   3. Celestia sends UploadDiff (text files) or UploadFile (binary/new files) for each
//
// File ops:
//   UploadFile / DownloadFile  — single file (base64 encoded)
//   DownloadDir                — returns a manifest so Celestia can request individual files
//   ListDir                    — shallow directory listing

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
enum ClientMessage {
    /// Sync: send {relative_path -> sha256} for all local files
    Manifest { files: HashMap<String, String> },
    /// Upload a unified diff for a text file (from diffy on the Celestia side)
    UploadDiff { path: String, diff: String },
    /// Upload a full file as base64 (for binary files or new files)
    UploadFile { path: String, content: String },
    /// Download a single file
    DownloadFile { path: String },
    /// Get a manifest of a directory so Celestia can pull individual files
    DownloadDir { path: String },
    /// Shallow directory listing
    ListDir { path: String },
    Ping,
    Status,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
enum ServerMessage {
    /// Paths Celestia needs to upload (missing or hash mismatch)
    ManifestResponse { needs: Vec<String> },
    /// File content as base64
    FileContent { path: String, content: String },
    /// Directory entries (shallow or recursive depending on request)
    DirListing { path: String, entries: Vec<DirEntry> },
    Ok { msg: String },
    Error { msg: String },
    Pong,
}

#[derive(Serialize, Deserialize, Debug)]
struct DirEntry {
    name: String,
    path: String,
    is_dir: bool,
    size: u64,
    hash: Option<String>, // only for files, useful for Celestia to detect what to pull
}

// ── File helpers ──────────────────────────────────────────────────────────────

/// Resolve a relative path inside the workspace, rejecting traversal attempts.
fn safe_path(workspace: &str, relative: &str) -> Option<PathBuf> {
    let base = Path::new(workspace).canonicalize().ok()?;
    let rel = Path::new(relative);

    if rel.is_absolute() {
        return None;
    }
    // Reject any ".." components
    for component in rel.components() {
        if matches!(component, Component::ParentDir) {
            return None;
        }
    }

    Some(base.join(rel))
}

fn hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn hash_file(path: &Path) -> Option<String> {
    fs::read(path).ok().as_deref().map(hash_bytes)
}

/// Build a {relative_path -> sha256} map of all files under workspace.
fn build_server_manifest(workspace: &str) -> HashMap<String, String> {
    let base = Path::new(workspace);
    WalkDir::new(workspace)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| {
            let rel = e.path().strip_prefix(base).ok()?.to_string_lossy().into_owned();
            let hash = hash_file(e.path())?;
            Some((rel, hash))
        })
        .collect()
}

// ── Message handling ──────────────────────────────────────────────────────────

fn handle_message(msg: ClientMessage, role: &Role, workspace: &str) -> ServerMessage {
    match msg {
        ClientMessage::Ping => ServerMessage::Pong,

        ClientMessage::Status => ServerMessage::Ok {
            msg: format!("Orion OK | role: {:?} | workspace: {}", role, workspace),
        },

        // ── Sync ─────────────────────────────────────────────────────────────
        ClientMessage::Manifest { files } => {
            let server = build_server_manifest(workspace);
            // Tell Celestia which files it needs to upload
            let needs = files
                .into_iter()
                .filter(|(path, hash)| server.get(path).map_or(true, |h| h != hash))
                .map(|(path, _)| path)
                .collect();
            ServerMessage::ManifestResponse { needs }
        }

        // ── Diff upload (text files) ──────────────────────────────────────────
        ClientMessage::UploadDiff { path, diff } => {
            let Some(full_path) = safe_path(workspace, &path) else {
                return ServerMessage::Error { msg: "Invalid path".into() };
            };

            let original = fs::read_to_string(&full_path).unwrap_or_default();

            let patch = match diffy::Patch::from_str(&diff) {
                Ok(p) => p,
                Err(e) => return ServerMessage::Error { msg: format!("Bad patch: {}", e) },
            };

            match diffy::apply(&original, &patch) {
                Ok(patched) => {
                    if let Some(parent) = full_path.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    match fs::write(&full_path, &patched) {
                        Ok(_) => ServerMessage::Ok { msg: format!("Applied diff to {}", path) },
                        Err(e) => ServerMessage::Error { msg: format!("Write failed: {}", e) },
                    }
                }
                Err(e) => ServerMessage::Error { msg: format!("Patch apply failed: {}", e) },
            }
        }

        // ── Full file upload (binary or new files) ────────────────────────────
        ClientMessage::UploadFile { path, content } => {
            let Some(full_path) = safe_path(workspace, &path) else {
                return ServerMessage::Error { msg: "Invalid path".into() };
            };

            let bytes = match BASE64.decode(&content) {
                Ok(b) => b,
                Err(_) => return ServerMessage::Error { msg: "Invalid base64".into() },
            };

            if let Some(parent) = full_path.parent() {
                let _ = fs::create_dir_all(parent);
            }

            match fs::write(&full_path, &bytes) {
                Ok(_) => ServerMessage::Ok { msg: format!("Uploaded {} ({} bytes)", path, bytes.len()) },
                Err(e) => ServerMessage::Error { msg: format!("Write failed: {}", e) },
            }
        }

        // ── Single file download ──────────────────────────────────────────────
        ClientMessage::DownloadFile { path } => {
            let Some(full_path) = safe_path(workspace, &path) else {
                return ServerMessage::Error { msg: "Invalid path".into() };
            };

            match fs::read(&full_path) {
                Ok(bytes) => ServerMessage::FileContent {
                    path,
                    content: BASE64.encode(&bytes),
                },
                Err(_) => ServerMessage::Error { msg: format!("Not found: {}", path) },
            }
        }

        // ── Directory manifest (Celestia requests individual files after this) ─
        ClientMessage::DownloadDir { path } => {
            let base = Path::new(workspace);
            let target = base.join(&path);

            let entries = WalkDir::new(&target)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let meta = e.metadata().ok()?;
                    let rel = e.path().strip_prefix(base).ok()?.to_string_lossy().into_owned();
                    Some(DirEntry {
                        name: e.file_name().to_string_lossy().into(),
                        path: rel,
                        is_dir: meta.is_dir(),
                        size: if meta.is_file() { meta.len() } else { 0 },
                        hash: if meta.is_file() { hash_file(e.path()) } else { None },
                    })
                })
                .collect();

            ServerMessage::DirListing { path, entries }
        }

        // ── Shallow directory listing ─────────────────────────────────────────
        ClientMessage::ListDir { path } => {
            let base = Path::new(workspace);
            let target = base.join(&path);

            let entries = match fs::read_dir(&target) {
                Ok(rd) => rd
                    .filter_map(|e| e.ok())
                    .filter_map(|e| {
                        let meta = e.metadata().ok()?;
                        let rel = e.path().strip_prefix(base).ok()?.to_string_lossy().into_owned();
                        Some(DirEntry {
                            name: e.file_name().to_string_lossy().into(),
                            path: rel,
                            is_dir: meta.is_dir(),
                            size: if meta.is_file() { meta.len() } else { 0 },
                            hash: if meta.is_file() { hash_file(&e.path()) } else { None },
                        })
                    })
                    .collect(),
                Err(e) => return ServerMessage::Error { msg: format!("Can't read dir: {}", e) },
            };

            ServerMessage::DirListing { path, entries }
        }
    }
}

// ── Connection handler ────────────────────────────────────────────────────────

async fn handle_connection(stream: TcpStream, addr: SocketAddr, keys: Arc<Keys>) {
    println!("[+] Connection from {}", addr);

    let ws_stream = match accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            eprintln!("[-] Handshake failed with {}: {}", addr, e);
            return;
        }
    };

    let (mut write, mut read) = ws_stream.split();

    let send = |msg: ServerMessage| serde_json::to_string(&msg).unwrap();

    // First message must be the auth key
    let role = match read.next().await {
        Some(Ok(Message::Text(key))) => match authenticate(key.trim(), &keys) {
            Some(role) => {
                let _ = write.send(Message::Text(send(ServerMessage::Ok {
                    msg: format!("AUTH_OK:{:?}", role),
                }).into())).await;
                println!("[+] {} authenticated as {:?}", addr, role);
                role
            }
            None => {
                let _ = write.send(Message::Text(send(ServerMessage::Error {
                    msg: "AUTH_FAIL:Invalid key".into(),
                }).into())).await;
                println!("[-] {} invalid key", addr);
                return;
            }
        },
        _ => {
            eprintln!("[-] {} disconnected before auth", addr);
            return;
        }
    };

    while let Some(result) = read.next().await {
        match result {
            Ok(Message::Text(text)) => {
                let response = match serde_json::from_str::<ClientMessage>(&text) {
                    Ok(msg) => {
                        println!("[{:?}][{}] {:?}", role, addr, msg);
                        handle_message(msg, &role, WORKSPACE)
                    }
                    Err(e) => ServerMessage::Error { msg: format!("Bad message format: {}", e) },
                };
                if write.send(Message::Text(send(response).into())).await.is_err() {
                    break;
                }
            }
            Ok(Message::Ping(data)) => { let _ = write.send(Message::Pong(data)).await; }
            Ok(Message::Close(_)) | Err(_) => break,
            _ => {}
        }
    }

    println!("[-] {} disconnected", addr);
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    fs::create_dir_all(WORKSPACE).expect("Failed to create workspace directory");
    let keys = Arc::new(load_or_generate_keys());
    let listener = TcpListener::bind(ADDR).await.expect("Failed to bind");
    println!("[*] Orion listening on ws://{}", ADDR);

    while let Ok((stream, addr)) = listener.accept().await {
        let keys = Arc::clone(&keys);
        tokio::spawn(handle_connection(stream, addr, keys));
    }
}