// ── Cargo.toml additions required ────────────────────────────────────────────
// chrono = { version = "0.4", features = ["serde"] }
//
// Full dependency block for reference:
//
// [dependencies]
// base64       = "0.22"
// chrono       = { version = "0.4", features = ["serde"] }
// diffy        = "0.4"
// futures-util = { version = "0.3", features = ["sink"] }
// hex          = "0.4"
// rand         = "0.9"
// serde        = { version = "1", features = ["derive"] }
// serde_json   = "1"
// sha2         = "0.10"
// tokio        = { version = "1", features = ["full"] }
// tokio-tungstenite = "0.24"
// walkdir      = "2"
// ─────────────────────────────────────────────────────────────────────────────

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Utc};
use futures_util::{SinkExt, StreamExt};
use rand::distr::Alphanumeric;
use rand::{rng, Rng, RngExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use walkdir::WalkDir;

// ── Constants ─────────────────────────────────────────────────────────────────

const KEYS_FILE: &str = "orion_keys.json";
const ADDR: &str = "0.0.0.0:8080";
const WORKSPACE: &str = "./workspace";

/// All Orion metadata lives here; never exposed to clients.
const ORION_DIR: &str = ".orion";
const INDEX_FILE: &str = ".orion/index.json";
const LOG_FILE: &str = ".orion/log.json";
const PREV_DIR: &str = ".orion/prev";
const IGNORE_FILE: &str = ".orionignore";

const LOG_CAP: usize = 500;

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

// ── Index (Phase 1) ───────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
struct IndexEntry {
    /// SHA-256 of the file at the time it was last synced.
    hash: String,
    synced_at: DateTime<Utc>,
}

fn read_index(workspace: &str) -> HashMap<String, IndexEntry> {
    let path = Path::new(workspace).join(INDEX_FILE);
    if !path.exists() {
        return HashMap::new();
    }
    match fs::read_to_string(&path) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

/// Atomically writes the index: write to a temp file, then rename.
fn write_index(workspace: &str, map: &HashMap<String, IndexEntry>) {
    let base = Path::new(workspace);
    let _ = fs::create_dir_all(base.join(ORION_DIR));
    let tmp = base.join(".orion/index.json.tmp");
    let dest = base.join(INDEX_FILE);
    if let Ok(data) = serde_json::to_string_pretty(map) {
        if fs::write(&tmp, data).is_ok() {
            let _ = fs::rename(&tmp, &dest);
        }
    }
}

/// Update a single path in the index, preserving all other entries.
fn update_index_entry(workspace: &str, path: &str, hash: &str) {
    let mut index = read_index(workspace);
    index.insert(
        path.to_string(),
        IndexEntry {
            hash: hash.to_string(),
            synced_at: Utc::now(),
        },
    );
    write_index(workspace, &index);
}

// ── Log (Phase 5) ─────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
enum SyncDirection {
    Push,
    Pull,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct LogEntry {
    timestamp: DateTime<Utc>,
    direction: SyncDirection,
    files: Vec<String>,
    forced: bool,
}

fn read_log(workspace: &str) -> Vec<LogEntry> {
    let path = Path::new(workspace).join(LOG_FILE);
    if !path.exists() {
        return Vec::new();
    }
    match fs::read_to_string(&path) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Append a log entry; trims to LOG_CAP most-recent entries (ring buffer).
fn append_log(workspace: &str, entry: LogEntry) {
    let base = Path::new(workspace);
    let _ = fs::create_dir_all(base.join(ORION_DIR));
    let mut entries = read_log(workspace);
    entries.push(entry);
    if entries.len() > LOG_CAP {
        let overflow = entries.len() - LOG_CAP;
        entries.drain(..overflow);
    }
    let tmp = base.join(".orion/log.json.tmp");
    let dest = base.join(LOG_FILE);
    if let Ok(data) = serde_json::to_string_pretty(&entries) {
        if fs::write(&tmp, data).is_ok() {
            let _ = fs::rename(&tmp, &dest);
        }
    }
}

// ── .orionignore (Cleanup phase) ──────────────────────────────────────────────

fn load_ignore_patterns(workspace: &str) -> Vec<String> {
    let path = Path::new(workspace).join(IGNORE_FILE);
    match fs::read_to_string(&path) {
        Ok(content) => content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Recursive glob match. `*` matches within a path component; `**` crosses `/`.
fn glob_match(pattern: &[char], pi: usize, text: &[char], ti: usize) -> bool {
    if pi == pattern.len() {
        return ti == text.len();
    }
    if pattern[pi] == '*' {
        if pi + 1 < pattern.len() && pattern[pi + 1] == '*' {
            // `**` — skip the optional trailing slash in pattern
            let next_pi = if pi + 2 < pattern.len() && pattern[pi + 2] == '/' {
                pi + 3
            } else {
                pi + 2
            };
            for i in ti..=text.len() {
                if glob_match(pattern, next_pi, text, i) {
                    return true;
                }
            }
            return false;
        }
        // `*` — match anything except `/`
        for i in ti..=text.len() {
            if i > ti && text[i - 1] == '/' {
                break;
            }
            if glob_match(pattern, pi + 1, text, i) {
                return true;
            }
        }
        return false;
    }
    if ti == text.len() {
        return false;
    }
    if pattern[pi] == '?' {
        if text[ti] == '/' {
            return false;
        }
        return glob_match(pattern, pi + 1, text, ti + 1);
    }
    if pattern[pi] == text[ti] {
        return glob_match(pattern, pi + 1, text, ti + 1);
    }
    false
}

fn matches_glob(pattern: &str, path: &str) -> bool {
    let p: Vec<char> = pattern.replace('\\', "/").chars().collect();
    let t: Vec<char> = path.replace('\\', "/").chars().collect();
    glob_match(&p, 0, &t, 0)
}

/// Returns true if `relative_path` should be excluded from sync operations.
fn is_ignored(patterns: &[String], relative_path: &str) -> bool {
    let path = relative_path.replace('\\', "/");
    let mut ignored = false;
    for raw in patterns {
        let (negate, pat) = if let Some(rest) = raw.strip_prefix('!') {
            (true, rest)
        } else {
            (false, raw.as_str())
        };
        let matched = if !pat.contains('/') {
            // No slash: match against filename component OR full path
            let filename = path.split('/').next_back().unwrap_or(&path);
            matches_glob(pat, filename) || matches_glob(pat, &path)
        } else {
            matches_glob(pat, &path)
        };
        if matched {
            ignored = !negate;
        }
    }
    ignored
}

// ── File helpers ──────────────────────────────────────────────────────────────

/// Resolve a relative path inside the workspace, rejecting path traversal.
fn safe_path(workspace: &str, relative: &str) -> Option<PathBuf> {
    let base = Path::new(workspace).canonicalize().ok()?;
    let rel = Path::new(relative);
    if rel.is_absolute() {
        return None;
    }
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

/// Returns true if `path` refers to something inside the `.orion/` metadata dir.
fn is_orion_internal(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    normalized == ORION_DIR
        || normalized.starts_with(".orion/")
        || normalized.starts_with(".orion\\")
}

/// Build a `{ relative_path -> sha256 }` map, excluding `.orion/` and ignored files.
fn build_server_manifest(workspace: &str, ignore_patterns: &[String]) -> HashMap<String, String> {
    let base = Path::new(workspace);
    WalkDir::new(workspace)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| {
            let rel = e.path().strip_prefix(base).ok()?.to_string_lossy().into_owned();
            if is_orion_internal(&rel) {
                return None;
            }
            if is_ignored(ignore_patterns, &rel) {
                return None;
            }
            let hash = hash_file(e.path())?;
            Some((rel, hash))
        })
        .collect()
}

/// Stash a copy of a file in `.orion/prev/<path>` before overwriting it.
/// Called immediately before every write so restore is always possible.
fn save_prev_snapshot(workspace: &str, relative_path: &str) {
    let base = Path::new(workspace);
    let src = base.join(relative_path);
    if !src.exists() {
        return;
    }
    let dest = base.join(PREV_DIR).join(relative_path);
    if let Some(parent) = dest.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::copy(&src, &dest);
}

// ── Conflict detection (Phase 2 / 3) ─────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
enum FileCategory {
    /// All three copies agree (or file is absent everywhere).
    Clean,
    /// Local differs from index; remote matches index → safe to push.
    ModifiedLocally,
    /// Remote differs from index; local matches index → safe to pull.
    ModifiedRemotely,
    /// Both local and remote differ from index → must resolve before sync.
    Conflict,
    /// File exists locally (and possibly remotely) but has never been indexed.
    Untracked,
    /// In index + remote but absent locally → client deleted it.
    DeletedLocally,
    /// In index + local but absent on remote → server copy was removed.
    DeletedRemotely,
    /// Present on remote, not in index, not held locally.
    NewRemote,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct FileStatus {
    path: String,
    category: FileCategory,
    local_hash: Option<String>,
    remote_hash: Option<String>,
    index_hash: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
enum DryRunActionKind {
    Push,
    Pull,
    Skip,
    Conflict,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DryRunAction {
    path: String,
    action: DryRunActionKind,
    reason: String,
}

/// Compute per-file three-way status across local (client-supplied), remote
/// (server disk), and the last-synced index.
fn compute_status(
    workspace: &str,
    local_files: &HashMap<String, String>,
    ignore_patterns: &[String],
) -> Vec<FileStatus> {
    let index = read_index(workspace);
    let remote_files = build_server_manifest(workspace, ignore_patterns);

    let mut all_paths: HashSet<String> = HashSet::new();
    all_paths.extend(local_files.keys().cloned());
    all_paths.extend(remote_files.keys().cloned());
    all_paths.extend(index.keys().cloned());

    let mut statuses: Vec<FileStatus> = all_paths
        .into_iter()
        .map(|path| {
            let local = local_files.get(&path).cloned();
            let remote = remote_files.get(&path).cloned();
            let idx = index.get(&path).map(|e| e.hash.clone());

            let category = categorize(&local, &remote, &idx);

            FileStatus {
                path,
                category,
                local_hash: local,
                remote_hash: remote,
                index_hash: idx,
            }
        })
        .collect();

    statuses.sort_by(|a, b| a.path.cmp(&b.path));
    statuses
}

fn categorize(
    local: &Option<String>,
    remote: &Option<String>,
    idx: &Option<String>,
) -> FileCategory {
    match (local.as_deref(), remote.as_deref(), idx.as_deref()) {
        // ── All match ────────────────────────────────────────────────────────
        (Some(l), Some(r), Some(i)) if l == r && r == i => FileCategory::Clean,
        (None, None, _) => FileCategory::Clean, // absent everywhere (stale index cleaned up)

        // ── Both sides changed to the same hash ──────────────────────────────
        (Some(l), Some(r), Some(_)) if l == r => FileCategory::Clean,

        // ── Safe to push: local changed, remote hasn't ───────────────────────
        (Some(l), Some(r), Some(i)) if l != i && r == i => FileCategory::ModifiedLocally,
        (Some(_), None, None) => FileCategory::Untracked,
        // New local file that was pushed before and remote deleted it — treat as conflict
        (Some(l), None, Some(i)) if l != i => FileCategory::Conflict,
        (Some(_), None, Some(_)) => FileCategory::DeletedRemotely,

        // ── Safe to pull: remote changed, local hasn't ───────────────────────
        (Some(l), Some(r), Some(i)) if r != i && l == i => FileCategory::ModifiedRemotely,
        (None, Some(_), Some(_)) => FileCategory::DeletedLocally,
        (None, Some(_), None) => FileCategory::NewRemote,

        // ── True conflict: both sides changed independently ──────────────────
        (Some(_), Some(_), Some(_)) => FileCategory::Conflict,

        // ── File exists both places but was never indexed ────────────────────
        (Some(l), Some(r), None) if l == r => FileCategory::Untracked,
        (Some(_), Some(_), None) => FileCategory::Conflict,
    }
}

// ── Protocol ──────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
enum ClientMessage {
    // ── Sync / push ──────────────────────────────────────────────────────────
    /// Send { relative_path -> sha256 } for all local files.
    /// Server replies with ManifestResponse listing paths the client should upload.
    Manifest {
        files: HashMap<String, String>,
        #[serde(default)]
        force: bool,
        #[serde(default)]
        dry_run: bool,
    },
    /// Upload a unified diff for a text file.
    UploadDiff { path: String, diff: String },
    /// Upload a full file as base64 (binary files or new files).
    UploadFile { path: String, content: String },

    // ── Pull ─────────────────────────────────────────────────────────────────
    /// Client sends its local hashes; server replies with ManifestResponse
    /// listing paths the client should download (i.e. newer on remote).
    Pull {
        files: HashMap<String, String>,
        #[serde(default)]
        force: bool,
        #[serde(default)]
        dry_run: bool,
    },
    /// Download a single file.
    DownloadFile { path: String },

    // ── Directory ops ────────────────────────────────────────────────────────
    /// Recursive manifest of a directory (client then pulls individual files).
    DownloadDir { path: String },
    /// Shallow directory listing.
    ListDir { path: String },

    // ── Queries (Phase 1 / 3 / 5 / 6) ───────────────────────────────────────
    /// Fetch the current SHA-256 of a specific remote file.
    GetFileHash { path: String },
    /// Three-way status: client sends local hashes, server categorises each file.
    GetStatus { files: HashMap<String, String> },
    /// Retrieve the sync log.
    GetLog {
        #[serde(default)]
        n: Option<usize>,
        #[serde(default)]
        all: bool,
    },
    /// Unified diff between the current remote version and its stored snapshot.
    GetDiff { path: String },
    /// Overwrite the current remote file with its previous snapshot.
    RestoreFile { path: String },

    Ping,
    Status,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
enum ServerMessage {
    /// Paths the client must upload (Manifest / Pull response).
    ManifestResponse { needs: Vec<String> },
    /// File content as base64.
    FileContent { path: String, content: String },
    /// Directory listing (shallow or recursive).
    DirListing { path: String, entries: Vec<DirEntry> },
    /// Hash of a specific remote file (None if absent or ignored).
    FileHash { path: String, hash: Option<String> },
    /// Per-file three-way status.
    StatusReport { files: Vec<FileStatus> },
    /// What a sync/pull *would* do, without touching anything.
    DryRunReport { actions: Vec<DryRunAction> },
    /// Unified diff output.
    Diff { path: String, diff: String },
    /// Recent log entries.
    LogEntries { entries: Vec<LogEntry> },
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
    /// SHA-256; present for files so the client can detect what to pull.
    hash: Option<String>,
}

// ── Message handling ──────────────────────────────────────────────────────────

fn handle_message(msg: ClientMessage, role: &Role, workspace: &str) -> ServerMessage {
    match msg {
        // ── Heartbeat / info ─────────────────────────────────────────────────
        ClientMessage::Ping => ServerMessage::Pong,

        ClientMessage::Status => ServerMessage::Ok {
            msg: format!("Orion OK | role: {:?} | workspace: {}", role, workspace),
        },

        // ── Sync push (Manifest → UploadFile / UploadDiff) ──────────────────
        //
        // Three-way conflict detection:
        //   local ≠ index, remote = index  → safe to push
        //   remote ≠ index, local = index  → tell client to pull instead
        //   local ≠ index AND remote ≠ index → conflict, refuse unless --force
        ClientMessage::Manifest { files, force, dry_run } => {
            let ignore_patterns = load_ignore_patterns(workspace);
            let remote = build_server_manifest(workspace, &ignore_patterns);
            let index = read_index(workspace);

            let mut needs: Vec<String> = Vec::new();
            let mut conflicts: Vec<String> = Vec::new();
            let mut actions: Vec<DryRunAction> = Vec::new();

            for (path, local_hash) in &files {
                if is_orion_internal(path) || is_ignored(&ignore_patterns, path) {
                    continue;
                }
                let remote_hash = remote.get(path);
                let idx_hash = index.get(path).map(|e| e.hash.as_str());

                let (action, reason) = push_decision(
                    local_hash,
                    remote_hash.map(String::as_str),
                    idx_hash,
                    force,
                );

                match action {
                    DryRunActionKind::Push => needs.push(path.clone()),
                    DryRunActionKind::Conflict => conflicts.push(path.clone()),
                    _ => {}
                }
                actions.push(DryRunAction {
                    path: path.clone(),
                    action,
                    reason: reason.to_string(),
                });
            }

            if !conflicts.is_empty() && !force {
                return ServerMessage::Error {
                    msg: format!(
                        "CONFLICT: {} file(s) have diverged — resolve manually or use --force:\n  {}",
                        conflicts.len(),
                        conflicts.join("\n  ")
                    ),
                };
            }

            if dry_run {
                return ServerMessage::DryRunReport { actions };
            }

            ServerMessage::ManifestResponse { needs }
        }

        // ── Diff upload ──────────────────────────────────────────────────────
        ClientMessage::UploadDiff { path, diff } => {
            if is_orion_internal(&path) {
                return ServerMessage::Error {
                    msg: "Cannot write inside .orion/".into(),
                };
            }
            let Some(full_path) = safe_path(workspace, &path) else {
                return ServerMessage::Error { msg: "Invalid path".into() };
            };

            let original = fs::read_to_string(&full_path).unwrap_or_default();
            let patch = match diffy::Patch::from_str(&diff) {
                Ok(p) => p,
                Err(e) => {
                    return ServerMessage::Error {
                        msg: format!("Bad patch: {}", e),
                    }
                }
            };

            match diffy::apply(&original, &patch) {
                Ok(patched) => {
                    save_prev_snapshot(workspace, &path);
                    if let Some(parent) = full_path.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    match fs::write(&full_path, &patched) {
                        Ok(_) => {
                            let hash = hash_bytes(patched.as_bytes());
                            update_index_entry(workspace, &path, &hash);
                            append_log(
                                workspace,
                                LogEntry {
                                    timestamp: Utc::now(),
                                    direction: SyncDirection::Push,
                                    files: vec![path.clone()],
                                    forced: false,
                                },
                            );
                            ServerMessage::Ok {
                                msg: format!("Applied diff to {}", path),
                            }
                        }
                        Err(e) => ServerMessage::Error {
                            msg: format!("Write failed: {}", e),
                        },
                    }
                }
                Err(e) => ServerMessage::Error {
                    msg: format!("Patch apply failed: {}", e),
                },
            }
        }

        // ── Full file upload ─────────────────────────────────────────────────
        ClientMessage::UploadFile { path, content } => {
            if is_orion_internal(&path) {
                return ServerMessage::Error {
                    msg: "Cannot write inside .orion/".into(),
                };
            }
            let Some(full_path) = safe_path(workspace, &path) else {
                return ServerMessage::Error { msg: "Invalid path".into() };
            };
            let bytes = match BASE64.decode(&content) {
                Ok(b) => b,
                Err(_) => {
                    return ServerMessage::Error {
                        msg: "Invalid base64".into(),
                    }
                }
            };

            save_prev_snapshot(workspace, &path);
            if let Some(parent) = full_path.parent() {
                let _ = fs::create_dir_all(parent);
            }

            match fs::write(&full_path, &bytes) {
                Ok(_) => {
                    let hash = hash_bytes(&bytes);
                    update_index_entry(workspace, &path, &hash);
                    append_log(
                        workspace,
                        LogEntry {
                            timestamp: Utc::now(),
                            direction: SyncDirection::Push,
                            files: vec![path.clone()],
                            forced: false,
                        },
                    );
                    ServerMessage::Ok {
                        msg: format!("Uploaded {} ({} bytes)", path, bytes.len()),
                    }
                }
                Err(e) => ServerMessage::Error {
                    msg: format!("Write failed: {}", e),
                },
            }
        }

        // ── Pull (conflict-aware) ────────────────────────────────────────────
        //
        // Client sends its local hashes. Server replies with the list of files
        // the client should download (safe-to-pull or forced). The client then
        // calls DownloadFile for each path in the response.
        ClientMessage::Pull { files, force, dry_run } => {
            let ignore_patterns = load_ignore_patterns(workspace);
            let remote = build_server_manifest(workspace, &ignore_patterns);
            let index = read_index(workspace);

            // Union of all paths visible from any side
            let all_paths: HashSet<String> = files
                .keys()
                .chain(remote.keys())
                .chain(index.keys())
                .cloned()
                .collect();

            let mut needs: Vec<String> = Vec::new();
            let mut conflicts: Vec<String> = Vec::new();
            let mut actions: Vec<DryRunAction> = Vec::new();

            for path in &all_paths {
                if is_orion_internal(path) || is_ignored(&ignore_patterns, path) {
                    continue;
                }
                let local_hash = files.get(path).map(String::as_str);
                let remote_hash = remote.get(path).map(String::as_str);
                let idx_hash = index.get(path).map(|e| e.hash.as_str());

                let (action, reason) =
                    pull_decision(local_hash, remote_hash, idx_hash, force);

                match action {
                    DryRunActionKind::Pull => needs.push(path.clone()),
                    DryRunActionKind::Conflict => conflicts.push(path.clone()),
                    _ => {}
                }
                actions.push(DryRunAction {
                    path: path.clone(),
                    action,
                    reason: reason.to_string(),
                });
            }

            if !conflicts.is_empty() && !force {
                return ServerMessage::Error {
                    msg: format!(
                        "CONFLICT: {} file(s) have diverged — resolve manually or use --force:\n  {}",
                        conflicts.len(),
                        conflicts.join("\n  ")
                    ),
                };
            }

            if dry_run {
                return ServerMessage::DryRunReport { actions };
            }

            ServerMessage::ManifestResponse { needs }
        }

        // ── Single file download ─────────────────────────────────────────────
        ClientMessage::DownloadFile { path } => {
            if is_orion_internal(&path) {
                return ServerMessage::Error {
                    msg: "Cannot read .orion/ files".into(),
                };
            }
            let Some(full_path) = safe_path(workspace, &path) else {
                return ServerMessage::Error { msg: "Invalid path".into() };
            };
            match fs::read(&full_path) {
                Ok(bytes) => {
                    let hash = hash_bytes(&bytes);
                    update_index_entry(workspace, &path, &hash);
                    append_log(
                        workspace,
                        LogEntry {
                            timestamp: Utc::now(),
                            direction: SyncDirection::Pull,
                            files: vec![path.clone()],
                            forced: false,
                        },
                    );
                    ServerMessage::FileContent {
                        path,
                        content: BASE64.encode(&bytes),
                    }
                }
                Err(_) => ServerMessage::Error {
                    msg: format!("Not found: {}", path),
                },
            }
        }

        // ── Recursive directory manifest ─────────────────────────────────────
        ClientMessage::DownloadDir { path } => {
            let ignore_patterns = load_ignore_patterns(workspace);
            let base = Path::new(workspace);
            let target = base.join(&path);

            let entries = WalkDir::new(&target)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let meta = e.metadata().ok()?;
                    let rel = e
                        .path()
                        .strip_prefix(base)
                        .ok()?
                        .to_string_lossy()
                        .into_owned();
                    if is_orion_internal(&rel) || is_ignored(&ignore_patterns, &rel) {
                        return None;
                    }
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

        // ── Shallow directory listing ────────────────────────────────────────
        ClientMessage::ListDir { path } => {
            let ignore_patterns = load_ignore_patterns(workspace);
            let base = Path::new(workspace);
            let target = base.join(&path);

            let entries = match fs::read_dir(&target) {
                Ok(rd) => rd
                    .filter_map(|e| e.ok())
                    .filter_map(|e| {
                        let meta = e.metadata().ok()?;
                        let rel = e
                            .path()
                            .strip_prefix(base)
                            .ok()?
                            .to_string_lossy()
                            .into_owned();
                        if is_orion_internal(&rel) || is_ignored(&ignore_patterns, &rel) {
                            return None;
                        }
                        Some(DirEntry {
                            name: e.file_name().to_string_lossy().into(),
                            path: rel,
                            is_dir: meta.is_dir(),
                            size: if meta.is_file() { meta.len() } else { 0 },
                            hash: if meta.is_file() { hash_file(&e.path()) } else { None },
                        })
                    })
                    .collect(),
                Err(e) => {
                    return ServerMessage::Error {
                        msg: format!("Can't read dir: {}", e),
                    }
                }
            };

            ServerMessage::DirListing { path, entries }
        }

        // ── GetFileHash ──────────────────────────────────────────────────────
        ClientMessage::GetFileHash { path } => {
            if is_orion_internal(&path) {
                return ServerMessage::FileHash { path, hash: None };
            }
            let ignore_patterns = load_ignore_patterns(workspace);
            if is_ignored(&ignore_patterns, &path) {
                return ServerMessage::FileHash { path, hash: None };
            }
            let Some(full_path) = safe_path(workspace, &path) else {
                return ServerMessage::Error { msg: "Invalid path".into() };
            };
            ServerMessage::FileHash {
                path,
                hash: hash_file(&full_path),
            }
        }

        // ── GetStatus ────────────────────────────────────────────────────────
        ClientMessage::GetStatus { files } => {
            let ignore_patterns = load_ignore_patterns(workspace);
            let statuses = compute_status(workspace, &files, &ignore_patterns);
            ServerMessage::StatusReport { files: statuses }
        }

        // ── GetLog ───────────────────────────────────────────────────────────
        ClientMessage::GetLog { n, all } => {
            let mut entries = read_log(workspace);
            entries.reverse(); // most-recent first
            if !all {
                entries.truncate(n.unwrap_or(20));
            }
            ServerMessage::LogEntries { entries }
        }

        // ── GetDiff ──────────────────────────────────────────────────────────
        // Returns a unified diff: previous snapshot → current remote file.
        ClientMessage::GetDiff { path } => {
            if is_orion_internal(&path) {
                return ServerMessage::Error {
                    msg: "Cannot diff .orion/ files".into(),
                };
            }
            let Some(full_path) = safe_path(workspace, &path) else {
                return ServerMessage::Error { msg: "Invalid path".into() };
            };
            let current = fs::read_to_string(&full_path).unwrap_or_default();
            let prev_path = Path::new(workspace).join(PREV_DIR).join(&path);
            let prev = fs::read_to_string(&prev_path).unwrap_or_default();

            let patch = diffy::create_patch(&prev, &current);
            ServerMessage::Diff {
                path,
                diff: patch.to_string(),
            }
        }

        // ── RestoreFile ──────────────────────────────────────────────────────
        // Replaces the current remote file with the stored previous snapshot.
        ClientMessage::RestoreFile { path } => {
            if is_orion_internal(&path) {
                return ServerMessage::Error {
                    msg: "Cannot restore .orion/ files".into(),
                };
            }
            let base = Path::new(workspace);
            let prev_path = base.join(PREV_DIR).join(&path);

            if !prev_path.exists() {
                return ServerMessage::Error {
                    msg: format!("No previous snapshot for '{}'", path),
                };
            }

            let snapshot = match fs::read(&prev_path) {
                Ok(b) => b,
                Err(_) => {
                    return ServerMessage::Error {
                        msg: format!("Failed to read snapshot for '{}'", path),
                    }
                }
            };

            let Some(full_path) = safe_path(workspace, &path) else {
                return ServerMessage::Error { msg: "Invalid path".into() };
            };

            // Preserve the current file as the new "prev" before overwriting.
            save_prev_snapshot(workspace, &path);

            if let Some(parent) = full_path.parent() {
                let _ = fs::create_dir_all(parent);
            }

            match fs::write(&full_path, &snapshot) {
                Ok(_) => {
                    let hash = hash_bytes(&snapshot);
                    update_index_entry(workspace, &path, &hash);
                    append_log(
                        workspace,
                        LogEntry {
                            timestamp: Utc::now(),
                            direction: SyncDirection::Pull,
                            files: vec![format!("restore:{}", path)],
                            forced: false,
                        },
                    );
                    ServerMessage::Ok {
                        msg: format!("Restored '{}' from previous snapshot", path),
                    }
                }
                Err(e) => ServerMessage::Error {
                    msg: format!("Restore write failed: {}", e),
                },
            }
        }
    }
}

// ── Conflict-decision helpers ─────────────────────────────────────────────────

/// Decide what to do with one file during a **push** (Manifest).
fn push_decision(
    local: &str,
    remote: Option<&str>,
    idx: Option<&str>,
    force: bool,
) -> (DryRunActionKind, &'static str) {
    match (remote, idx) {
        // ── Never seen before ────────────────────────────────────────────────
        (None, None) => (DryRunActionKind::Push, "new file"),

        // ── Remote exists, never indexed ────────────────────────────────────
        (Some(r), None) if r == local => (DryRunActionKind::Skip, "identical content, untracked"),
        (Some(_), None) if force => (DryRunActionKind::Push, "forced (untracked conflict)"),
        (Some(_), None) => (DryRunActionKind::Conflict, "remote exists but not indexed"),

        // ── Both local and remote match index → clean ────────────────────────
        (Some(r), Some(i)) if local == i && r == i => (DryRunActionKind::Skip, "clean"),

        // ── Local changed, remote unchanged → safe push ──────────────────────
        (Some(r), Some(i)) if local != i && r == i => {
            (DryRunActionKind::Push, "local modified, remote unchanged")
        }

        // ── Remote changed, local unchanged → client should pull ────────────
        (Some(r), Some(i)) if r != i && local == i => {
            (DryRunActionKind::Skip, "remote modified, local unchanged — pull to update")
        }

        // ── File deleted on remote ───────────────────────────────────────────
        (None, Some(_)) if force => (DryRunActionKind::Push, "forced (remote was deleted)"),
        (None, Some(_)) => (DryRunActionKind::Conflict, "remote was deleted but local still exists"),

        // ── Both sides changed ───────────────────────────────────────────────
        (Some(r), Some(_)) if r == local => (DryRunActionKind::Skip, "both modified identically"),
        (Some(_), Some(_)) if force => (DryRunActionKind::Push, "forced (both sides modified)"),
        (Some(_), Some(_)) => (DryRunActionKind::Conflict, "both local and remote modified"),
    }
}

/// Decide what to do with one file during a **pull**.
fn pull_decision(
    local: Option<&str>,
    remote: Option<&str>,
    idx: Option<&str>,
    force: bool,
) -> (DryRunActionKind, &'static str) {
    match (local, remote, idx) {
        // ── File absent everywhere ───────────────────────────────────────────
        (None, None, _) => (DryRunActionKind::Skip, "absent everywhere"),

        // ── Remote absent, nothing to pull ──────────────────────────────────
        (_, None, _) => (DryRunActionKind::Skip, "not present on remote"),

        // ── New remote file client doesn't have ─────────────────────────────
        (None, Some(_), None) => (DryRunActionKind::Pull, "new remote file"),
        (None, Some(_), Some(_)) => (DryRunActionKind::Pull, "deleted locally, still on remote"),

        // ── All three match ──────────────────────────────────────────────────
        (Some(l), Some(r), Some(i)) if l == r && r == i => (DryRunActionKind::Skip, "clean"),

        // ── Remote changed, local unchanged → safe pull ──────────────────────
        (Some(l), Some(r), Some(i)) if r != i && l == i => {
            (DryRunActionKind::Pull, "remote modified, local unchanged")
        }
        (Some(l), Some(r), None) if l == r => (DryRunActionKind::Skip, "identical content"),

        // ── Both match index or each other ───────────────────────────────────
        (Some(l), Some(r), _) if l == r => (DryRunActionKind::Skip, "already in sync"),

        // ── Local changed, remote unchanged ─────────────────────────────────
        (Some(l), Some(r), Some(i)) if l != i && r == i => {
            (DryRunActionKind::Skip, "local modified, remote unchanged — push to sync")
        }

        // ── Both sides changed ───────────────────────────────────────────────
        (Some(_), Some(_), _) if force => {
            (DryRunActionKind::Pull, "forced (both sides modified)")
        }
        (Some(_), Some(_), _) => {
            (DryRunActionKind::Conflict, "both local and remote modified")
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

    // First message must be the auth key.
    let role = match read.next().await {
        Some(Ok(Message::Text(key))) => match authenticate(key.trim(), &keys) {
            Some(role) => {
                let _ = write
                    .send(Message::Text(
                        send(ServerMessage::Ok {
                            msg: format!("AUTH_OK:{:?}", role),
                        })
                        .into(),
                    ))
                    .await;
                println!("[+] {} authenticated as {:?}", addr, role);
                role
            }
            None => {
                let _ = write
                    .send(Message::Text(
                        send(ServerMessage::Error {
                            msg: "AUTH_FAIL:Invalid key".into(),
                        })
                        .into(),
                    ))
                    .await;
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
                    Err(e) => ServerMessage::Error {
                        msg: format!("Bad message format: {}", e),
                    },
                };
                if write
                    .send(Message::Text(send(response).into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Ok(Message::Ping(data)) => {
                let _ = write.send(Message::Pong(data)).await;
            }
            Ok(Message::Close(_)) | Err(_) => break,
            _ => {}
        }
    }

    println!("[-] {} disconnected", addr);
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Ensure workspace and metadata directory exist on first run.
    fs::create_dir_all(WORKSPACE).expect("Failed to create workspace directory");
    fs::create_dir_all(Path::new(WORKSPACE).join(ORION_DIR))
        .expect("Failed to create .orion directory");

    let keys = Arc::new(load_or_generate_keys());
    let listener = TcpListener::bind(ADDR).await.expect("Failed to bind");
    println!("[*] Orion listening on ws://{}", ADDR);

    while let Ok((stream, addr)) = listener.accept().await {
        let keys = Arc::clone(&keys);
        tokio::spawn(handle_connection(stream, addr, keys));
    }
}