use std::collections::HashMap;
use std::fs;
use std::process::Command;
use std::sync::{LazyLock, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use hex::encode as hex_encode;
use salvo::oapi::{ToSchema, endpoint};
use salvo::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{AppError, AppResult};
use crate::services::{CasbinService, CliDownloaderService};

#[derive(Clone)]
struct CachedOutput {
    output: String,
    cached_at: Instant,
}

#[derive(Clone)]
struct CliVersionInfo {
    version: String,
    binary_path: String,
    modified_at: SystemTime,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CasbinCommandResponse {
    pub output: String,
    pub cached: bool,
}

static COMMAND_CACHE: LazyLock<RwLock<HashMap<String, CachedOutput>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));
static CLI_VERSION_CACHE: LazyLock<RwLock<HashMap<String, CliVersionInfo>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));
static CACHE_TTL: Duration = Duration::from_secs(300);
static CLEANUP_GUARD: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn clear_cli_caches() {
    if let Ok(mut cache) = COMMAND_CACHE.write() {
        cache.clear();
    }
    if let Ok(mut cache) = CLI_VERSION_CACHE.write() {
        cache.clear();
    }
}

fn command_binary(language: &str) -> AppResult<std::path::PathBuf> {
    CliDownloaderService::binary_path(language)
}

fn generate_cache_key(language: &str, args: &[String]) -> AppResult<String> {
    let args_json = serde_json::to_vec(args)
        .map_err(|e| AppError::Internal(format!("Failed to serialize args: {}", e)))?;
    let mut hasher = Sha256::new();
    hasher.update(language.as_bytes());
    hasher.update(b":");
    hasher.update(&args_json);
    Ok(hex_encode(hasher.finalize()))
}

fn validate_identifier(req: &Request, language: &str, arg_string: &str) -> AppResult<()> {
    let hash = req.query::<String>("m");
    let timestamp = req.query::<String>("t");
    let (Some(hash), Some(timestamp)) = (hash, timestamp) else {
        return Ok(());
    };

    let request_time = chrono::DateTime::parse_from_rfc3339(&timestamp)
        .map_err(|_| AppError::Authentication("invalid identifier".to_string()))?;
    let age = chrono::Utc::now().signed_duration_since(request_time.with_timezone(&chrono::Utc));
    if age.num_minutes().abs() > 5 {
        return Err(AppError::Authentication("invalid identifier".to_string()));
    }

    let raw = format!(
        "casbin-editor-v1|{}|args={}&language={}",
        timestamp, arg_string, language
    );
    let calculated = hex_encode(Sha256::digest(raw.as_bytes()));
    if calculated != hash.to_ascii_lowercase() {
        return Err(AppError::Authentication("invalid identifier".to_string()));
    }

    Ok(())
}

fn cleanup_cache() {
    let _guard = CLEANUP_GUARD.lock().ok();
    if let Ok(mut cache) = COMMAND_CACHE.write() {
        cache.retain(|_, entry| entry.cached_at.elapsed() < CACHE_TTL);
    }
}

fn get_cached_output(cache_key: &str) -> Option<String> {
    let cache = COMMAND_CACHE.read().ok()?;
    let entry = cache.get(cache_key)?;
    if entry.cached_at.elapsed() >= CACHE_TTL {
        return None;
    }
    Some(entry.output.clone())
}

fn set_cached_output(cache_key: String, output: String) {
    if let Ok(mut cache) = COMMAND_CACHE.write() {
        cache.insert(
            cache_key,
            CachedOutput {
                output,
                cached_at: Instant::now(),
            },
        );
        if cache.len() % 100 == 0 {
            drop(cache);
            cleanup_cache();
        }
    }
}

fn cleanup_old_mei_folders() {
    let Ok(entries) = fs::read_dir("temp") else {
        return;
    };
    let cutoff = SystemTime::now() - Duration::from_secs(24 * 3600);
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !name.starts_with("_MEI") {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if metadata.is_dir()
            && metadata
                .modified()
                .map(|time| time < cutoff)
                .unwrap_or(false)
        {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn process_args_to_temp_files(args: &[String]) -> AppResult<(Vec<String>, Vec<String>)> {
    let mut temp_files = Vec::new();
    let mut processed = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if (arg == "-m" || arg == "-p") && index + 1 < args.len() {
            let file = tempfile::Builder::new()
                .prefix("casbin_temp_")
                .suffix(".conf")
                .tempfile()
                .map_err(|e| AppError::Internal(format!("Failed to create temp file: {}", e)))?;
            fs::write(file.path(), &args[index + 1]).map_err(|e| {
                AppError::Internal(format!("Failed to write temp policy/model file: {}", e))
            })?;
            let kept = file.keep().map_err(|e| {
                AppError::Internal(format!(
                    "Failed to persist temp policy/model file: {}",
                    e.error
                ))
            })?;
            let path = kept.1.to_string_lossy().to_string();
            temp_files.push(path.clone());
            processed.push(arg.clone());
            processed.push(path);
            index += 2;
            continue;
        }
        processed.push(arg.clone());
        index += 1;
    }
    Ok((temp_files, processed))
}

fn get_cli_version(language: &str, binary_name: &str) -> AppResult<String> {
    let binary_path = command_binary(language).or_else(|_| {
        which::which(binary_name)
            .map_err(|e| AppError::NotFound(format!("executable file not found: {}", e)))
    })?;
    let metadata = fs::metadata(&binary_path)
        .map_err(|e| AppError::Internal(format!("failed to inspect binary: {}", e)))?;
    let modified_at = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

    if let Ok(cache) = CLI_VERSION_CACHE.read() {
        if let Some(info) = cache.get(language) {
            if info.binary_path == binary_path.to_string_lossy() && info.modified_at == modified_at
            {
                return Ok(info.version.clone());
            }
        }
    }

    cleanup_old_mei_folders();
    let output = Command::new(&binary_path)
        .arg("--version")
        .output()
        .map_err(|e| {
            AppError::Internal(format!("failed to run {} --version: {}", binary_name, e))
        })?;
    if !output.status.success() {
        return Err(AppError::Internal(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }

    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if let Ok(mut cache) = CLI_VERSION_CACHE.write() {
        cache.insert(
            language.to_string(),
            CliVersionInfo {
                version: version.clone(),
                binary_path: binary_path.to_string_lossy().to_string(),
                modified_at,
            },
        );
    }
    Ok(version)
}

#[endpoint(tags("casbin"), summary = "Run Casbin CLI command")]
pub async fn run_casbin_command(req: &mut Request) -> AppResult<Json<CasbinCommandResponse>> {
    let language = req
        .query::<String>("language")
        .unwrap_or_else(|| "go".to_string());
    let arg_string = req
        .query::<String>("args")
        .ok_or_else(|| AppError::Validation("args is required".to_string()))?;
    validate_identifier(req, &language, &arg_string)?;

    let args: Vec<String> = serde_json::from_str(&arg_string)
        .map_err(|e| AppError::Validation(format!("Invalid args JSON: {}", e)))?;
    let binary_name = format!("casbin-{}-cli", language);
    let cache_key = generate_cache_key(&language, &args)?;

    if let Some(output) = get_cached_output(&cache_key) {
        return Ok(Json(CasbinCommandResponse {
            output,
            cached: true,
        }));
    }

    if matches!(args.first().map(String::as_str), Some("--version")) {
        let output = get_cli_version(&language, &binary_name)?;
        return Ok(Json(CasbinCommandResponse {
            output,
            cached: false,
        }));
    }

    cleanup_old_mei_folders();
    let binary_path = command_binary(&language).or_else(|_| {
        which::which(&binary_name).map_err(|e| {
            AppError::NotFound(format!("executable file {} not found: {}", binary_name, e))
        })
    })?;
    let (temp_files, processed_args) = process_args_to_temp_files(&args)?;
    let output = Command::new(&binary_path)
        .args(&processed_args)
        .output()
        .map_err(|e| {
            AppError::NotFound(format!("executable file {} not found: {}", binary_name, e))
        })?;
    for file in temp_files {
        let _ = fs::remove_file(file);
    }

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let message = if !stderr.is_empty() { stderr } else { stdout };
        return Err(AppError::Internal(message));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    set_cached_output(cache_key, stdout.clone());
    Ok(Json(CasbinCommandResponse {
        output: stdout,
        cached: false,
    }))
}

#[endpoint(tags("casbin"), summary = "Refresh Casbin engines")]
pub async fn refresh_engines(depot: &mut Depot) -> AppResult<Json<serde_json::Value>> {
    let cli_report = CliDownloaderService::refresh_all().await?;
    clear_cli_caches();

    let casbin_service = depot
        .obtain::<CasbinService>()
        .map_err(|_| AppError::Internal("Casbin service not initialized".to_string()))?
        .clone();
    casbin_service.reload().await?;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "msg": "Casbin engines refreshed",
        "cli": cli_report,
    })))
}
