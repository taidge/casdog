use std::{collections::BTreeSet, net::Ipv4Addr, path::PathBuf, time::Duration};

use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::{
    error::{AppError, AppResult},
    hoops::authz::Principal,
    models::provider::Provider,
};

#[derive(Clone, Debug, Default)]
pub struct SystemGapConfig {
    pub manifest_url: Option<String>,
    pub manifest_sha256: Option<String>,
    pub install_path: Option<PathBuf>,
    pub restart_program: Option<PathBuf>,
    pub restart_args: Vec<String>,
}

impl SystemGapConfig {
    pub fn from_env() -> Self {
        let restart_args = std::env::var("CASDOG_UPGRADE_RESTART_ARGS")
            .ok()
            .map(|value| serde_json::from_str::<Vec<String>>(&value))
            .transpose();
        let restart_program = restart_args
            .as_ref()
            .ok()
            .and_then(|_| std::env::var_os("CASDOG_UPGRADE_RESTART_PROGRAM"))
            .map(PathBuf::from);
        Self {
            manifest_url: std::env::var("CASDOG_UPGRADE_MANIFEST_URL").ok(),
            manifest_sha256: std::env::var("CASDOG_UPGRADE_MANIFEST_SHA256").ok(),
            install_path: std::env::var_os("CASDOG_UPGRADE_INSTALL_PATH").map(PathBuf::from),
            restart_program,
            restart_args: restart_args.ok().flatten().unwrap_or_default(),
        }
    }
}

fn invalid(message: impl std::fmt::Display) -> AppError {
    AppError::Validation(message.to_string())
}
pub fn denied() -> AppError {
    AppError::Authorization("Operation unavailable for this tenant".into())
}
fn internal(error: impl std::fmt::Display) -> AppError {
    AppError::Internal(error.to_string())
}
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Pin DNS answers to the checked addresses, and never follow redirects to a
/// different origin. Tenant-controlled providers cannot access private services.
pub async fn client(url: &Url, allow_private: bool) -> AppResult<reqwest::Client> {
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "An HTTP(S) URL without credentials or fragment is required",
        ));
    }
    let host = url.host_str().ok_or_else(|| invalid("URL host required"))?;
    // URL authority syntax includes brackets for IPv6; socket resolution and
    // DNS override keys require the address without those brackets.
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    let addresses: Vec<_> = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::lookup_host((host, url.port_or_known_default().unwrap_or(443))),
    )
    .await
    .map_err(|_| invalid("Provider DNS lookup timed out"))?
    .map_err(invalid)?
    .collect();
    let non_public = |ip: std::net::IpAddr| match ip {
        std::net::IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.octets()[0] == 0
                || ip.octets()[0] >= 240
                || (ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
        }
        std::net::IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
                || ip.to_ipv4_mapped().is_some()
        }
    };
    if addresses.is_empty()
        || (!allow_private && addresses.iter().any(|address| non_public(address.ip())))
    {
        return Err(denied());
    }
    reqwest::Client::builder()
        .no_proxy()
        .resolve_to_addrs(host, &addresses)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(8))
        .connect_timeout(Duration::from_secs(2))
        .build()
        .map_err(internal)
}

pub async fn limited_bytes(mut response: reqwest::Response, limit: usize) -> AppResult<Vec<u8>> {
    if !response.status().is_success() {
        return Err(invalid(format!(
            "Provider returned HTTP {}",
            response.status()
        )));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(invalid)? {
        if bytes.len() + chunk.len() > limit {
            return Err(invalid(
                "Provider response exceeds the configured size limit",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[derive(Clone, Deserialize)]
pub struct Release {
    pub version: String,
    pub url: String,
    pub sha256: String,
    pub size: usize,
    pub target: String,
}

fn version(value: &str) -> AppResult<[u64; 3]> {
    let parts: Vec<_> = value
        .strip_prefix('v')
        .unwrap_or(value)
        .split('.')
        .collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(invalid("Release version must contain major.minor.patch"));
    }
    Ok([
        parts[0].parse().map_err(invalid)?,
        parts[1].parse().map_err(invalid)?,
        parts[2].parse().map_err(invalid)?,
    ])
}

async fn release(config: &SystemGapConfig) -> AppResult<Release> {
    let url = Url::parse(
        config
            .manifest_url
            .as_deref()
            .ok_or_else(|| invalid("Upgrade manifest is not configured"))?,
    )
    .map_err(invalid)?;
    if url.scheme() != "https" && !matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"))
    {
        return Err(invalid("Upgrade manifest requires HTTPS"));
    }
    let expected = config
        .manifest_sha256
        .as_deref()
        .ok_or_else(|| invalid("A trusted manifest SHA-256 is required"))?;
    let bytes = limited_bytes(
        client(&url, true)
            .await?
            .get(url.clone())
            .send()
            .await
            .map_err(invalid)?,
        65_536,
    )
    .await?;
    if expected.len() != 64 || !digest(&bytes).eq_ignore_ascii_case(expected) {
        return Err(invalid(
            "Upgrade manifest does not match the operator's trusted SHA-256",
        ));
    }
    let release: Release = serde_json::from_slice(&bytes).map_err(invalid)?;
    version(&release.version)?;
    let package = Url::parse(&release.url).map_err(invalid)?;
    if package.origin() != url.origin()
        || release.size == 0
        || release.size > 268_435_456
        || release.sha256.len() != 64
        || !release.sha256.bytes().all(|b| b.is_ascii_hexdigit())
        || release.version.is_empty()
        || release.version.len() > 100
        || release.target != format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
    {
        return Err(invalid(
            "Invalid upgrade package origin, size, digest, version or platform",
        ));
    }
    Ok(release)
}

pub async fn upgrade_info(pool: &PgPool, config: &SystemGapConfig) -> AppResult<Value> {
    let status: Option<Value> = sqlx::query_scalar(
        "SELECT status FROM system_upgrade_history ORDER BY created_at DESC,id DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    let configured = config.manifest_url.is_some() && config.manifest_sha256.is_some();
    let install_ready = config.install_path.as_ref().is_some_and(|path| {
        path.is_absolute()
            && std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
    });
    let restart_ready = config
        .restart_program
        .as_ref()
        .is_some_and(|path| path.is_absolute() && path.is_file());
    let mut info = json!({"currentVersion":env!("CARGO_PKG_VERSION"),"deploymentType":"binary",
        "latestVersion":"","latestUrl":"","hasNewVersion":false,"isCheckDisabled":!configured,
        "isUpgradeDisabled":!install_ready || !restart_ready,"canUpgrade":false,
        "checkError":"","status":status});
    if configured {
        match release(config).await {
            Ok(release) => {
                let newer = version(&release.version)? > version(env!("CARGO_PKG_VERSION"))?;
                info["latestVersion"] = json!(release.version);
                info["latestUrl"] = json!(release.url);
                info["hasNewVersion"] = json!(newer);
                info["canUpgrade"] = json!(newer && install_ready && restart_ready);
            }
            Err(error) => info["checkError"] = json!(error.to_string()),
        }
    }
    Ok(info)
}

#[derive(Clone, Serialize, Deserialize)]
struct UpgradeJournal {
    destination: PathBuf,
    stage: PathBuf,
    backup: PathBuf,
    previous_sha256: String,
    package_sha256: String,
    machine: String,
}

fn machine() -> String {
    std::env::var("CASDOG_UPGRADE_INSTANCE_ID")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "local".into())
}
fn install_destination(config: &SystemGapConfig) -> AppResult<PathBuf> {
    let destination = config
        .install_path
        .as_ref()
        .ok_or_else(|| invalid("Upgrade install path is not configured"))?;
    if !destination.is_absolute() {
        return Err(invalid("Upgrade install path must be absolute"));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| invalid("Upgrade install parent required"))?
        .canonicalize()
        .map_err(internal)?;
    let destination = parent.join(
        destination
            .file_name()
            .ok_or_else(|| invalid("Upgrade installation file name required"))?,
    );
    if destination.to_str().is_none() {
        return Err(invalid("Upgrade installation path must use UTF-8"));
    }
    Ok(destination)
}
fn install_paths(config: &SystemGapConfig, id: &str) -> AppResult<(PathBuf, PathBuf, PathBuf)> {
    uuid::Uuid::parse_str(id).map_err(invalid)?;
    let destination = install_destination(config)?;
    let parent = destination.parent().unwrap();
    let stage = parent.join(format!(".casdog-upgrade-{id}.new"));
    let backup = parent.join(format!(".casdog-upgrade-{id}.backup"));
    for path in [&destination, &stage, &backup] {
        if let Ok(metadata) = std::fs::symlink_metadata(path) {
            if !metadata.file_type().is_file() || metadata.len() > 268_435_456 {
                return Err(invalid(
                    "Upgrade paths must be regular files no larger than 256 MiB",
                ));
            }
        }
    }
    Ok((destination, stage, backup))
}
fn file_digest(path: &std::path::Path) -> AppResult<String> {
    Ok(digest(&std::fs::read(path).map_err(internal)?))
}

fn validate_journal(config: &SystemGapConfig, id: &str, journal: &UpgradeJournal) -> AppResult<()> {
    let (destination, stage, backup) = install_paths(config, id)?;
    if journal.destination != destination
        || journal.stage != stage
        || journal.backup != backup
        || journal.machine != machine()
    {
        return Err(invalid(
            "Pending upgrade belongs to another installation; restore its operator configuration before retrying",
        ));
    }
    Ok(())
}

fn restore_upgrade(config: &SystemGapConfig, id: &str, journal: &UpgradeJournal) -> AppResult<()> {
    validate_journal(config, id, journal)?;
    let (destination, stage, backup) = install_paths(config, id)?;
    if backup.exists() {
        if file_digest(&backup)? != journal.previous_sha256 {
            return Err(invalid(
                "Upgrade backup changed; operator recovery is required",
            ));
        }
        if destination.exists() {
            if file_digest(&destination)? != journal.package_sha256 || stage.exists() {
                return Err(invalid(
                    "Upgrade installation changed; operator recovery is required",
                ));
            }
            std::fs::rename(&destination, &stage).map_err(internal)?;
        }
        std::fs::rename(&backup, &destination).map_err(internal)?;
    } else if !destination.exists() || file_digest(&destination)? != journal.previous_sha256 {
        return Err(invalid(
            "Previous upgrade installation is unavailable; operator recovery is required",
        ));
    }
    if stage.exists() {
        std::fs::remove_file(&stage).map_err(internal)?;
    }
    Ok(())
}

/// Run before accepting requests. A new image confirms an interrupted handover;
/// an old image restores its previous installation before it serves traffic.
pub async fn reconcile_upgrades(pool: &PgPool, config: &SystemGapConfig) -> AppResult<()> {
    if config.install_path.is_none() {
        return Ok(());
    }
    let executable = std::env::current_exe()
        .map_err(internal)?
        .canonicalize()
        .map_err(internal)?;
    // Linux exposes the executing inode even if its directory entry was replaced.
    // Other hosts additionally require the version compiled into this process,
    // preventing an old process from trusting only its newly replaced disk path.
    #[cfg(target_os = "linux")]
    let executable_sha256 = file_digest(std::path::Path::new("/proc/self/exe"))?;
    #[cfg(not(target_os = "linux"))]
    let executable_sha256 = file_digest(&executable)?;
    let mut connection = pool.acquire().await?;
    connection.close_on_drop();
    let locked: bool = sqlx::query_scalar(
        "SELECT pg_try_advisory_lock(hashtextextended('casdog-system-upgrade',0))",
    )
    .fetch_one(&mut *connection)
    .await?;
    if !locked {
        return Err(AppError::Conflict(
            "Another process is still completing an upgrade".into(),
        ));
    }
    let outcome=async {
        let rows:Vec<(String,String,Value)>=sqlx::query_as("SELECT id,version,journal FROM system_upgrade_history WHERE status->>'state' IN ('prepared','installing','restarting','restart_requested','recovery_required') AND journal->>'machine'=$1 AND journal->>'destination'=$2 ORDER BY created_at,id")
            .bind(machine()).bind(install_destination(config)?.to_string_lossy().to_string()).fetch_all(&mut *connection).await?;
        for (id,release_version,document) in rows {
            let journal:UpgradeJournal=serde_json::from_value(document).map_err(invalid)?;
            validate_journal(config,&id,&journal)?;
            let running_new_image=executable==journal.destination && executable_sha256==journal.package_sha256
                && version(env!("CARGO_PKG_VERSION"))?==version(&release_version)?;
            if running_new_image {
                write_upgrade_status(&mut connection,&id,&release_version,"installed",None).await?;
            } else {
                match restore_upgrade(config,&id,&journal) {
                    Ok(())=>{write_upgrade_status(&mut connection,&id,&release_version,"failed",Some("Startup restored the previous executable after an interrupted upgrade".into())).await?;}
                    Err(error)=>{
                        let _=write_upgrade_status(&mut connection,&id,&release_version,"recovery_required",Some(error.to_string())).await;
                        return Err(error);
                    }
                }
            }
        }
        Ok(())
    }.await;
    let _ = sqlx::query("SELECT pg_advisory_unlock(hashtextextended('casdog-system-upgrade',0))")
        .execute(&mut *connection)
        .await;
    let _ = connection.close().await;
    outcome
}

async fn write_upgrade_status(
    connection: &mut sqlx::PgConnection,
    id: &str,
    version: &str,
    state: &str,
    error: Option<String>,
) -> AppResult<Value> {
    let status = json!({"state":state,"version":version,"error":error});
    sqlx::query_scalar("UPDATE system_upgrade_history SET status=status || $2,updated_at=clock_timestamp() WHERE id=$1 RETURNING status")
        .bind(id).bind(&status).fetch_optional(connection).await?
        .ok_or_else(|| AppError::Conflict("Upgrade operation journal disappeared".into()))
}

async fn recover_upgrades(
    connection: &mut sqlx::PgConnection,
    config: &SystemGapConfig,
) -> AppResult<()> {
    let rows:Vec<(String,String,Value,String)>=sqlx::query_as("SELECT id,version,journal,status->>'state' FROM system_upgrade_history WHERE status->>'state' IN ('prepared','installing','restarting','restart_requested','recovery_required') AND journal->>'machine'=$1 AND journal->>'destination'=$2 ORDER BY created_at,id")
        .bind(machine()).bind(install_destination(config)?.to_string_lossy().to_string()).fetch_all(&mut *connection).await?;
    for (id, version, document, state) in rows {
        if state == "restart_requested" {
            return Err(AppError::Conflict(
                "A restart has been requested; wait for startup to confirm the new image".into(),
            ));
        }
        let journal: UpgradeJournal = serde_json::from_value(document).map_err(invalid)?;
        match restore_upgrade(config, &id, &journal) {
            Ok(()) => {
                write_upgrade_status(
                    connection,
                    &id,
                    &version,
                    "failed",
                    Some("Interrupted operation was recovered to the previous executable".into()),
                )
                .await?;
            }
            Err(error) => {
                let _ = write_upgrade_status(
                    connection,
                    &id,
                    &version,
                    "recovery_required",
                    Some(error.to_string()),
                )
                .await;
                return Err(error);
            }
        }
    }
    Ok(())
}

async fn restart(config: &SystemGapConfig) -> AppResult<()> {
    let program = config
        .restart_program
        .as_ref()
        .ok_or_else(|| invalid("Upgrade restart program is not configured"))?;
    if !program.is_absolute() || !program.is_file() {
        return Err(invalid(
            "Upgrade restart program must be an existing absolute file",
        ));
    }
    let mut command = tokio::process::Command::new(program);
    command
        .args(&config.restart_args)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    let result = tokio::time::timeout(Duration::from_secs(30), command.status()).await;
    if result
        .as_ref()
        .is_ok_and(|result| result.as_ref().is_ok_and(|status| status.success()))
    {
        Ok(())
    } else {
        Err(invalid("Upgrade restart program failed or timed out"))
    }
}

pub async fn upgrade(
    pool: &PgPool,
    config: &SystemGapConfig,
    actor: &Principal,
    requested_version: &str,
) -> AppResult<Value> {
    if !actor.global_admin() {
        return Err(denied());
    }
    // A session lock serializes independently committed journal phases. Closing
    // this connection on drop also releases the lock if this future is cancelled.
    let mut connection = pool.acquire().await?;
    connection.close_on_drop();
    let locked: bool = sqlx::query_scalar(
        "SELECT pg_try_advisory_lock(hashtextextended('casdog-system-upgrade',0))",
    )
    .fetch_one(&mut *connection)
    .await?;
    if !locked {
        return Err(AppError::Conflict("Another upgrade is in progress".into()));
    }
    let outcome = async {
        recover_upgrades(&mut connection, config).await?;
        let release = release(config).await?;
        if requested_version != release.version || version(&release.version)? <= version(env!("CARGO_PKG_VERSION"))? {
            return Err(invalid("Only the configured newer release can be installed"));
        }
        let program =
            config.restart_program.as_ref().ok_or_else(|| invalid("Upgrade restart program is not configured"))?;
        if !program.is_absolute() || !program.is_file() {
            return Err(invalid("Upgrade restart program must be an existing absolute file"));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let (destination, stage, backup) = install_paths(config, &id)?;
        let previous_sha256 = file_digest(&destination)?;
        let url = Url::parse(&release.url).map_err(invalid)?;
        let bytes =
            limited_bytes(client(&url, true).await?.get(url).send().await.map_err(invalid)?, release.size).await?;
        if bytes.len() != release.size || !digest(&bytes).eq_ignore_ascii_case(&release.sha256) {
            return Err(invalid("Upgrade package SHA-256 or size mismatch"));
        }
        let journal = UpgradeJournal {
            destination,
            stage,
            backup,
            previous_sha256,
            package_sha256: digest(&bytes),
            machine: machine(),
        };
        let prepared =
            json!({"state":"prepared","version":release.version,"downloaded":bytes.len(),"total":release.size});
        sqlx::query("INSERT INTO system_upgrade_history(id,actor_id,version,status,journal) VALUES($1,$2,$3,$4,$5)")
            .bind(&id)
            .bind(&actor.id)
            .bind(&release.version)
            .bind(&prepared)
            .bind(serde_json::to_value(&journal).map_err(internal)?)
            .execute(&mut *connection)
            .await?;
        let install = async {
            use std::io::Write;
            let mut file =
                std::fs::OpenOptions::new().create_new(true).write(true).open(&journal.stage).map_err(internal)?;
            file.write_all(&bytes).and_then(|_| file.sync_all()).map_err(internal)?;
            std::fs::set_permissions(
                &journal.stage,
                std::fs::metadata(&journal.destination).map_err(internal)?.permissions(),
            )
            .map_err(internal)?;
            drop(file);
            write_upgrade_status(&mut connection, &id, &release.version, "installing", None).await?;
            std::fs::rename(&journal.destination, &journal.backup).map_err(internal)?;
            std::fs::rename(&journal.stage, &journal.destination).map_err(internal)?;
            write_upgrade_status(&mut connection, &id, &release.version, "restarting", None).await?;
            restart(config).await?;
            write_upgrade_status(&mut connection, &id, &release.version, "restart_requested", None).await
        }
        .await;
        match install {
            Ok(status) => Ok(status),
            Err(error) => {
                let restored = restore_upgrade(config, &id, &journal);
                let state = if restored.is_ok() {
                    "failed"
                } else {
                    "recovery_required"
                };
                let reason = match &restored {
                    Ok(()) => error.to_string(),
                    Err(rollback) => format!("{error}; rollback failed: {rollback}"),
                };
                // If this write also fails, the durable prepared/intermediate phase
                // remains available for recovery by the next upgrade request.
                let _ = write_upgrade_status(&mut connection, &id, &release.version, state, Some(reason)).await;
                restored?;
                Err(error)
            }
        }
    }
    .await;
    let _ = sqlx::query("SELECT pg_advisory_unlock(hashtextextended('casdog-system-upgrade',0))")
        .execute(&mut *connection)
        .await;
    let _ = connection.close().await;
    outcome
}

pub async fn provider(
    pool: &PgPool,
    principal: &Principal,
    owner: &str,
    name: &str,
) -> AppResult<Provider> {
    if !principal.global_admin() && !(principal.admin && principal.owner == owner) {
        return Err(denied());
    }
    sqlx::query_as::<_, Provider>("SELECT * FROM providers WHERE owner=$1 AND name=$2")
        .bind(owner)
        .bind(name)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Provider not found".into()))
}

async fn get_document(url: &Url, allow_private: bool) -> AppResult<(String, String)> {
    let response = client(url, allow_private)
        .await?
        .get(url.clone())
        .send()
        .await
        .map_err(invalid)?;
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| format!("{name}: {}", value.to_str().unwrap_or_default()))
        .collect::<Vec<_>>()
        .join("\n");
    let bytes = limited_bytes(response, 2_097_152).await?;
    Ok((headers, String::from_utf8_lossy(&bytes).into_owned()))
}

pub async fn security_scan(
    pool: &PgPool,
    principal: &Principal,
    provider: &Provider,
    target: &str,
) -> AppResult<Value> {
    if !principal.global_admin() && !(principal.admin && principal.owner == provider.owner) {
        return Err(denied());
    }
    tokio::time::timeout(
        Duration::from_secs(60),
        security_scan_inner(pool, principal, provider, target),
    )
    .await
    .map_err(|_| invalid("Security scan exceeded 60 seconds"))?
}

async fn security_scan_inner(
    pool: &PgPool,
    principal: &Principal,
    provider: &Provider,
    target: &str,
) -> AppResult<Value> {
    if provider.category != "Scan" || provider.provider_type != "Security Scan" {
        return Err(invalid("A Scan / Security Scan provider is required"));
    }
    let subtype = provider.sub_type.as_deref().unwrap_or("Url");
    let targets: Vec<(String, String)> = if subtype.eq_ignore_ascii_case("Site") {
        let rows: Vec<(String, String, String, i32)> = sqlx::query_as(
            "SELECT name,domain,ssl_mode,port FROM sites WHERE owner=$1 AND NOT is_deleted",
        )
        .bind(&provider.owner)
        .fetch_all(pool)
        .await?;
        rows.into_iter()
            .filter(|(_, domain, _, _)| target.is_empty() || domain.contains(target))
            .map(|(name, domain, ssl, port)| {
                let scheme = if ssl == "HTTP Only" { "http" } else { "https" };
                (name, format!("{scheme}://{domain}:{port}"))
            })
            .collect()
    } else if subtype.eq_ignore_ascii_case("Url") {
        let selected = if target.trim().is_empty() {
            provider.content.as_deref().unwrap_or_default()
        } else {
            target
        };
        selected
            .split([',', '\n'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|url| (url.to_string(), url.to_string()))
            .collect()
    } else {
        return Err(invalid("Supported scan subtypes are Site and Url"));
    };
    if targets.is_empty() || targets.len() > 32 {
        return Err(invalid("Configure between 1 and 32 scan targets"));
    }
    let list = provider
        .endpoint
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("https://casdoor.ai/casdoor-data/data.json");
    let list_url = Url::parse(list).map_err(invalid)?;
    let bytes = limited_bytes(
        client(&list_url, principal.global_admin())
            .await?
            .get(list_url)
            .send()
            .await
            .map_err(invalid)?,
        4_194_304,
    )
    .await?;
    let catalog: Value = serde_json::from_slice(&bytes).map_err(invalid)?;
    let fingerprints = catalog["fingerprintList"]
        .as_array()
        .ok_or_else(|| invalid("Scanner catalog must contain fingerprintList"))?;
    if fingerprints.len() > 128 {
        return Err(invalid("Scanner catalog exceeds 128 fingerprints"));
    }
    let mut findings = Vec::new();
    for (name, target) in targets {
        let base = Url::parse(&target).map_err(invalid)?;
        let before = findings.len();
        for fingerprint in fingerprints {
            let info = &fingerprint["httpInfo"];
            if info["method"]
                .as_str()
                .is_some_and(|method| !method.eq_ignore_ascii_case("GET"))
            {
                return Err(invalid("Only GET fingerprint probes are supported"));
            }
            let path = info["path"].as_str().unwrap_or("/");
            let probe = base.join(path).map_err(invalid)?;
            if probe.origin() != base.origin() {
                return Err(invalid("Fingerprint paths must stay on the target origin"));
            }
            let (headers, body) = get_document(&probe, principal.global_admin()).await?;
            let matchers = info["matchers"]
                .as_array()
                .ok_or_else(|| invalid("Fingerprint matchers are required"))?;
            let mut matched = false;
            for matcher in matchers {
                let value = matcher["value"].as_str().unwrap_or_default().trim();
                if value.is_empty() {
                    continue;
                }
                matched |= match matcher["pos"].as_str().unwrap_or("body") {
                    "body" => body.contains(value),
                    "header" | "headers" => headers
                        .to_ascii_lowercase()
                        .contains(&value.to_ascii_lowercase()),
                    "icon" => {
                        let icon = base.join("/favicon.ico").map_err(invalid)?;
                        let response = client(&icon, principal.global_admin())
                            .await?
                            .get(icon)
                            .send()
                            .await
                            .map_err(invalid)?;
                        let status = response.status().as_u16();
                        if status.to_string() == value {
                            true
                        } else {
                            let bytes = limited_bytes(response, 262_144).await?;
                            bytes.len().to_string() == value
                                || String::from_utf8_lossy(&bytes).contains(value)
                        }
                    }
                    _ => false,
                };
            }
            if !matched {
                continue;
            }
            let version_info = &fingerprint["versionInfo"];
            let mut version = String::new();
            if let Some(pattern) = version_info["regex"]
                .as_str()
                .filter(|value| !value.is_empty())
            {
                let path = version_info["path"].as_str().unwrap_or(path);
                let url = base.join(path).map_err(invalid)?;
                if url.origin() != base.origin() {
                    return Err(invalid("Version probe must stay on the target origin"));
                }
                let (headers, body) = get_document(&url, principal.global_admin()).await?;
                let part = if matches!(version_info["part"].as_str(), Some("header" | "headers")) {
                    headers
                } else {
                    body
                };
                let regex = regex::RegexBuilder::new(pattern)
                    .size_limit(262_144)
                    .build()
                    .map_err(invalid)?;
                version = regex
                    .captures(&part)
                    .and_then(|captures| captures.get(1).or_else(|| captures.get(0)))
                    .map(|value| value.as_str().to_string())
                    .unwrap_or_default();
            }
            let cves: Vec<Value> = catalog["cveList"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|cve| {
                    cve["name"] == fingerprint["name"]
                        && cve["rule"].as_str().unwrap_or_default().is_empty()
                })
                .cloned()
                .collect();
            let unassessed: Vec<Value> = catalog["cveList"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|cve| {
                    cve["name"] == fingerprint["name"]
                        && !cve["rule"].as_str().unwrap_or_default().is_empty()
                })
                .cloned()
                .collect();
            findings.push(json!({"name":name,"product":fingerprint["product"],"vendor":fingerprint["vendor"],"version":version,"severity":fingerprint["severity"],"targetUrl":target,"cves":cves,"assessmentComplete":unassessed.is_empty(),"unassessedCves":unassessed}));
        }
        if before == findings.len() {
            findings.push(json!({"name":name,"product":"Unknown","vendor":"Unknown","version":"","severity":"Unknown","targetUrl":target,"cves":[]}));
        }
    }
    let result = json!(findings);
    sqlx::query("UPDATE providers SET metadata=$1,updated_at=NOW() WHERE id=$2 AND updated_at=$3")
        .bind(result.to_string())
        .bind(&provider.id)
        .bind(provider.updated_at)
        .execute(pool)
        .await?
        .rows_affected()
        .eq(&1)
        .then_some(())
        .ok_or_else(|| {
            AppError::Conflict(
                "Provider changed during scanning; retry with its current configuration".into(),
            )
        })?;
    Ok(result)
}

fn targets(value: &str) -> AppResult<BTreeSet<Ipv4Addr>> {
    let mut result = BTreeSet::new();
    for target in value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let (address, prefix) = target.split_once('/').unwrap_or((target, "32"));
        let address: Ipv4Addr = address.parse().map_err(invalid)?;
        let prefix: u32 = prefix.parse().map_err(invalid)?;
        if !(22..=32).contains(&prefix) {
            return Err(invalid("Intranet CIDR prefix must be /22 through /32"));
        }
        let count = 1u32 << (32 - prefix);
        let base = u32::from(address) & (u32::MAX << (32 - prefix));
        for offset in 0..count {
            let ip = Ipv4Addr::from(base + offset);
            if !ip.is_private() && !ip.is_loopback() && !ip.is_link_local() {
                return Err(invalid("Intranet targets must be private IPv4 addresses"));
            }
            result.insert(ip);
            if result.len() > 1024 {
                return Err(invalid("At most 1024 hosts may be scanned"));
            }
        }
    }
    if result.is_empty() {
        return Err(invalid("Configure intranet targets in provider scopes"));
    }
    Ok(result)
}

pub async fn intranet_scan(principal: &Principal, provider: &Provider) -> AppResult<Value> {
    if !principal.global_admin() {
        return Err(denied());
    }
    if provider.category != "Scan"
        || provider.provider_type != "MCP Scan"
        || provider.sub_type.as_deref() != Some("Intranet Scan")
    {
        return Err(invalid(
            "A Scan / MCP Scan / Intranet Scan provider is required",
        ));
    }
    let hosts = targets(provider.scopes.as_deref().unwrap_or_default())?;
    let ports: Vec<u16> = provider
        .content
        .as_deref()
        .unwrap_or("3000,8080,80")
        .split(',')
        .map(|value| value.trim().parse::<u16>().map_err(invalid))
        .collect::<AppResult<_>>()?;
    let paths: Vec<String> = provider
        .endpoint
        .as_deref()
        .unwrap_or("/,/mcp,/sse,/mcp/sse")
        .split(',')
        .map(|value| value.trim().to_string())
        .collect();
    if ports.is_empty()
        || ports.len() > 16
        || ports.contains(&0)
        || paths.is_empty()
        || paths.len() > 8
        || paths.iter().any(|path| {
            !path.starts_with('/')
                || path.starts_with("//")
                || path.contains(['?', '#', '\\'])
                || path.len() > 128
        })
    {
        return Err(invalid(
            "Configure up to 16 valid ports and 8 absolute paths",
        ));
    }
    let mut jobs = tokio::task::JoinSet::new();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(16));
    for host in hosts.iter().copied() {
        let semaphore = semaphore.clone();
        let ports = ports.clone();
        let paths = paths.clone();
        jobs.spawn(async move {
            let _permit=semaphore.acquire_owned().await.map_err(internal)?;
            let client=reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_millis(1200)).build().map_err(internal)?;
            let mut online=false;let mut servers=Vec::new();
            for port in ports {
                for path in &paths {
                    let url=format!("http://{host}:{port}{path}");
                    let response=client.post(&url).header("Accept","application/json, text/event-stream")
                        .json(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"casdog-discovery","version":env!("CARGO_PKG_VERSION")}}})).send().await;
                    let Ok(response)=response else{continue;};online=true;
                    let Ok(bytes)=limited_bytes(response,262_144).await else{continue;};
                    let text=String::from_utf8_lossy(&bytes);
                    let document=serde_json::from_slice::<Value>(&bytes).ok().or_else(||text.lines().filter_map(|line|line.strip_prefix("data:")).find_map(|line|serde_json::from_str::<Value>(line.trim()).ok()));
                    if let Some(document)=document.filter(|value|value["jsonrpc"]=="2.0" && value["id"]==1 && value["result"]["protocolVersion"].is_string() && value["result"]["serverInfo"].is_object()) {
                        servers.push(json!({"url":url,"name":document["result"]["serverInfo"]["name"],"version":document["result"]["serverInfo"]["version"],"protocolVersion":document["result"]["protocolVersion"],"capabilities":document["result"]["capabilities"]}));
                    }
                }
            }
            Ok::<_,AppError>((host.to_string(),online,servers))
        });
    }
    let collect = async {
        let mut online = Vec::new();
        let mut servers = Vec::new();
        while let Some(result) = jobs.join_next().await {
            let (host, is_online, found) = result.map_err(internal)??;
            if is_online {
                online.push(host);
            }
            servers.extend(found);
        }
        online.sort();
        servers.sort_by_key(|server| server["url"].as_str().unwrap_or_default().to_string());
        Ok::<_, AppError>(
            json!({"cidr":provider.scopes.as_deref().unwrap_or_default().split(',').collect::<Vec<_>>(),"scannedHosts":hosts.len(),"onlineHosts":online,"servers":servers}),
        )
    };
    tokio::time::timeout(Duration::from_secs(60), collect)
        .await
        .map_err(|_| invalid("Intranet scan exceeded 60 seconds"))?
}

pub async fn sync_intranet_servers(
    pool: &PgPool,
    principal: &Principal,
    provider: &Provider,
) -> AppResult<Value> {
    let mut result = intranet_scan(principal, provider).await?;
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("intranet-sync:{}", provider.owner))
        .execute(&mut *transaction)
        .await?;
    let current: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT updated_at FROM providers WHERE id=$1 FOR SHARE")
            .bind(&provider.id)
            .fetch_optional(&mut *transaction)
            .await?;
    if current != Some(provider.updated_at) {
        return Err(AppError::Conflict(
            "Provider changed during discovery; retry with its current configuration".into(),
        ));
    }
    for server in result["servers"].as_array_mut().unwrap() {
        let url = server["url"]
            .as_str()
            .ok_or_else(|| invalid("Discovered server URL missing"))?;
        let existing:Option<String> = sqlx::query_scalar("SELECT name FROM casdoor_objects WHERE kind='server' AND owner=$1 AND document->>'url'=$2 ORDER BY name LIMIT 1 FOR UPDATE")
            .bind(&provider.owner).bind(url).fetch_optional(&mut *transaction).await?;
        let name =
            existing.unwrap_or_else(|| format!("intranet-{}", &digest(url.as_bytes())[..24]));
        let title = server["name"].as_str().unwrap_or("Discovered MCP server");
        let time = chrono::Utc::now().to_rfc3339();
        let document = json!({"owner":provider.owner,"name":name,"displayName":title,"url":url,"tools":[],"createdTime":time,"updatedTime":time});
        let affected=sqlx::query("INSERT INTO casdoor_objects(kind,owner,name,document) VALUES('server',$1,$2,$3) ON CONFLICT(kind,owner,name) DO UPDATE SET document=casdoor_objects.document || jsonb_build_object('displayName',EXCLUDED.document->'displayName','updatedTime',EXCLUDED.document->'updatedTime'),updated_at=NOW() WHERE casdoor_objects.document->>'url'=EXCLUDED.document->>'url'")
            .bind(&provider.owner).bind(&name).bind(document).execute(&mut *transaction).await?.rows_affected();
        if affected != 1 {
            return Err(AppError::Conflict(
                "Discovered server name conflicts with an existing resource".into(),
            ));
        }
        server["owner"] = json!(provider.owner);
        server["name"] = json!(name);
    }
    transaction.commit().await?;
    Ok(result)
}

pub async fn verify_identification(
    pool: &PgPool,
    principal: &Principal,
    owner: &str,
    name: &str,
    provider_name: Option<&str>,
) -> AppResult<String> {
    if !principal.global_admin()
        && (owner != principal.owner || (!principal.admin && name != principal.name))
    {
        return Err(denied());
    }
    let mut transaction = pool.begin().await?;
    let organization: Option<String> = sqlx::query_scalar(
        "SELECT id FROM organizations WHERE name=$1 AND NOT is_deleted FOR SHARE",
    )
    .bind(owner)
    .fetch_optional(&mut *transaction)
    .await?;
    if organization.is_none() {
        return Err(denied());
    }
    type Subject = (
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        bool,
    );
    let (id, card_type, card, real_name, application, verified): Subject = sqlx::query_as(
        "SELECT id,id_card_type,id_card,real_name,signup_application,is_verified FROM users WHERE owner=$1 AND name=$2 AND NOT is_deleted AND NOT is_forbidden FOR UPDATE")
        .bind(owner).bind(name).fetch_optional(&mut *transaction).await?.ok_or_else(|| AppError::NotFound("User not found".into()))?;
    if !principal.admin && id != principal.id {
        return Err(denied());
    }
    if verified {
        return Err(AppError::Conflict("User is already verified".into()));
    }
    let card_type = card_type
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("ID card type required"))?;
    let card = card
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("ID card number required"))?;
    let real_name = real_name
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("Real name required"))?;
    let application = application.ok_or_else(|| invalid("User has no signup application"))?;
    let applications:Vec<Option<Value>>=sqlx::query_scalar("SELECT providers FROM applications WHERE organization=$1 AND NOT is_deleted AND (id=$2 OR owner||'/'||name=$2 OR name=$2) FOR SHARE")
        .bind(owner).bind(application).fetch_all(&mut *transaction).await?;
    if applications.len() != 1 {
        return Err(denied());
    }
    let configured = applications
        .into_iter()
        .next()
        .flatten()
        .unwrap_or(json!([]));
    let providers:Vec<Provider>=sqlx::query_as("SELECT * FROM providers WHERE category='ID Verification' AND (owner=$1 OR owner='admin') ORDER BY owner,name FOR SHARE")
        .bind(owner).fetch_all(&mut *transaction).await?;
    let available: Vec<_> = providers
        .into_iter()
        .filter(|provider| {
            let reference = format!("{}/{}", provider.owner, provider.name);
            let enabled = configured.as_array().into_iter().flatten().any(|entry| {
                let name = entry.as_str().or_else(|| entry["name"].as_str());
                (name == Some(reference.as_str()) || name == Some(provider.name.as_str()))
                    && entry.get("canVerify").and_then(Value::as_bool) != Some(false)
            });
            enabled
                && provider_name
                    .is_none_or(|requested| requested == reference || requested == provider.name)
        })
        .collect();
    if available.len() != 1 {
        return Err(invalid(
            "Configure exactly one permitted ID Verification provider or select it explicitly",
        ));
    }
    let provider = &available[0];
    if !matches!(provider.provider_type.as_str(), "HTTP" | "Generic") {
        return Err(invalid(
            "This ID Verification provider requires a supported HTTP adapter",
        ));
    }
    let endpoint = provider
        .endpoint
        .as_deref()
        .or(provider.provider_url.as_deref())
        .ok_or_else(|| invalid("Identity verification endpoint required"))?;
    let url = Url::parse(endpoint).map_err(invalid)?;
    if url.scheme() != "https"
        && !(principal.global_admin()
            && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1")))
    {
        return Err(invalid("Identity verification requires HTTPS"));
    }
    let mut request = client(&url, principal.global_admin())
        .await?
        .post(url)
        .json(&json!({"idCardType":card_type,"idCard":card,"realName":real_name}));
    if let Some(secret) = provider
        .client_secret
        .as_deref()
        .filter(|secret| !secret.is_empty())
    {
        request = request.bearer_auth(secret);
    }
    let bytes = limited_bytes(
        request
            .send()
            .await
            .map_err(|_| invalid("Identity verification provider could not be reached"))?,
        65_536,
    )
    .await?;
    let response: Value = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("Identity verification provider returned invalid JSON"))?;
    if response["verified"] != true || response["status"].as_str() == Some("error") {
        return Err(invalid("Identity verification failed"));
    }
    let subject =
        digest(&serde_json::to_vec(&json!([card_type, card, real_name])).map_err(internal)?);
    sqlx::query("UPDATE users SET is_verified=true,updated_at=NOW() WHERE id=$1")
        .bind(&id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("INSERT INTO identification_verifications(id,user_id,provider_id,subject_sha256) VALUES($1,$2,$3,$4)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(id)
        .bind(&provider.id)
        .bind(subject)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(real_name)
}
