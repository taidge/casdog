use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT};
use serde::Deserialize;

use crate::error::{AppError, AppResult};

const DOWNLOAD_DIR: &str = "bin";
const GO_RELEASE_API: &str = "https://api.github.com/repos/casbin/casbin-go-cli/releases/latest";
const JAVA_RELEASE_API: &str =
    "https://api.github.com/repos/jcasbin/casbin-java-cli/releases/latest";
const RUST_RELEASE_API: &str =
    "https://api.github.com/repos/casbin-rs/casbin-rust-cli/releases/latest";
const PYTHON_RELEASE_API: &str =
    "https://api.github.com/repos/casbin/casbin-python-cli/releases/latest";
const DOTNET_RELEASE_API: &str =
    "https://api.github.com/repos/casbin-net/casbin-dotnet-cli/releases/latest";

#[derive(Debug, Clone, serde::Serialize)]
pub struct CliRefreshEntry {
    pub language: String,
    pub version: Option<String>,
    pub path: Option<String>,
    pub downloaded: bool,
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CliRefreshReport {
    pub download_dir: String,
    pub entries: Vec<CliRefreshEntry>,
}

#[derive(Debug, Deserialize)]
struct ReleaseInfo {
    tag_name: String,
    assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
}

pub struct CliDownloaderService;

impl CliDownloaderService {
    pub fn download_dir() -> AppResult<PathBuf> {
        let dir = std::env::current_dir()
            .map_err(|e| AppError::Internal(format!("failed to determine working directory: {e}")))?
            .join(DOWNLOAD_DIR);
        Ok(dir)
    }

    pub fn ensure_download_dir() -> AppResult<PathBuf> {
        let dir = Self::download_dir()?;
        fs::create_dir_all(&dir)
            .map_err(|e| AppError::Internal(format!("failed to create CLI download dir: {e}")))?;
        Ok(dir)
    }

    pub fn ensure_download_dir_in_path() -> AppResult<PathBuf> {
        let dir = Self::ensure_download_dir()?;
        let current = std::env::var_os("PATH").unwrap_or_default();
        let mut parts = std::env::split_paths(&current).collect::<Vec<_>>();
        if !parts.iter().any(|path| path == &dir) {
            parts.insert(0, dir.clone());
            let joined = std::env::join_paths(parts).map_err(|e| {
                AppError::Internal(format!("failed to update PATH with CLI download dir: {e}"))
            })?;
            unsafe {
                std::env::set_var("PATH", joined);
            }
        }
        Ok(dir)
    }

    pub fn binary_path(language: &str) -> AppResult<PathBuf> {
        let dir = Self::ensure_download_dir_in_path()?;
        let path = dir.join(Self::final_binary_name(language)?);
        if path.exists() {
            return Ok(path);
        }

        which::which(format!("casbin-{language}-cli")).map_err(|_| {
            AppError::NotFound(format!(
                "executable file {} not found in {} or PATH",
                Self::final_binary_name(language).unwrap_or_default(),
                dir.display()
            ))
        })
    }

    pub async fn refresh_all() -> AppResult<CliRefreshReport> {
        let dir = Self::ensure_download_dir_in_path()?;
        let mut entries = Vec::new();

        for language in ["go", "java", "rust", "python", "dotnet"] {
            let entry = match Self::refresh_language(language).await {
                Ok(entry) => entry,
                Err(err) => CliRefreshEntry {
                    language: language.to_string(),
                    version: None,
                    path: None,
                    downloaded: false,
                    success: false,
                    message: err.to_string(),
                },
            };
            entries.push(entry);
        }

        Ok(CliRefreshReport {
            download_dir: dir.display().to_string(),
            entries,
        })
    }

    async fn refresh_language(language: &str) -> AppResult<CliRefreshEntry> {
        let release = Self::fetch_release_info(language).await?;
        let asset = Self::select_asset(language, &release)?;
        let bytes = Self::download_asset(&asset.browser_download_url).await?;
        let path = Self::persist_asset(language, &asset.name, &bytes)?;
        let message = format!("downloaded {} {}", language, release.tag_name);
        Ok(CliRefreshEntry {
            language: language.to_string(),
            version: Some(release.tag_name),
            path: Some(path.display().to_string()),
            downloaded: true,
            success: true,
            message,
        })
    }

    async fn fetch_release_info(language: &str) -> AppResult<ReleaseInfo> {
        let url = match language {
            "go" => GO_RELEASE_API,
            "java" => JAVA_RELEASE_API,
            "rust" => RUST_RELEASE_API,
            "python" => PYTHON_RELEASE_API,
            "dotnet" => DOTNET_RELEASE_API,
            _ => {
                return Err(AppError::Validation(format!(
                    "unsupported CLI language: {language}"
                )));
            }
        };

        let response = Self::http_client().get(url).send().await.map_err(|e| {
            AppError::Internal(format!("failed to fetch {language} release info: {e}"))
        })?;
        let response = response.error_for_status().map_err(|e| {
            AppError::Internal(format!("failed to fetch {language} release info: {e}"))
        })?;

        response.json::<ReleaseInfo>().await.map_err(|e| {
            AppError::Internal(format!(
                "failed to decode {language} release response from GitHub: {e}"
            ))
        })
    }

    async fn download_asset(url: &str) -> AppResult<Vec<u8>> {
        let response = Self::http_client()
            .get(url)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("failed to download CLI asset: {e}")))?;
        let response = response
            .error_for_status()
            .map_err(|e| AppError::Internal(format!("failed to download CLI asset: {e}")))?;
        response
            .bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|e| AppError::Internal(format!("failed to read downloaded CLI asset: {e}")))
    }

    fn persist_asset(language: &str, asset_name: &str, bytes: &[u8]) -> AppResult<PathBuf> {
        let dir = Self::ensure_download_dir_in_path()?;
        let final_path = dir.join(Self::final_binary_name(language)?);

        match language {
            "go" => Self::extract_go_archive(bytes, &final_path)?,
            "java" => {
                fs::write(dir.join("casbin-java-cli.jar"), bytes).map_err(|e| {
                    AppError::Internal(format!("failed to save Java CLI asset {asset_name}: {e}"))
                })?;
                Self::create_java_wrapper(&dir)?;
            }
            _ => {
                fs::write(&final_path, bytes).map_err(|e| {
                    AppError::Internal(format!(
                        "failed to save {} CLI asset {}: {}",
                        language, asset_name, e
                    ))
                })?;
                Self::set_executable_if_needed(&final_path)?;
            }
        }

        Ok(final_path)
    }

    fn create_java_wrapper(dir: &Path) -> AppResult<()> {
        #[cfg(target_os = "windows")]
        let (wrapper_name, wrapper_body) = (
            "casbin-java-cli.cmd",
            format!(
                "@echo off\r\njava -jar \"{}\" %*\r\n",
                dir.join("casbin-java-cli.jar").display()
            ),
        );

        #[cfg(not(target_os = "windows"))]
        let (wrapper_name, wrapper_body) = (
            "casbin-java-cli",
            format!(
                "#!/bin/sh\njava -jar \"{}\" \"$@\"\n",
                dir.join("casbin-java-cli.jar").display()
            ),
        );

        let wrapper_path = dir.join(wrapper_name);
        fs::write(&wrapper_path, wrapper_body)
            .map_err(|e| AppError::Internal(format!("failed to create Java CLI wrapper: {e}")))?;
        Self::set_executable_if_needed(&wrapper_path)?;
        Ok(())
    }

    fn extract_go_archive(bytes: &[u8], final_path: &Path) -> AppResult<()> {
        if cfg!(target_os = "windows") {
            let cursor = Cursor::new(bytes);
            let mut archive = zip::ZipArchive::new(cursor)
                .map_err(|e| AppError::Internal(format!("failed to open Go CLI zip: {e}")))?;
            let exec_name = final_path
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| AppError::Internal("invalid Go CLI output path".to_string()))?;

            for index in 0..archive.len() {
                let mut file = archive.by_index(index).map_err(|e| {
                    AppError::Internal(format!("failed to read Go CLI zip entry: {e}"))
                })?;
                let Some(name) = Path::new(file.name()).file_name().and_then(|v| v.to_str()) else {
                    continue;
                };
                if name != exec_name {
                    continue;
                }

                let mut out = fs::File::create(final_path).map_err(|e| {
                    AppError::Internal(format!("failed to create Go CLI target: {e}"))
                })?;
                std::io::copy(&mut file, &mut out).map_err(|e| {
                    AppError::Internal(format!("failed to extract Go CLI executable: {e}"))
                })?;
                return Ok(());
            }

            return Err(AppError::NotFound(
                "casbin-go-cli executable not found in downloaded archive".to_string(),
            ));
        }

        let gzip = flate2::read::GzDecoder::new(Cursor::new(bytes));
        let mut archive = tar::Archive::new(gzip);
        let exec_name = final_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| AppError::Internal("invalid Go CLI output path".to_string()))?;

        let entries = archive
            .entries()
            .map_err(|e| AppError::Internal(format!("failed to read Go CLI tar entries: {e}")))?;
        for entry in entries {
            let mut entry = entry
                .map_err(|e| AppError::Internal(format!("failed to read Go CLI tar entry: {e}")))?;
            let path = entry.path().map_err(|e| {
                AppError::Internal(format!("failed to inspect Go CLI tar entry: {e}"))
            })?;
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if name != exec_name {
                continue;
            }

            let mut out = fs::File::create(final_path)
                .map_err(|e| AppError::Internal(format!("failed to create Go CLI target: {e}")))?;
            std::io::copy(&mut entry, &mut out).map_err(|e| {
                AppError::Internal(format!("failed to extract Go CLI executable: {e}"))
            })?;
            Self::set_executable_if_needed(final_path)?;
            return Ok(());
        }

        Err(AppError::NotFound(
            "casbin-go-cli executable not found in downloaded archive".to_string(),
        ))
    }

    fn set_executable_if_needed(path: &Path) -> AppResult<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = fs::metadata(path)
                .map_err(|e| AppError::Internal(format!("failed to inspect CLI file: {e}")))?
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions)
                .map_err(|e| AppError::Internal(format!("failed to make CLI executable: {e}")))?;
        }

        #[cfg(not(unix))]
        {
            let _ = path;
        }

        Ok(())
    }

    fn select_asset<'a>(language: &str, release: &'a ReleaseInfo) -> AppResult<&'a ReleaseAsset> {
        let target_name = Self::asset_name(language)?;
        release
            .assets
            .iter()
            .find(|asset| asset.name == target_name)
            .ok_or_else(|| {
                AppError::NotFound(format!(
                    "no suitable {} CLI asset found for current platform; expected {}",
                    language, target_name
                ))
            })
    }

    fn asset_name(language: &str) -> AppResult<String> {
        let (go_arch, rust_arch) = match std::env::consts::ARCH {
            "x86_64" => ("x86_64", "x86_64"),
            "amd64" => ("x86_64", "x86_64"),
            "aarch64" => ("arm64", "aarch64"),
            "arm64" => ("arm64", "aarch64"),
            other => (other, other),
        };

        let name = match (language, std::env::consts::OS) {
            ("go", "windows") => format!("casbin-go-cli_Windows_{go_arch}.zip"),
            ("go", "macos") => format!("casbin-go-cli_Darwin_{go_arch}.tar.gz"),
            ("go", "linux") => format!("casbin-go-cli_Linux_{go_arch}.tar.gz"),
            ("java", _) => "casbin-java-cli.jar".to_string(),
            ("rust", "windows") => format!("casbin-rust-cli-{rust_arch}-pc-windows-gnu"),
            ("rust", "macos") => format!("casbin-rust-cli-{rust_arch}-apple-darwin"),
            ("rust", "linux") => format!("casbin-rust-cli-{rust_arch}-unknown-linux-gnu"),
            ("python", "windows") => format!("casbin-python-cli-windows-{go_arch}.exe"),
            ("python", "macos") => format!("casbin-python-cli-darwin-{go_arch}"),
            ("python", "linux") => format!("casbin-python-cli-linux-{go_arch}"),
            ("dotnet", "windows") => format!("casbin-dotnet-cli-windows-{go_arch}.exe"),
            ("dotnet", "macos") => format!("casbin-dotnet-cli-darwin-{go_arch}"),
            ("dotnet", "linux") => format!("casbin-dotnet-cli-linux-{go_arch}"),
            _ => {
                return Err(AppError::Validation(format!(
                    "unsupported CLI language/platform combination: {language}/{}",
                    std::env::consts::OS
                )));
            }
        };

        Ok(name)
    }

    fn final_binary_name(language: &str) -> AppResult<&'static str> {
        match (language, std::env::consts::OS) {
            ("go", "windows") => Ok("casbin-go-cli.exe"),
            ("go", _) => Ok("casbin-go-cli"),
            ("java", "windows") => Ok("casbin-java-cli.cmd"),
            ("java", _) => Ok("casbin-java-cli"),
            ("rust", "windows") => Ok("casbin-rust-cli.exe"),
            ("rust", _) => Ok("casbin-rust-cli"),
            ("python", "windows") => Ok("casbin-python-cli.exe"),
            ("python", _) => Ok("casbin-python-cli"),
            ("dotnet", "windows") => Ok("casbin-dotnet-cli.exe"),
            ("dotnet", _) => Ok("casbin-dotnet-cli"),
            _ => Err(AppError::Validation(format!(
                "unsupported CLI language: {language}"
            ))),
        }
    }

    fn http_client() -> reqwest::Client {
        let mut headers = HeaderMap::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static("casdog-cli-downloader"),
        );
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github+json"),
        );
        if let Ok(token) = std::env::var("GITHUB_TOKEN") {
            if !token.is_empty() {
                let value = format!("Bearer {token}");
                if let Ok(header) = HeaderValue::from_str(&value) {
                    headers.insert(AUTHORIZATION, header);
                }
            }
        }

        reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    }
}
