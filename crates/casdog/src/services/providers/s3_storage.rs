use async_trait::async_trait;
use hmac::{Hmac, Mac};
use reqwest::{Client, Method, StatusCode, Url};
use sha2::{Digest, Sha256};

use crate::error::{AppError, AppResult};
use crate::services::providers::storage_provider::{
    ObjectPreview, StorageProvider, validate_object_key,
};

/// S3 and path-style S3-compatible storage, authenticated with AWS SigV4.
pub struct S3StorageProvider {
    client: Client,
    access_key: String,
    secret_key: String,
    region: String,
    bucket: String,
    endpoint: String,
}

fn invalid(message: &str) -> AppError {
    AppError::Validation(message.into())
}

// AWS URI encoding operates on UTF-8 bytes and preserves '/' only in the key.
fn encode_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            use std::fmt::Write;
            write!(encoded, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    encoded
}

fn hash(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

impl S3StorageProvider {
    pub fn new(
        access_key: String,
        secret_key: String,
        region: String,
        bucket: String,
        endpoint: String,
    ) -> Self {
        Self {
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(8))
                .build()
                .expect("static S3 client configuration"),
            access_key,
            secret_key,
            region: if region.is_empty() {
                "us-east-1".into()
            } else {
                region
            },
            bucket,
            endpoint,
        }
    }

    /// Use the caller's checked, DNS-pinned client. Every normal API constructs
    /// this client before allowing tenant-controlled remote storage access.
    pub fn with_client(mut self, client: Client) -> Self {
        self.client = client;
        self
    }

    pub fn base_url(&self) -> AppResult<Url> {
        if self.bucket.is_empty()
            || !self
                .bucket
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
            || matches!(self.bucket.as_str(), "." | "..")
            || !self
                .region
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(invalid("Invalid S3 bucket or region"));
        }
        let base = if self.endpoint.is_empty() {
            format!("https://{}.s3.{}.amazonaws.com", self.bucket, self.region)
        } else {
            format!(
                "{}/{}",
                self.endpoint.trim_end_matches('/'),
                encode_segment(&self.bucket)
            )
        };
        let url = Url::parse(&base).map_err(|_| invalid("Invalid storage endpoint"))?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid(
                "Storage endpoint must be HTTP(S) without credentials, query or fragment",
            ));
        }
        Ok(url)
    }

    fn object_url(&self, key: &str) -> AppResult<Url> {
        validate_object_key(key)?;
        let key = key
            .split('/')
            .map(encode_segment)
            .collect::<Vec<_>>()
            .join("/");
        Url::parse(&format!(
            "{}/{key}",
            self.base_url()?.as_str().trim_end_matches('/')
        ))
        .map_err(|_| invalid("Invalid storage object URL"))
    }

    fn authorization(
        &self,
        method: &Method,
        url: &Url,
        content_hash: &str,
        date: &str,
        range: Option<&str>,
    ) -> AppResult<String> {
        if self.access_key.is_empty() || self.secret_key.is_empty() {
            return Err(AppError::Config(
                "Both S3 access key and secret key are required".into(),
            ));
        }
        // Endpoints have no userinfo. This retains brackets and non-default
        // ports exactly as reqwest transmits the Host header.
        let host = url
            .as_str()
            .split_once("://")
            .and_then(|(_, tail)| tail.split('/').next())
            .ok_or_else(|| invalid("Invalid storage request host"))?;
        let mut headers = format!("host:{host}\n");
        let mut signed = "host".to_string();
        if let Some(range) = range {
            headers.push_str(&format!("range:{range}\n"));
            signed.push_str(";range");
        }
        headers.push_str(&format!(
            "x-amz-content-sha256:{content_hash}\nx-amz-date:{date}\n"
        ));
        signed.push_str(";x-amz-content-sha256;x-amz-date");
        let canonical = format!(
            "{}\n{}\n\n{}\n{}\n{}",
            method.as_str(),
            url.path(),
            headers,
            signed,
            content_hash
        );
        let day = &date[..8];
        let scope = format!("{day}/{}/s3/aws4_request", self.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{date}\n{scope}\n{}",
            hash(canonical.as_bytes())
        );
        let day_key = hmac(
            format!("AWS4{}", self.secret_key).as_bytes(),
            day.as_bytes(),
        );
        let region_key = hmac(&day_key, self.region.as_bytes());
        let service_key = hmac(&region_key, b"s3");
        let signing_key = hmac(&service_key, b"aws4_request");
        let signature = hex::encode(hmac(&signing_key, to_sign.as_bytes()));
        Ok(format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope},SignedHeaders={signed},Signature={signature}",
            self.access_key
        ))
    }

    fn request(
        &self,
        method: Method,
        url: &Url,
        body: &[u8],
        range: Option<&str>,
    ) -> AppResult<reqwest::RequestBuilder> {
        let date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let content_hash = hash(body);
        let mut request = self
            .client
            .request(method.clone(), url.clone())
            .header("x-amz-content-sha256", &content_hash)
            .header("x-amz-date", &date)
            .header("Accept-Encoding", "identity");
        if let Some(range) = range {
            request = request.header("Range", range);
        }
        if !self.access_key.is_empty() || !self.secret_key.is_empty() {
            request = request.header(
                "Authorization",
                self.authorization(&method, url, &content_hash, &date, range)?,
            );
        }
        Ok(request)
    }

    fn check_response(response: &reqwest::Response, operation: &str) -> AppResult<()> {
        if response.status() == StatusCode::NOT_FOUND {
            return Err(AppError::NotFound("Storage object not found".into()));
        }
        if !response.status().is_success() {
            // Do not buffer an untrusted error body or expose provider secrets.
            return Err(AppError::Internal(format!(
                "S3 {operation} returned HTTP {}",
                response.status().as_u16()
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl StorageProvider for S3StorageProvider {
    async fn upload(&self, key: &str, data: &[u8], content_type: &str) -> AppResult<String> {
        let url = self.object_url(key)?;
        let response = self
            .request(Method::PUT, &url, data, None)?
            .header("Content-Type", content_type)
            .body(data.to_vec())
            .send()
            .await
            .map_err(|_| AppError::Internal("S3 upload failed".into()))?;
        Self::check_response(&response, "upload")?;
        Ok(url.into())
    }

    async fn download(&self, key: &str) -> AppResult<Vec<u8>> {
        let url = self.object_url(key)?;
        let response = self
            .request(Method::GET, &url, &[], None)?
            .send()
            .await
            .map_err(|_| AppError::Internal("S3 download failed".into()))?;
        Self::check_response(&response, "download")?;
        response
            .bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|_| AppError::Internal("Cannot read S3 object".into()))
    }

    async fn preview(&self, key: &str, limit: usize) -> AppResult<ObjectPreview> {
        if limit == 0 || limit == usize::MAX {
            return Err(invalid("Invalid storage preview limit"));
        }
        let url = self.object_url(key)?;
        // Fetch one sentinel byte to distinguish an exact-limit object from a
        // larger one, even if the server ignores Range or omits its length.
        let range = format!("bytes=0-{limit}");
        let mut response = self
            .request(Method::GET, &url, &[], Some(&range))?
            .send()
            .await
            .map_err(|_| AppError::Internal("S3 preview failed".into()))?;
        if response.status() == StatusCode::RANGE_NOT_SATISFIABLE
            && response
                .headers()
                .get("Content-Range")
                .and_then(|v| v.to_str().ok())
                == Some("bytes */0")
        {
            return Ok(ObjectPreview {
                bytes: Vec::new(),
                size: Some(0),
                truncated: false,
            });
        }
        Self::check_response(&response, "preview")?;
        if response
            .headers()
            .get("Content-Encoding")
            .is_some_and(|value| value != "identity")
        {
            return Err(invalid("Encoded S3 preview response is unsupported"));
        }
        let partial = response.status() == StatusCode::PARTIAL_CONTENT;
        let (mut size, range_size) = if partial {
            let header = response
                .headers()
                .get("Content-Range")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("bytes 0-"))
                .ok_or_else(|| invalid("Invalid S3 preview Content-Range"))?;
            let (end, total) = header
                .split_once('/')
                .ok_or_else(|| invalid("Invalid S3 preview Content-Range"))?;
            let end: u64 = end
                .parse()
                .map_err(|_| invalid("Invalid S3 preview range end"))?;
            let total = if total == "*" {
                None
            } else {
                Some(
                    total
                        .parse::<u64>()
                        .map_err(|_| invalid("Invalid S3 preview object size"))?,
                )
            };
            if end > limit as u64 || total.is_some_and(|total| total <= end) {
                return Err(invalid("Invalid S3 preview range bounds"));
            }
            (total, Some(end + 1))
        } else if response.status() == StatusCode::OK {
            (response.content_length(), None)
        } else {
            return Err(invalid("Unexpected S3 preview status"));
        };
        let mut bytes = Vec::new();
        let mut complete = false;
        while bytes.len() <= limit {
            let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| AppError::Internal("S3 preview response interrupted".into()))?
            else {
                complete = true;
                break;
            };
            let remaining = limit + 1 - bytes.len();
            bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        }
        if complete && range_size.is_some_and(|expected| bytes.len() as u64 != expected) {
            return Err(invalid("Incomplete S3 preview range"));
        }
        if complete && !partial && size.is_none() {
            size = Some(bytes.len() as u64);
        }
        let truncated = bytes.len() > limit
            || size.is_some_and(|size| size > bytes.len() as u64)
            || (partial && size.is_none());
        bytes.truncate(limit);
        Ok(ObjectPreview {
            bytes,
            size,
            truncated,
        })
    }

    async fn delete(&self, key: &str) -> AppResult<()> {
        let url = self.object_url(key)?;
        let response = self
            .request(Method::DELETE, &url, &[], None)?
            .send()
            .await
            .map_err(|_| AppError::Internal("S3 delete failed".into()))?;
        Self::check_response(&response, "delete")
    }

    async fn get_url(&self, key: &str) -> AppResult<String> {
        Ok(self.object_url(key)?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_matches_aws_published_get_object_example() {
        // https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html
        let provider = S3StorageProvider::new(
            "AKIAIOSFODNN7EXAMPLE".into(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            "us-east-1".into(),
            "examplebucket".into(),
            String::new(),
        );
        let signature = provider
            .authorization(
                &Method::GET,
                &Url::parse("https://examplebucket.s3.amazonaws.com/test.txt").unwrap(),
                &hash(&[]),
                "20130524T000000Z",
                Some("bytes=0-9"),
            )
            .unwrap();
        assert_eq!(
            signature,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }
}
