use std::io::{Read, Write};

use base64::Engine as _;
use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use crate::models::{Application, Provider, User};

pub struct SamlService;

#[derive(Debug, Serialize, Deserialize)]
pub struct SamlMetadata {
    pub entity_id: String,
    pub sso_url: String,
    pub slo_url: Option<String>,
    pub certificate: String,
    pub name_id_format: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SamlLoginRequest {
    pub auth_url: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub form_html: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SamlRequestInfo {
    pub issuer: String,
    pub destination: Option<String>,
    pub assertion_consumer_service_url: Option<String>,
    pub request_id: Option<String>,
    pub protocol_binding: Option<String>,
}

impl SamlService {
    pub fn generate_idp_metadata(
        entity_id: &str,
        sso_url: &str,
        slo_url: Option<&str>,
        certificate_pem: &str,
        enable_post_binding: bool,
    ) -> AppResult<String> {
        let cert_base64 = Self::normalize_certificate(certificate_pem);
        let binding = if enable_post_binding {
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        } else {
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        };

        let slo_elem = slo_url
            .map(|url| {
                format!(
                    r#"<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{}" />"#,
                    Self::xml_escape(url)
                )
            })
            .unwrap_or_default();

        Ok(format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>{cert_base64}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:Attribute xmlns="urn:oasis:names:tc:SAML:2.0:assertion" Name="Email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="E-Mail" />
    <md:Attribute xmlns="urn:oasis:names:tc:SAML:2.0:assertion" Name="DisplayName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="displayName" />
    <md:Attribute xmlns="urn:oasis:names:tc:SAML:2.0:assertion" Name="Name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Name" />
    {slo_elem}
    <md:SingleSignOnService Binding="{binding}" Location="{sso_url}" />
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#,
            entity_id = Self::xml_escape(entity_id),
            cert_base64 = cert_base64,
            slo_elem = slo_elem,
            binding = binding,
            sso_url = Self::xml_escape(sso_url),
        ))
    }

    pub fn build_authn_request(
        request_issuer: &str,
        acs_url: &str,
        destination: &str,
        relay_state: Option<&str>,
        use_post_binding: bool,
    ) -> AppResult<SamlLoginRequest> {
        let request_id = format!("_{}", uuid::Uuid::new_v4());
        let issue_instant = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let protocol_binding = if use_post_binding {
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        } else {
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        };
        let xml = format!(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{request_id}" Version="2.0" IssueInstant="{issue_instant}" Destination="{destination}" ProtocolBinding="{protocol_binding}" AssertionConsumerServiceURL="{acs_url}">
  <saml:Issuer>{issuer}</saml:Issuer>
</samlp:AuthnRequest>"#,
            request_id = request_id,
            issue_instant = issue_instant,
            destination = Self::xml_escape(destination),
            protocol_binding = protocol_binding,
            acs_url = Self::xml_escape(acs_url),
            issuer = Self::xml_escape(request_issuer),
        );

        let encoded_request = if use_post_binding {
            base64::engine::general_purpose::STANDARD.encode(xml.as_bytes())
        } else {
            Self::encode_redirect_binding(&xml)?
        };

        if use_post_binding {
            let form_html = Self::build_auto_post_form(
                destination,
                &[
                    ("SAMLRequest", encoded_request.as_str()),
                    ("RelayState", relay_state.unwrap_or_default()),
                ],
            );
            return Ok(SamlLoginRequest {
                auth_url: destination.to_string(),
                method: "POST".to_string(),
                form_html: Some(form_html),
            });
        }

        let mut auth_url = format!(
            "{}?SAMLRequest={}",
            destination,
            urlencoding::encode(&encoded_request)
        );
        if let Some(relay_state) = relay_state {
            if !relay_state.is_empty() {
                auth_url.push_str("&RelayState=");
                auth_url.push_str(&urlencoding::encode(relay_state));
            }
        }

        Ok(SamlLoginRequest {
            auth_url,
            method: "GET".to_string(),
            form_html: None,
        })
    }

    pub fn parse_request(saml_request: &str) -> AppResult<SamlRequestInfo> {
        let xml = Self::decode_saml_request(saml_request)?;
        let issuer = Self::extract_tag_text(&xml, "Issuer")
            .ok_or_else(|| AppError::Validation("SAML request missing Issuer".to_string()))?;
        let destination = Self::extract_attribute(&xml, "Destination");
        let acs = Self::extract_attribute(&xml, "AssertionConsumerServiceURL");
        let request_id = Self::extract_attribute(&xml, "ID");
        let protocol_binding = Self::extract_attribute(&xml, "ProtocolBinding");

        Ok(SamlRequestInfo {
            issuer,
            destination,
            assertion_consumer_service_url: acs,
            request_id,
            protocol_binding,
        })
    }

    pub fn build_application_response(
        application: &Application,
        user: &User,
        saml_request: &str,
        issuer: &str,
    ) -> AppResult<(String, String, String)> {
        let request = Self::parse_request(saml_request)?;
        let destination = application
            .saml_reply_url
            .clone()
            .or(request.assertion_consumer_service_url.clone())
            .or(request.destination.clone())
            .ok_or_else(|| {
                AppError::Validation(
                    "SAML request missing AssertionConsumerServiceURL and application has no saml_reply_url"
                        .to_string(),
                )
            })?;

        if !application.redirect_uris.is_empty()
            && !Self::redirect_uri_allowed(&application.redirect_uris, &request.issuer)
        {
            return Err(AppError::Authentication(format!(
                "Issuer URI '{}' is not in the application's redirect URIs",
                request.issuer
            )));
        }

        let name_id = user
            .email
            .clone()
            .unwrap_or_else(|| format!("{}/{}", user.owner, user.name));
        let session_index = request
            .request_id
            .clone()
            .unwrap_or_else(|| format!("_{}", uuid::Uuid::new_v4()));
        let attributes = vec![
            ("Name", user.name.as_str()),
            ("DisplayName", user.display_name.as_str()),
            ("Email", user.email.as_deref().unwrap_or("")),
            ("Phone", user.phone.as_deref().unwrap_or("")),
        ];
        let response_xml = Self::build_saml_response(
            issuer,
            &destination,
            &name_id,
            &session_index,
            &attributes,
            request.request_id.as_deref(),
            Some(&request.issuer),
        )?;
        let response = base64::engine::general_purpose::STANDARD.encode(response_xml.as_bytes());
        let method = if request.protocol_binding.as_deref()
            == Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
            || application.saml_reply_url.is_some()
        {
            "POST"
        } else {
            "GET"
        };

        Ok((response, destination, method.to_string()))
    }

    pub fn build_saml_response(
        issuer: &str,
        destination: &str,
        name_id: &str,
        session_index: &str,
        attributes: &[(&str, &str)],
        in_response_to: Option<&str>,
        audience: Option<&str>,
    ) -> AppResult<String> {
        let now = chrono::Utc::now();
        let now_str = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let not_after =
            (now + chrono::Duration::minutes(5)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let response_id = format!("_{}", uuid::Uuid::new_v4());
        let assertion_id = format!("_{}", uuid::Uuid::new_v4());
        let attrs: String = attributes
            .iter()
            .filter(|(_, value)| !value.is_empty())
            .map(|(name, value)| {
                format!(
                    r#"<saml:Attribute Name="{name}"><saml:AttributeValue>{value}</saml:AttributeValue></saml:Attribute>"#,
                    name = Self::xml_escape(name),
                    value = Self::xml_escape(value)
                )
            })
            .collect::<Vec<_>>()
            .join("\n      ");
        let in_response_to_attr = in_response_to
            .map(|value| format!(r#" InResponseTo="{}""#, Self::xml_escape(value)))
            .unwrap_or_default();
        let audience_block = audience
            .map(|value| {
                format!(
                    r#"<saml:AudienceRestriction><saml:Audience>{}</saml:Audience></saml:AudienceRestriction>"#,
                    Self::xml_escape(value)
                )
            })
            .unwrap_or_default();

        Ok(format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{response_id}" Version="2.0" IssueInstant="{now}" Destination="{destination}"{in_response_to_attr}>
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="{now}">
    <saml:Issuer>{issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="{not_after}" Recipient="{destination}"{in_response_to_attr}/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{now}" NotOnOrAfter="{not_after}">
      {audience_block}
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{now}" SessionIndex="{session_index}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      {attrs}
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"#,
            response_id = response_id,
            assertion_id = assertion_id,
            now = now_str,
            destination = Self::xml_escape(destination),
            in_response_to_attr = in_response_to_attr,
            issuer = Self::xml_escape(issuer),
            name_id = Self::xml_escape(name_id),
            not_after = not_after,
            audience_block = audience_block,
            session_index = Self::xml_escape(session_index),
            attrs = attrs
        ))
    }

    pub fn provider_sso_url(provider: &Provider) -> Option<String> {
        provider.endpoint.clone().or_else(|| {
            provider
                .metadata
                .as_deref()
                .and_then(Self::extract_sso_from_metadata)
        })
    }

    pub fn redirect_uri_allowed(allowed: &str, candidate: &str) -> bool {
        let candidate = candidate.trim();
        allowed
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .any(|value| value == candidate)
    }

    pub fn build_auto_post_form(action: &str, fields: &[(&str, &str)]) -> String {
        let inputs = fields
            .iter()
            .filter(|(_, value)| !value.is_empty())
            .map(|(name, value)| {
                format!(
                    r#"<input type="hidden" name="{}" value="{}" />"#,
                    Self::xml_escape(name),
                    Self::xml_escape(value)
                )
            })
            .collect::<Vec<_>>()
            .join("\n    ");

        format!(
            r#"<!doctype html>
<html>
  <body onload="document.forms[0].submit()">
    <form method="post" action="{action}">
    {inputs}
    <noscript><button type="submit">Continue</button></noscript>
    </form>
  </body>
</html>"#,
            action = Self::xml_escape(action),
            inputs = inputs
        )
    }

    pub fn decode_relay_state_target(relay_state: &str) -> Option<String> {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(relay_state)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())?;

        if decoded.starts_with("http://") || decoded.starts_with("https://") {
            return Some(decoded);
        }

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&decoded) {
            for key in ["redirect", "redirectUrl", "callback", "url", "target"] {
                if let Some(value) = json.get(key).and_then(|value| value.as_str()) {
                    return Some(value.to_string());
                }
            }
        }

        for piece in decoded.split('&') {
            if piece.starts_with("http://") || piece.starts_with("https://") {
                return Some(piece.to_string());
            }
            if let Some((key, value)) = piece.split_once('=') {
                if matches!(
                    key,
                    "redirect" | "redirectUrl" | "callback" | "url" | "target"
                ) {
                    return Some(value.to_string());
                }
            }
        }

        None
    }

    fn encode_redirect_binding(xml: &str) -> AppResult<String> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
        encoder
            .write_all(xml.as_bytes())
            .map_err(|e| AppError::Internal(format!("failed to deflate SAML request: {e}")))?;
        let bytes = encoder.finish().map_err(|e| {
            AppError::Internal(format!("failed to finalize SAML request compression: {e}"))
        })?;
        Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    fn decode_saml_request(saml_request: &str) -> AppResult<String> {
        let normalized = saml_request.replace(' ', "+");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(normalized.as_bytes())
            .map_err(|e| AppError::Validation(format!("failed to decode SAML request: {e}")))?;

        if bytes.starts_with(b"<") {
            return String::from_utf8(bytes)
                .map_err(|e| AppError::Validation(format!("invalid SAML request XML: {e}")));
        }

        let mut decoder = DeflateDecoder::new(bytes.as_slice());
        let mut xml = String::new();
        match decoder.read_to_string(&mut xml) {
            Ok(_) if !xml.is_empty() => Ok(xml),
            _ => String::from_utf8(bytes)
                .map_err(|e| AppError::Validation(format!("invalid SAML request payload: {e}"))),
        }
    }

    fn extract_attribute(xml: &str, attribute: &str) -> Option<String> {
        let pattern = format!(r#"{attribute}="([^"]+)""#);
        let regex = Regex::new(&pattern).ok()?;
        regex
            .captures(xml)
            .and_then(|captures| captures.get(1))
            .map(|value| Self::xml_unescape(value.as_str()))
    }

    fn extract_tag_text(xml: &str, local_name: &str) -> Option<String> {
        let pattern = format!(r#"<(?:\w+:)?{local_name}[^>]*>(.*?)</(?:\w+:)?{local_name}>"#);
        let regex = Regex::new(&pattern).ok()?;
        regex
            .captures(xml)
            .and_then(|captures| captures.get(1))
            .map(|value| Self::xml_unescape(value.as_str()))
    }

    fn extract_sso_from_metadata(metadata: &str) -> Option<String> {
        let regex =
            Regex::new(r#"<(?:\w+:)?SingleSignOnService[^>]*Location="([^"]+)"[^>]*/?>"#).ok()?;
        regex
            .captures(metadata)
            .and_then(|captures| captures.get(1))
            .map(|value| Self::xml_unescape(value.as_str()))
    }

    fn normalize_certificate(certificate_pem: &str) -> String {
        certificate_pem
            .replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace('\n', "")
            .replace('\r', "")
            .trim()
            .to_string()
    }

    fn xml_escape(value: &str) -> String {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }

    fn xml_unescape(value: &str) -> String {
        value
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&gt;", ">")
            .replace("&lt;", "<")
            .replace("&amp;", "&")
    }
}
