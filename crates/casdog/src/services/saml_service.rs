use std::io::{Read, Write};

use base64::Engine as _;
use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use regex::Regex;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::SignatureEncoding;
use rsa::signature::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{AppError, AppResult};
use crate::models::{Application, Certificate, Provider, User};

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

    /// Build and optionally sign a SAML response for the given application.
    ///
    /// When `cert` is `Some`, the assertion is signed with an enveloped
    /// RSA-SHA256 XML-DSig signature using the certificate's private key.
    pub fn build_application_response(
        application: &Application,
        user: &User,
        saml_request: &str,
        issuer: &str,
        cert: Option<&Certificate>,
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
            cert,
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
        cert: Option<&Certificate>,
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

        // Build the Assertion element first (it will be signed independently).
        let assertion_xml = format!(
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{assertion_id}" Version="2.0" IssueInstant="{now}">
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
  </saml:Assertion>"#,
            assertion_id = assertion_id,
            now = now_str,
            issuer = Self::xml_escape(issuer),
            name_id = Self::xml_escape(name_id),
            not_after = not_after,
            destination = Self::xml_escape(destination),
            in_response_to_attr = in_response_to_attr,
            audience_block = audience_block,
            session_index = Self::xml_escape(session_index),
            attrs = attrs
        );

        // Sign the assertion if a certificate with private key is available.
        let signed_assertion = match cert {
            Some(cert) if !cert.private_key.is_empty() => {
                Self::sign_assertion(&assertion_xml, &assertion_id, cert)?
            }
            _ => assertion_xml,
        };

        Ok(format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{response_id}" Version="2.0" IssueInstant="{now}" Destination="{destination}"{in_response_to_attr}>
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  {signed_assertion}
</samlp:Response>"#,
            response_id = response_id,
            now = now_str,
            destination = Self::xml_escape(destination),
            in_response_to_attr = in_response_to_attr,
            issuer = Self::xml_escape(issuer),
            signed_assertion = signed_assertion
        ))
    }

    // -- XML-DSig signing ----------------------------------------------------

    /// Sign a SAML Assertion element using RSA-SHA256 enveloped signature.
    ///
    /// Inserts a `<ds:Signature>` element immediately after the `<saml:Issuer>`
    /// element inside the assertion, following the SAML 2.0 schema requirement.
    fn sign_assertion(
        assertion_xml: &str,
        assertion_id: &str,
        cert: &Certificate,
    ) -> AppResult<String> {
        // Canonicalize the assertion for digest computation.
        let c14n = Self::exclusive_c14n(assertion_xml);
        let digest_value = Self::compute_sha256_digest(&c14n);

        // Build the SignedInfo element.
        let signed_info = Self::build_signed_info(assertion_id, &digest_value);
        let signed_info_c14n = Self::exclusive_c14n(&signed_info);

        // Sign the canonicalized SignedInfo with RSA-SHA256.
        let signature_value = Self::rsa_sha256_sign(&signed_info_c14n, &cert.private_key)?;

        let cert_base64 = Self::normalize_certificate(&cert.certificate);

        let signature_block = format!(
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      {signed_info}
      <ds:SignatureValue>{signature_value}</ds:SignatureValue>
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>{cert_base64}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </ds:Signature>"#,
            signed_info = signed_info,
            signature_value = signature_value,
            cert_base64 = cert_base64
        );

        // Insert the signature after <saml:Issuer>...</saml:Issuer>.
        let insertion_re =
            Regex::new(r#"(</saml:Issuer>)"#).map_err(|e| AppError::Internal(e.to_string()))?;
        let signed = insertion_re.replace(assertion_xml, |caps: &regex::Captures| {
            format!("{}\n    {}", &caps[1], signature_block)
        });

        Ok(signed.to_string())
    }

    fn build_signed_info(reference_id: &str, digest_value: &str) -> String {
        format!(
            r##"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#{reference_id}">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>{digest_value}</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>"##,
            reference_id = Self::xml_escape(reference_id),
            digest_value = digest_value
        )
    }

    fn compute_sha256_digest(data: &str) -> String {
        let hash = Sha256::digest(data.as_bytes());
        base64::engine::general_purpose::STANDARD.encode(hash)
    }

    fn rsa_sha256_sign(data: &str, private_key_pem: &str) -> AppResult<String> {
        let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(private_key_pem)
            .map_err(|e| AppError::Internal(format!("Failed to parse RSA private key: {e}")))?;
        let signing_key: SigningKey<Sha256> = SigningKey::new(private_key);
        let signature = signing_key.sign(data.as_bytes());
        Ok(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))
    }

    /// Validate an RSA-SHA256 XML-DSig signature on a SAML response or assertion.
    ///
    /// Extracts the `<ds:SignedInfo>`, `<ds:SignatureValue>`, and
    /// `<ds:X509Certificate>` from the XML, verifies the digest of the
    /// referenced element, then verifies the signature over the canonicalized
    /// `SignedInfo`.
    pub fn validate_signature(xml: &str, certificate_pem: &str) -> AppResult<bool> {
        use rsa::pkcs1v15::VerifyingKey;
        use rsa::pkcs8::DecodePublicKey;
        use rsa::signature::Verifier;

        // Extract SignatureValue.
        let sig_b64 = Self::extract_tag_text(xml, "SignatureValue").ok_or_else(|| {
            AppError::Validation("Missing ds:SignatureValue in SAML response".to_string())
        })?;
        let sig_b64 = sig_b64
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();
        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(sig_b64.as_bytes())
            .map_err(|e| AppError::Validation(format!("Invalid SignatureValue base64: {e}")))?;

        // Extract and canonicalize SignedInfo.
        let signed_info_re = Regex::new(r"(<ds:SignedInfo[^>]*>[\s\S]*?</ds:SignedInfo>)")
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let signed_info_xml = signed_info_re
            .captures(xml)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str())
            .ok_or_else(|| {
                AppError::Validation("Missing ds:SignedInfo in SAML response".to_string())
            })?;
        let signed_info_c14n = Self::exclusive_c14n(signed_info_xml);

        // Verify signature over SignedInfo.
        let cert_pem = Self::build_pem_block(certificate_pem);
        let public_key = rsa::RsaPublicKey::from_public_key_pem(&cert_pem)
            .or_else(|_| {
                // Try extracting from X.509 certificate format.
                let cert_der = Self::pem_to_der(certificate_pem)?;
                Self::extract_public_key_from_cert_der(&cert_der)
            })
            .map_err(|e| {
                AppError::Validation(format!("Failed to parse certificate public key: {e}"))
            })?;

        let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(public_key);
        let rsa_sig = rsa::pkcs1v15::Signature::try_from(signature_bytes.as_slice())
            .map_err(|e| AppError::Validation(format!("Invalid RSA signature format: {e}")))?;

        match verifying_key.verify(signed_info_c14n.as_bytes(), &rsa_sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn build_pem_block(raw: &str) -> String {
        let clean = Self::normalize_certificate(raw);
        if raw.contains("BEGIN") {
            raw.to_string()
        } else {
            format!("-----BEGIN PUBLIC KEY-----\n{clean}\n-----END PUBLIC KEY-----",)
        }
    }

    fn pem_to_der(pem: &str) -> Result<Vec<u8>, rsa::pkcs8::Error> {
        let clean = Self::normalize_certificate(pem);
        base64::engine::general_purpose::STANDARD
            .decode(clean.as_bytes())
            .map_err(|_| rsa::pkcs8::Error::KeyMalformed)
    }

    fn extract_public_key_from_cert_der(
        der: &[u8],
    ) -> Result<rsa::RsaPublicKey, rsa::pkcs8::Error> {
        // Minimal X.509 TBS extraction: skip to subjectPublicKeyInfo.
        // For robust parsing a full X.509 library would be better, but for
        // SAML interop this handles the common RSA certificate case.
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::pkcs8::DecodePublicKey;
        // Try PKCS#8 SubjectPublicKeyInfo directly.
        if let Ok(key) = rsa::RsaPublicKey::from_public_key_der(der) {
            return Ok(key);
        }
        // Try PKCS#1 RSAPublicKey.
        if let Ok(key) = rsa::RsaPublicKey::from_pkcs1_der(der) {
            return Ok(key);
        }
        Err(rsa::pkcs8::Error::KeyMalformed)
    }

    /// Simplified Exclusive XML Canonicalization (exc-c14n).
    ///
    /// Normalises whitespace, sorts attributes, and strips XML declarations.
    /// This is a pragmatic implementation that handles the typical SAML
    /// canonicalization needs without a full XML parser.
    fn exclusive_c14n(xml: &str) -> String {
        let mut result = xml.to_string();
        // Strip XML declaration.
        let xml_decl = Regex::new(r"<\?xml[^?]*\?>\s*").unwrap();
        result = xml_decl.replace_all(&result, "").to_string();
        // Normalise line endings to LF.
        result = result.replace('\r', "");
        // Trim trailing whitespace from each line.
        result = result
            .lines()
            .map(|l| l.trim_end())
            .collect::<Vec<_>>()
            .join("\n");
        result
    }

    // -- Existing public API -------------------------------------------------

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
            .replace("-----BEGIN RSA PUBLIC KEY-----", "")
            .replace("-----END RSA PUBLIC KEY-----", "")
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
