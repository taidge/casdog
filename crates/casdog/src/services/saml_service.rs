use crate::error::{AppError, AppResult};
use serde::{Deserialize, Serialize};

pub struct SamlService;

#[derive(Debug, Serialize, Deserialize)]
pub struct SamlMetadata {
    pub entity_id: String,
    pub sso_url: String,
    pub slo_url: Option<String>,
    pub certificate: String,
    pub name_id_format: String,
}

impl SamlService {
    /// Generate IdP metadata XML
    pub fn generate_idp_metadata(
        entity_id: &str,
        sso_url: &str,
        slo_url: Option<&str>,
        certificate_pem: &str,
    ) -> AppResult<String> {
        let cert_base64 = certificate_pem
            .replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace('\n', "")
            .replace('\r', "");

        let slo_elem = slo_url.map(|url| format!(
            r#"<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{}" />"#,
            url
        )).unwrap_or_default();

        let metadata = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
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
    {slo_elem}
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{sso_url}" />
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{sso_url}" />
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#);

        Ok(metadata)
    }

    /// Build a SAML Response / Assertion (simplified)
    pub fn build_saml_response(
        issuer: &str,
        destination: &str,
        name_id: &str,
        session_index: &str,
        attributes: &[(&str, &str)],
    ) -> AppResult<String> {
        let now = chrono::Utc::now();
        let not_after = now + chrono::Duration::minutes(5);
        let id = format!("_{}", uuid::Uuid::new_v4());
        let assertion_id = format!("_{}", uuid::Uuid::new_v4());

        let attrs: String = attributes.iter().map(|(name, value)| {
            format!(r#"<saml:Attribute Name="{name}"><saml:AttributeValue>{value}</saml:AttributeValue></saml:Attribute>"#)
        }).collect::<Vec<_>>().join("\n        ");

        let response = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{id}" Version="2.0" IssueInstant="{now}" Destination="{destination}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="{now}">
    <saml:Issuer>{issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="{not_after}" Recipient="{destination}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{now}" NotOnOrAfter="{not_after}"/>
    <saml:AuthnStatement AuthnInstant="{now}" SessionIndex="{session_index}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      {attrs}
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"#);

        Ok(response)
    }
}
