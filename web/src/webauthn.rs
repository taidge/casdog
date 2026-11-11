use serde_json::Value;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(inline_js = r#"
let activeRequest;
export function cancelPasskeyRequest() {
    activeRequest?.abort();
    activeRequest = undefined;
}
function requestController() {
    cancelPasskeyRequest();
    const controller = new AbortController();
    activeRequest = controller;
    return controller;
}
function decodeBase64Url(value) {
    const encoded = value.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(encoded + "=".repeat((4 - encoded.length % 4) % 4));
    return Uint8Array.from(binary, character => character.charCodeAt(0));
}
function encodeBase64Url(buffer) {
    let binary = "";
    for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export async function createPasskey(optionsJson) {
    if (!window.isSecureContext || !window.PublicKeyCredential || !navigator.credentials?.create) {
        throw new Error("Passkey registration requires HTTPS or localhost and a browser with WebAuthn support.");
    }
    const options = JSON.parse(optionsJson);
    const source = options.publicKey ?? options;
    let publicKey;
    if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function") {
        publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(source);
    } else {
        publicKey = {
            ...source,
            challenge: decodeBase64Url(source.challenge),
            user: {...source.user, id: decodeBase64Url(source.user.id)},
            excludeCredentials: (source.excludeCredentials ?? []).map(credential => ({
                ...credential, id: decodeBase64Url(credential.id)
            }))
        };
    }
    publicKey.timeout = Math.min(Number(publicKey.timeout) || 60000, 60000);
    const controller = requestController();
    try {
        const credential = await navigator.credentials.create({publicKey, signal: controller.signal});
        if (!credential) throw new Error("Passkey registration was cancelled.");
        return JSON.stringify({
            id: credential.id,
            rawId: encodeBase64Url(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: encodeBase64Url(credential.response.attestationObject),
                clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
                transports: credential.response.getTransports?.() ?? []
            },
            extensions: credential.getClientExtensionResults()
        });
    } catch (error) {
        if (error?.name === "NotAllowedError" || error?.name === "AbortError") {
            throw new Error("Passkey registration was cancelled or timed out. Try again when ready.");
        }
        if (error?.name === "InvalidStateError") {
            throw new Error("This authenticator is already registered for your account.");
        }
        throw new Error(error?.message || "The authenticator could not create a passkey.");
    } finally {
        if (activeRequest === controller) activeRequest = undefined;
    }
}
export async function getPasskey(optionsJson) {
    if (!window.isSecureContext || !window.PublicKeyCredential || !navigator.credentials?.get) {
        throw new Error("Passkey sign-in requires HTTPS or localhost and a browser with WebAuthn support.");
    }
    const options = JSON.parse(optionsJson);
    const source = options.publicKey ?? options;
    const publicKey = typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function"
        ? PublicKeyCredential.parseRequestOptionsFromJSON(source)
        : {...source, challenge: decodeBase64Url(source.challenge), allowCredentials: (source.allowCredentials ?? []).map(credential => ({...credential, id: decodeBase64Url(credential.id)}))};
    publicKey.timeout = Math.min(Number(publicKey.timeout) || 60000, 60000);
    const controller = requestController();
    try {
        const credential = await navigator.credentials.get({publicKey, signal: controller.signal});
        if (!credential) throw new Error("Passkey sign-in was cancelled.");
        return JSON.stringify({
            id: credential.id,
            rawId: encodeBase64Url(credential.rawId),
            type: credential.type,
            response: {
                authenticatorData: encodeBase64Url(credential.response.authenticatorData),
                clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
                signature: encodeBase64Url(credential.response.signature),
                userHandle: credential.response.userHandle ? encodeBase64Url(credential.response.userHandle) : null
            },
            extensions: credential.getClientExtensionResults()
        });
    } catch (error) {
        if (error?.name === "NotAllowedError" || error?.name === "AbortError") {
            throw new Error("Passkey sign-in was cancelled or timed out. Try again when ready.");
        }
        throw new Error(error?.message || "The authenticator could not sign in.");
    } finally {
        if (activeRequest === controller) activeRequest = undefined;
    }
}
"#)]
extern "C" {
    #[wasm_bindgen(catch)]
    async fn createPasskey(options_json: &str) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(catch)]
    async fn getPasskey(options_json: &str) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(js_name = cancelPasskeyRequest)]
    fn cancel_js();
}

#[cfg(target_arch = "wasm32")]
pub async fn register(options: Value) -> Result<Value, String> {
    let result = createPasskey(&options.to_string()).await.map_err(|error| {
        js_sys_error(&error).unwrap_or_else(|| "The authenticator could not create a passkey.".into())
    })?;
    let json = result.as_string().ok_or("The authenticator returned an invalid credential.")?;
    serde_json::from_str(&json).map_err(|_| "The authenticator returned an invalid credential.".into())
}

#[cfg(target_arch = "wasm32")]
fn js_sys_error(error: &JsValue) -> Option<String> {
    // JavaScript Error values are exposed by the web-sys DOM exception wrapper.
    error.as_string().or_else(|| {
        let exception: &web_sys::DomException = error.unchecked_ref();
        Some(exception.message()).filter(|message| !message.is_empty())
    })
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn register(_: Value) -> Result<Value, String> {
    Err("Passkey registration requires a browser.".into())
}

#[cfg(target_arch = "wasm32")]
pub async fn authenticate(options: Value) -> Result<Value, String> {
    let result = getPasskey(&options.to_string())
        .await
        .map_err(|error| js_sys_error(&error).unwrap_or_else(|| "The authenticator could not sign in.".into()))?;
    let json = result.as_string().ok_or("The authenticator returned an invalid credential.")?;
    serde_json::from_str(&json).map_err(|_| "The authenticator returned an invalid credential.".into())
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn authenticate(_: Value) -> Result<Value, String> {
    Err("Passkey sign-in requires a browser.".into())
}

pub fn cancel() {
    #[cfg(target_arch = "wasm32")]
    cancel_js();
}

/// Retained by the page scope so navigation dismisses its browser ceremony.
pub struct CancelOnDrop;
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        cancel();
    }
}
