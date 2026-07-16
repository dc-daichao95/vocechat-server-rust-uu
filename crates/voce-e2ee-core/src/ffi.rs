//! JSON IPC surface for Flutter FFI / C consumers.
//!
//! ```c
//! char* voce_e2ee_call(const char* method, const char* json_args);
//! void voce_e2ee_free(char* p);
//! ```

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};

use crate::envelope::EnvelopeV2;
use crate::identity::{safety_number, IdentityPublic, IdentitySecret};
use crate::x3dh::{x3dh_initiator, x3dh_responder, PreKeyBundle, X3dhInitialMessage};

fn ok(v: Value) -> String {
    json!({ "ok": true, "result": v }).to_string()
}

fn err(msg: impl ToString) -> String {
    json!({ "ok": false, "error": msg.to_string() }).to_string()
}

pub fn dispatch(method: &str, args: &Value) -> String {
    match method {
        "version" => ok(json!(crate::version())),
        "generate_identity" => match IdentitySecret::generate() {
            (sec, pub_) => ok(json!({
                "secret_x25519_b64": B64.encode(sec.x25519),
                "secret_ed25519_b64": B64.encode(sec.ed25519),
                "public": pub_,
            })),
        },
        "generate_signed_prekey" => generate_signed_prekey(args),
        "safety_number" => match (
            serde_json::from_value::<IdentityPublic>(args["a"].clone()),
            serde_json::from_value::<IdentityPublic>(args["b"].clone()),
        ) {
            (Ok(a), Ok(b)) => ok(json!(safety_number(&a, &b))),
            _ => err("invalid identity public"),
        },
        "x3dh_initiator" => x3dh_init(args),
        "x3dh_responder" => x3dh_resp(args),
        "envelope_v2_parse" => match args["json"].as_str() {
            Some(s) => match EnvelopeV2::parse_json(s) {
                Ok(e) => ok(serde_json::to_value(e).unwrap_or(json!(null))),
                Err(e) => err(e),
            },
            None => err("missing json"),
        },
        "v1_decrypt" => v1_decrypt(args),
        _ => err(format!("unknown method: {method}")),
    }
}

fn generate_signed_prekey(args: &Value) -> String {
    let x = match decode32(args, "secret_x25519_b64") {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let ed = match decode32(args, "secret_ed25519_b64") {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let key_id = args["key_id"].as_u64().unwrap_or(1) as u32;
    let sec = IdentitySecret {
        x25519: x,
        ed25519: ed,
    };
    match sec.generate_signed_prekey(key_id) {
        Ok((s, p)) => ok(json!({
            "secret_b64": B64.encode(s.secret),
            "public": p,
        })),
        Err(e) => err(e),
    }
}

fn x3dh_init(args: &Value) -> String {
    let alice_sec = match decode32(args, "alice_x25519_b64") {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let alice_pub: IdentityPublic = match serde_json::from_value(args["alice_public"].clone()) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let bundle: PreKeyBundle = match serde_json::from_value(args["bundle"].clone()) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    match x3dh_initiator(&alice_sec, &alice_pub, &bundle) {
        Ok((sk, msg, eka)) => ok(json!({
            "shared_secret_b64": B64.encode(sk.0),
            "initial_message": msg,
            "ephemeral_secret_b64": B64.encode(eka),
        })),
        Err(e) => err(e),
    }
}

fn x3dh_resp(args: &Value) -> String {
    let bob_ik = match decode32(args, "bob_x25519_b64") {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let bob_spk = match decode32(args, "bob_spk_secret_b64") {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let otk = match args.get("bob_otk_secret_b64") {
        Some(v) if !v.is_null() => match decode32(args, "bob_otk_secret_b64") {
            Ok(b) => Some(b),
            Err(e) => return err(e),
        },
        _ => None,
    };
    let msg: X3dhInitialMessage = match serde_json::from_value(args["initial_message"].clone()) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    match x3dh_responder(&bob_ik, &bob_spk, otk.as_ref(), &msg) {
        Ok(sk) => ok(json!({ "shared_secret_b64": B64.encode(sk.0) })),
        Err(e) => err(e),
    }
}

fn v1_decrypt(args: &Value) -> String {
    let d = match B64.decode(args["private_d_b64"].as_str().unwrap_or("")) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let my = args["my_spki_b64"].as_str().unwrap_or("");
    let content = args["content_b64"].as_str().unwrap_or("");
    match crate::v1_compat::decrypt_v1_text(&d, my, content) {
        Ok(t) => ok(json!(t)),
        Err(e) => err(e),
    }
}

fn decode32(args: &Value, key: &str) -> Result<[u8; 32], String> {
    let s = args[key].as_str().ok_or_else(|| format!("missing {key}"))?;
    let bytes = B64.decode(s).map_err(|e| e.to_string())?;
    bytes
        .try_into()
        .map_err(|_| format!("{key} must be 32 bytes"))
}

fn to_c_string(s: String) -> *mut c_char {
    CString::new(s).map(|c| c.into_raw()).unwrap_or(std::ptr::null_mut())
}

/// # Safety
/// `method` and `json_args` must be valid NUL-terminated UTF-8 C strings (or null → empty).
#[no_mangle]
pub unsafe extern "C" fn voce_e2ee_call(method: *const c_char, json_args: *const c_char) -> *mut c_char {
    let method = if method.is_null() {
        ""
    } else {
        CStr::from_ptr(method).to_str().unwrap_or("")
    };
    let args_str = if json_args.is_null() {
        "{}"
    } else {
        CStr::from_ptr(json_args).to_str().unwrap_or("{}")
    };
    let args: Value = serde_json::from_str(args_str).unwrap_or(json!({}));
    to_c_string(dispatch(method, &args))
}

/// # Safety
/// `p` must be a pointer previously returned by [`voce_e2ee_call`], or null.
#[no_mangle]
pub unsafe extern "C" fn voce_e2ee_free(p: *mut c_char) {
    if !p.is_null() {
        drop(CString::from_raw(p));
    }
}

#[cfg(feature = "wasm")]
mod wasm_api {
    use super::*;
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen(start)]
    pub fn wasm_start() {
        console_error_panic_hook::set_once();
    }

    /// Same JSON IPC as `voce_e2ee_call` for browser / wasm-pack consumers.
    #[wasm_bindgen]
    pub fn voce_e2ee_wasm_call(method: &str, json_args: &str) -> String {
        let args: Value = serde_json::from_str(json_args).unwrap_or(json!({}));
        dispatch(method, &args)
    }
}
