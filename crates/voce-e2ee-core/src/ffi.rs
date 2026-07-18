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
use crate::identity::{decode_x25519_pub, safety_number, IdentityPublic, IdentitySecret};
use crate::ratchet::{RatchetHeader, RatchetState, RatchetStateDto};
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
        "ratchet_init_alice" => ratchet_init_alice(args),
        "ratchet_init_bob" => ratchet_init_bob(args),
        "ratchet_encrypt" => ratchet_encrypt(args),
        "ratchet_decrypt" => ratchet_decrypt(args),
        "dm_session_open_initiator" => dm_session_open_initiator(args),
        "dm_session_open_responder" => dm_session_open_responder(args),
        "pad_message" => pad_message_ffi(args),
        "unpad_message" => unpad_message_ffi(args),
        method if method.starts_with("mls_") => {
            match crate::mls::commands::dispatch(method, args) {
                Ok(value) => ok(value),
                Err(error) => err(error),
            }
        }
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

fn ratchet_init_alice(args: &Value) -> String {
    let sk = match decode32(args, "shared_secret_b64") {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let bob_dh = match args["bob_dh_pub_b64"].as_str() {
        Some(s) => match decode_x25519_pub(s) {
            Ok(p) => p,
            Err(e) => return err(e),
        },
        None => return err("missing bob_dh_pub_b64"),
    };
    match RatchetState::init_alice(sk, &bob_dh) {
        Ok(st) => ok(json!({ "state": st.to_dto() })),
        Err(e) => err(e),
    }
}

fn ratchet_init_bob(args: &Value) -> String {
    let sk = match decode32(args, "shared_secret_b64") {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let spk = match decode32(args, "bob_spk_secret_b64") {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let st = RatchetState::init_bob(sk, spk);
    ok(json!({ "state": st.to_dto() }))
}

fn parse_state(args: &Value) -> Result<RatchetState, String> {
    let dto: RatchetStateDto =
        serde_json::from_value(args["state"].clone()).map_err(|e| e.to_string())?;
    RatchetState::from_dto(&dto).map_err(|e| e.to_string())
}

fn ratchet_encrypt(args: &Value) -> String {
    let mut st = match parse_state(args) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let plaintext = match plaintext_bytes(args) {
        Ok(b) => b,
        Err(e) => return err(e),
    };
    match st.encrypt(&plaintext) {
        Ok((header, ct)) => ok(json!({
            "state": st.to_dto(),
            "header": header,
            "ciphertext_b64": B64.encode(ct),
        })),
        Err(e) => err(e),
    }
}

fn ratchet_decrypt(args: &Value) -> String {
    let mut st = match parse_state(args) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let header: RatchetHeader = match serde_json::from_value(args["header"].clone()) {
        Ok(h) => h,
        Err(e) => return err(e),
    };
    let ct = match B64.decode(args["ciphertext_b64"].as_str().unwrap_or("")) {
        Ok(b) => b,
        Err(e) => return err(e),
    };
    match st.decrypt(&header, &ct) {
        Ok(pt) => {
            let mut out = json!({
                "state": st.to_dto(),
                "plaintext_b64": B64.encode(&pt),
            });
            if let Ok(s) = String::from_utf8(pt) {
                out["plaintext"] = json!(s);
            }
            ok(out)
        }
        Err(e) => err(e),
    }
}

fn dm_session_open_initiator(args: &Value) -> String {
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
    let plaintext = match plaintext_bytes(args) {
        Ok(b) => b,
        Err(e) => return err(e),
    };
    let (sk, initial, _) = match x3dh_initiator(&alice_sec, &alice_pub, &bundle) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let bob_dh = match decode_x25519_pub(&bundle.signed_prekey.dh_pub_b64) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let mut st = match RatchetState::init_alice(sk.0, &bob_dh) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let (header, ct) = match st.encrypt(&plaintext) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    ok(json!({
        "state": st.to_dto(),
        "header": header,
        "ciphertext_b64": B64.encode(ct),
        "x3dh_initial": initial,
        "used_signed_prekey_id": bundle.signed_prekey.key_id,
    }))
}

fn dm_session_open_responder(args: &Value) -> String {
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
    let initial: X3dhInitialMessage = match serde_json::from_value(args["x3dh_initial"].clone()) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let header: RatchetHeader = match serde_json::from_value(args["header"].clone()) {
        Ok(h) => h,
        Err(e) => return err(e),
    };
    let ct = match B64.decode(args["ciphertext_b64"].as_str().unwrap_or("")) {
        Ok(b) => b,
        Err(e) => return err(e),
    };
    let sk = match x3dh_responder(&bob_ik, &bob_spk, otk.as_ref(), &initial) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let mut st = RatchetState::init_bob(sk.0, bob_spk);
    match st.decrypt(&header, &ct) {
        Ok(pt) => {
            let mut out = json!({
                "state": st.to_dto(),
                "plaintext_b64": B64.encode(&pt),
            });
            if let Ok(s) = String::from_utf8(pt) {
                out["plaintext"] = json!(s);
            }
            ok(out)
        }
        Err(e) => err(e),
    }
}

fn pad_message_ffi(args: &Value) -> String {
    let mime = args["mime"].as_str().unwrap_or("text/plain");
    let text = args["text"].as_str().unwrap_or("");
    match crate::pad::pad_message(mime, text) {
        Ok(b) => ok(json!({ "padded_b64": B64.encode(b) })),
        Err(e) => err(e),
    }
}

fn unpad_message_ffi(args: &Value) -> String {
    let raw = match B64.decode(args["padded_b64"].as_str().unwrap_or("")) {
        Ok(b) => b,
        Err(e) => return err(e),
    };
    match crate::pad::unpad_message(&raw) {
        Ok((m, c)) => ok(json!({ "mime": m, "text": c })),
        Err(e) => err(e),
    }
}

fn plaintext_bytes(args: &Value) -> Result<Vec<u8>, String> {
    if let Some(b64) = args["plaintext_b64"].as_str() {
        return B64.decode(b64).map_err(|e| e.to_string());
    }
    Ok(args["plaintext"].as_str().unwrap_or("").as_bytes().to_vec())
}

fn decode32(args: &Value, key: &str) -> Result<[u8; 32], String> {
    let s = args[key].as_str().ok_or_else(|| format!("missing {key}"))?;
    let bytes = B64.decode(s).map_err(|e| e.to_string())?;
    bytes
        .try_into()
        .map_err(|_| format!("{key} must be 32 bytes"))
}

fn to_c_string(s: String) -> *mut c_char {
    CString::new(s)
        .map(|c| c.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// # Safety
/// `method` and `json_args` must be valid NUL-terminated UTF-8 C strings (or null → empty).
#[no_mangle]
pub unsafe extern "C" fn voce_e2ee_call(
    method: *const c_char,
    json_args: *const c_char,
) -> *mut c_char {
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
