use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};
use voce_e2ee_core::ffi::dispatch;

fn call(method: &str, args: Value) -> Value {
    let output: Value = serde_json::from_str(&dispatch(method, &args)).expect("JSON response");
    assert_eq!(output["ok"], true, "{output}");
    output["result"].clone()
}

#[test]
fn stateless_command_boundary_exchanges_an_mls_application_payload() {
    let alice = call(
        "mls_device_generate",
        json!({"identity_b64": B64.encode(b"alice")}),
    );
    let bob = call(
        "mls_device_generate",
        json!({"identity_b64": B64.encode(b"bob")}),
    );
    let bob_package = call(
        "mls_key_package",
        json!({"device_state_b64": bob["device_state_b64"]}),
    );
    let alice_group = call(
        "mls_group_create",
        json!({
            "device_state_b64": alice["device_state_b64"],
            "group_id_b64": B64.encode(b"opaque-route-token"),
        }),
    );
    let added = call(
        "mls_group_add",
        json!({
            "group_state_b64": alice_group["group_state_b64"],
            "key_package_b64": bob_package["key_package_b64"],
        }),
    );
    let bob_group = call(
        "mls_group_join",
        json!({
            "device_state_b64": bob_package["device_state_b64"],
            "welcome_b64": added["welcome_b64"],
        }),
    );
    let application = call(
        "mls_application_encode",
        json!({
            "kind": 1,
            "body_b64": B64.encode(b"hello"),
            "metadata": {"1": B64.encode(b"text/plain")},
        }),
    );
    let encrypted = call(
        "mls_encrypt",
        json!({
            "group_state_b64": added["group_state_b64"],
            "plaintext_b64": application["plaintext_b64"],
        }),
    );
    let decrypted = call(
        "mls_decrypt",
        json!({
            "group_state_b64": bob_group["group_state_b64"],
            "private_message_b64": encrypted["private_message_b64"],
        }),
    );
    let decoded = call(
        "mls_application_decode",
        json!({"plaintext_b64": decrypted["plaintext_b64"]}),
    );

    assert_eq!(
        B64.decode(decoded["body_b64"].as_str().unwrap()).unwrap(),
        b"hello"
    );
    assert_eq!(decoded["kind"], 1);
}

#[test]
fn malformed_or_oversized_command_input_is_rejected() {
    let malformed: Value = serde_json::from_str(&dispatch(
        "mls_group_join",
        &json!({"device_state_b64": "!", "welcome_b64": "!"}),
    ))
    .unwrap();
    assert_eq!(malformed["ok"], false);

    let oversized: Value = serde_json::from_str(&dispatch(
        "mls_device_generate",
        &json!({"identity_b64": B64.encode(vec![0_u8; 256])}),
    ))
    .unwrap();
    assert_eq!(oversized["ok"], false);
}
