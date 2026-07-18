use openmls::prelude::tls_codec::Deserialize;
use openmls::prelude::{MlsMessageBodyIn, MlsMessageIn};
use voce_e2ee_core::mls::{MlsClient, MlsGroupState};

#[test]
fn two_devices_join_and_exchange_application_message() {
    let alice = MlsClient::generate(b"alice-device").expect("alice credential");
    let mut bob = MlsClient::generate(b"bob-device").expect("bob credential");

    let mut alice_group = alice
        .create_group(b"opaque-group-id")
        .expect("create group");
    let welcome = alice_group
        .add_member(bob.key_package().expect("bob key package"))
        .expect("add bob");
    let mut bob_group = bob.join_group(&welcome).expect("join group");

    let encrypted = alice_group
        .encrypt_application(b"hello from alice")
        .expect("encrypt application message");
    let wire_message =
        MlsMessageIn::tls_deserialize(&mut encrypted.as_slice()).expect("valid MLS wire message");
    assert!(matches!(
        wire_message.extract(),
        MlsMessageBodyIn::PrivateMessage(_)
    ));
    let plaintext = bob_group
        .decrypt_application(&encrypted)
        .expect("decrypt application message");

    assert_eq!(plaintext, b"hello from alice");
    assert!(
        bob_group.decrypt_application(&encrypted).is_err(),
        "replay rejected"
    );
}

#[test]
fn group_state_roundtrips_without_changing_wire_behavior() {
    let alice = MlsClient::generate(b"alice-device").expect("alice credential");
    let mut bob = MlsClient::generate(b"bob-device").expect("bob credential");
    let mut alice_group = alice.create_group(b"persistent-group").expect("group");
    let welcome = alice_group
        .add_member(bob.key_package().expect("bob key package"))
        .expect("add bob");
    let mut bob_group = bob.join_group(&welcome).expect("join group");

    let snapshot = alice_group.snapshot().expect("snapshot");
    let mut restored = voce_e2ee_core::mls::MlsGroupState::restore(&snapshot).expect("restore");
    let encrypted = restored
        .encrypt_application(b"after restart")
        .expect("encrypt after restore");

    assert_eq!(
        bob_group.decrypt_application(&encrypted).expect("decrypt"),
        b"after restart"
    );
}

#[test]
fn tampering_is_rejected() {
    let alice = MlsClient::generate(b"alice-device").expect("alice credential");
    let mut bob = MlsClient::generate(b"bob-device").expect("bob credential");
    let mut alice_group = alice.create_group(b"tamper-group").expect("group");
    let welcome = alice_group
        .add_member(bob.key_package().expect("bob key package"))
        .expect("add bob");
    let mut bob_group = bob.join_group(&welcome).expect("join group");
    let mut encrypted = alice_group
        .encrypt_application(b"authenticated")
        .expect("encrypt");
    let last = encrypted.last_mut().expect("non-empty wire message");
    *last ^= 1;

    assert!(bob_group.decrypt_application(&encrypted).is_err());
}

#[test]
fn device_key_package_and_welcome_survive_binary_boundaries() {
    let alice = MlsClient::generate(b"alice-device").expect("alice credential");
    let bob = MlsClient::generate(b"bob-device").expect("bob credential");
    let bob_snapshot = bob.snapshot().expect("device snapshot");
    let mut bob = MlsClient::restore(&bob_snapshot).expect("device restore");
    let key_package = bob.key_package().expect("key package");
    let key_package = voce_e2ee_core::mls::MlsKeyPackage::from_bytes(
        &key_package.to_bytes().expect("serialize key package"),
    )
    .expect("deserialize key package");

    let mut alice_group = alice.create_group(b"binary-boundary").expect("group");
    let welcome = alice_group.add_member(key_package).expect("add member");
    let welcome = voce_e2ee_core::mls::MlsWelcome::from_bytes(
        &welcome.to_bytes().expect("serialize welcome"),
    )
    .expect("deserialize welcome");
    let mut bob_group = bob.join_group(&welcome).expect("join");
    let message = alice_group
        .encrypt_application(b"portable")
        .expect("encrypt");

    assert_eq!(
        bob_group.decrypt_application(&message).expect("decrypt"),
        b"portable"
    );
}

#[test]
fn a_single_commit_adds_all_channel_devices() {
    let alice = MlsClient::generate(b"alice").unwrap();
    let mut bob = MlsClient::generate(b"bob").unwrap();
    let mut charlie = MlsClient::generate(b"charlie").unwrap();
    let packages = vec![bob.key_package().unwrap(), charlie.key_package().unwrap()];
    let mut alice_group = alice.create_group(b"channel").unwrap();
    let welcome = alice_group.add_members(packages).unwrap();
    let mut bob_group = bob.join_group(&welcome).unwrap();
    let mut charlie_group = charlie.join_group(&welcome).unwrap();
    assert_eq!(alice_group.member_identities().len(), 3);
    assert_eq!(bob_group.member_identities().len(), 3);
    let message = alice_group.encrypt_application(b"everyone").unwrap();

    assert_eq!(
        bob_group.decrypt_application(&message).unwrap(),
        b"everyone"
    );
    assert_eq!(
        charlie_group.decrypt_application(&message).unwrap(),
        b"everyone"
    );
}

#[test]
fn existing_members_process_commit_when_a_device_joins_later() {
    let alice = MlsClient::generate(b"alice").unwrap();
    let mut bob = MlsClient::generate(b"bob").unwrap();
    let mut charlie = MlsClient::generate(b"charlie").unwrap();
    let mut alice_group = alice.create_group(b"growing-channel").unwrap();
    let bob_welcome = alice_group.add_member(bob.key_package().unwrap()).unwrap();
    let mut bob_group = bob.join_group(&bob_welcome).unwrap();

    let admission = alice_group
        .add_members_with_commit(vec![charlie.key_package().unwrap()])
        .unwrap();
    let commit = MlsGroupState::admission_commit(&admission).to_vec();
    assert!(matches!(
        bob_group.process_message(&commit).unwrap(),
        voce_e2ee_core::mls::MlsProcessed::Commit
    ));
    let welcome = MlsGroupState::admission_welcome(admission);
    let mut charlie_group = charlie.join_group(&welcome).unwrap();
    let message = alice_group.encrypt_application(b"new epoch").unwrap();

    assert_eq!(
        bob_group.decrypt_application(&message).unwrap(),
        b"new epoch"
    );
    assert_eq!(
        charlie_group.decrypt_application(&message).unwrap(),
        b"new epoch"
    );
}

#[test]
fn removed_member_cannot_decrypt_the_next_epoch() {
    let alice = MlsClient::generate(b"alice").unwrap();
    let mut bob = MlsClient::generate(b"bob").unwrap();
    let mut charlie = MlsClient::generate(b"charlie").unwrap();
    let mut alice_group = alice.create_group(b"removal-channel").unwrap();
    let welcome = alice_group
        .add_members(vec![
            bob.key_package().unwrap(),
            charlie.key_package().unwrap(),
        ])
        .unwrap();
    let mut bob_group = bob.join_group(&welcome).unwrap();
    let mut charlie_group = charlie.join_group(&welcome).unwrap();

    let commit = alice_group
        .remove_identities(&[b"charlie".to_vec()])
        .unwrap();
    assert!(matches!(
        bob_group.process_message(&commit).unwrap(),
        voce_e2ee_core::mls::MlsProcessed::Commit
    ));
    let _ = charlie_group.process_message(&commit);
    let message = alice_group.encrypt_application(b"after removal").unwrap();

    assert_eq!(
        bob_group.decrypt_application(&message).unwrap(),
        b"after removal"
    );
    assert!(charlie_group.decrypt_application(&message).is_err());
}
