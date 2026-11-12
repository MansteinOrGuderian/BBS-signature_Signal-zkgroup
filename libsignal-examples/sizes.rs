// Prints serialized sizes (bytes) of the main zkgroup objects.
// Copy to libsignal/rust/zkgroup/examples/sizes.rs and run:
//   cargo run --release -p zkgroup --example sizes
use zkgroup::auth::AuthCredentialWithPniZkcResponse;

fn main() {
    let server_secret_params = zkgroup::ServerSecretParams::generate(zkgroup::TEST_ARRAY_32);
    let server_public_params = server_secret_params.get_public_params();
    let master_key = zkgroup::groups::GroupMasterKey::new(zkgroup::TEST_ARRAY_32_1);
    let group_secret_params = zkgroup::groups::GroupSecretParams::derive_from_master_key(master_key);

    let aci = libsignal_core::Aci::from_uuid_bytes(zkgroup::TEST_ARRAY_16);
    let pni = libsignal_core::Pni::from_uuid_bytes(zkgroup::TEST_ARRAY_16_1);
    let redemption_time = zkgroup::Timestamp::from_epoch_seconds(123456 * zkgroup::SECONDS_PER_DAY);

    // AuthCredential (zkcredential-based, current production variant)
    let auth_response = AuthCredentialWithPniZkcResponse::issue_credential(
        aci, pni, redemption_time, &server_secret_params, zkgroup::TEST_ARRAY_32_2);
    let auth_credential = auth_response.clone()
        .receive(aci, pni, redemption_time, &server_public_params).unwrap();
    let auth_presentation =
        auth_credential.present(&server_public_params, &group_secret_params, zkgroup::TEST_ARRAY_32_5);

    // Ciphertexts
    let uid_ct = group_secret_params.encrypt_service_id(aci.into());
    let profile_key = zkgroup::profiles::ProfileKey::create(zkgroup::TEST_ARRAY_32_1);
    let pk_ct = group_secret_params.encrypt_profile_key(profile_key, aci);

    // Expiring ProfileKeyCredential (blind issuance)
    let context = server_public_params
        .create_profile_key_credential_request_context(zkgroup::TEST_ARRAY_32_3, aci, profile_key);
    let request = context.get_request();
    let pk_commitment = profile_key.get_commitment(aci);
    let pk_response = server_secret_params.issue_expiring_profile_key_credential(
        zkgroup::TEST_ARRAY_32_4, &request, aci, pk_commitment,
        zkgroup::Timestamp::from_epoch_seconds(zkgroup::SECONDS_PER_DAY)).unwrap();
    let pk_credential = server_public_params.receive_expiring_profile_key_credential(
        &context, &pk_response, zkgroup::Timestamp::from_epoch_seconds(0)).unwrap();
    let pk_presentation = server_public_params.create_expiring_profile_key_credential_presentation(
        zkgroup::TEST_ARRAY_32_5, group_secret_params, pk_credential);

    let rows: Vec<(&str, usize)> = vec![
        ("UidCiphertext", zkgroup::serialize(&uid_ct).len()),
        ("ProfileKeyCiphertext", zkgroup::serialize(&pk_ct).len()),
        ("AuthCredentialWithPniZkcResponse", zkgroup::serialize(&auth_response).len()),
        ("AuthCredentialPresentation (Zkc)", zkgroup::serialize(&auth_presentation).len()),
        ("ProfileKeyCredentialRequest", zkgroup::serialize(&request).len()),
        ("ExpiringProfileKeyCredentialResponse", zkgroup::serialize(&pk_response).len()),
        ("ExpiringProfileKeyCredentialPresentation", zkgroup::serialize(&pk_presentation).len()),
    ];
    for (name, len) in rows {
        println!("{name:<45} {len:>5} bytes");
    }
}
