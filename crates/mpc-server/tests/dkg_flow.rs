//! The full flow with the server acting as a DKG party.
//!
//! The test drives the extension's two parties (A and B) while the server handles party C over
//! HTTP. It also confirms that the server's state survives a round trip through the database
//! between rounds.

// Panicking is how a test asserts. Production code keeps these lints.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use base64::Engine;
use mpc_core::{
    DkgParty, Envelope, KeyShare, PartyId, Progress, PublicKey, ReshareRole, SignParty,
    SignProgress,
};
use mpc_server::api::{router, AppState};
use mpc_server::crypto::SealingKey;
use mpc_server::passkey::PasskeyConfig;
use mpc_server::recovery::RecoveryConfig;
use mpc_server::store::Store;
use p256::ecdsa::{signature::Signer, SigningKey};
use serde_json::{json, Value};
use tower::ServiceExt;

const SERVER_PARTY: u8 = 2;

async fn test_app() -> axum::Router {
    let store = Store::open("sqlite::memory:")
        .await
        .expect("the database should open");
    router(AppState {
        store,
        sealing: SealingKey::new(&[42u8; 32]),
        passkey: PasskeyConfig::new("localhost", "http://localhost:8080")
            .expect("test passkey configuration"),
        recovery: RecoveryConfig::default(),
    })
}

#[tokio::test]
async fn device_key_registration_validates_and_persists_the_public_key() {
    let app = test_app().await;
    let public_key = format!("04{}", "ab".repeat(64));
    let (status, body) = post(
        &app,
        "/v1/device-key",
        json!({ "wallet_id": "wallet-device", "public_key": public_key }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "registration failed: {body}"
    );

    let (status, body) = post(
        &app,
        "/v1/device-key",
        json!({ "wallet_id": "wallet-device", "public_key": "not-hex" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "malformed key was accepted: {body}"
    );

    let (status, body) = post(
        &app,
        "/v1/device-key",
        json!({
            "wallet_id": "wallet-device",
            "public_key": format!("02{}", "ab".repeat(64))
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "compressed key was accepted: {body}"
    );
}

/// Anyone who knows a wallet id could once replace its device key and lock the real extension
/// out. Registration is first-use only now, and the original key must keep working.
#[tokio::test]
async fn a_second_device_key_cannot_replace_the_first() {
    let (app, _store, device_key) = wallet_with_device("wallet-squat").await;

    let intruder = SigningKey::from_bytes((&[99u8; 32]).into()).expect("intruder key");
    let intruder_key = hex_of(intruder.verifying_key().to_encoded_point(false).as_bytes());
    let (status, body) = post(
        &app,
        "/v1/device-key",
        json!({ "wallet_id": "wallet-squat", "public_key": intruder_key }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a replacement must be refused: {body}"
    );

    // The first key still authenticates, and the intruder's does not.
    let request = json!({ "wallet_id": "wallet-squat", "purpose": "register" });
    let (status, _) = signed_post(
        &app,
        &device_key,
        "/v1/passkeys/handoff",
        request.clone(),
        "kept",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the original key must still work");
    let (status, _) =
        signed_post(&app, &intruder, "/v1/passkeys/handoff", request, "intruder").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the intruder's key must not work"
    );
}

#[tokio::test]
async fn device_nonce_is_reserved_only_once() {
    let store = Store::open("sqlite::memory:")
        .await
        .expect("the database should open");
    assert!(store
        .reserve_device_nonce("wallet-device", "nonce-1", 300)
        .await
        .expect("the first reservation should work"));
    assert!(!store
        .reserve_device_nonce("wallet-device", "nonce-1", 300)
        .await
        .expect("the replay should be checked"));
    assert!(store
        .reserve_device_nonce("other-wallet", "nonce-1", 300)
        .await
        .expect("a different wallet has its own nonce namespace"));
}

#[tokio::test]
async fn passkey_challenges_are_single_use_and_wallet_bound() {
    let store = Store::open("sqlite::memory:")
        .await
        .expect("the database should open");
    store
        .put_passkey_challenge("challenge-1", "wallet-a", "sign", &[1, 2, 3], 300)
        .await
        .expect("the challenge should be stored");
    assert_eq!(
        store
            .take_passkey_challenge("challenge-1", "wallet-b", "sign")
            .await
            .expect("the wrong wallet should be checked"),
        None
    );
    assert_eq!(
        store
            .take_passkey_challenge("challenge-1", "wallet-a", "sign")
            .await
            .expect("the challenge should be consumed"),
        Some(vec![1, 2, 3])
    );
    assert_eq!(
        store
            .take_passkey_challenge("challenge-1", "wallet-a", "sign")
            .await
            .expect("the replay should be checked"),
        None
    );
}

#[tokio::test]
async fn passkey_registration_options_are_authenticated_and_single_use() {
    let app = test_app().await;
    let device_key = SigningKey::from_bytes((&[11u8; 32]).into()).expect("device key");
    let public_key = device_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let (status, _) = post(
        &app,
        "/v1/device-key",
        json!({ "wallet_id": "wallet-passkey", "public_key": public_key }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let options_request = json!({ "wallet_id": "wallet-passkey" });
    let (status, options) = post_with_headers(
        &app,
        "/v1/passkeys/register/options",
        options_request.clone(),
        device_headers(
            "/v1/passkeys/register/options",
            &options_request,
            &device_key,
            "passkey-options",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "options failed: {options}");
    let challenge_id = options["challenge_id"]
        .as_str()
        .expect("the challenge id should be returned")
        .to_owned();
    assert_eq!(
        options["options"]["rp"]["id"], "localhost",
        "the RP ID must be fixed by server configuration"
    );
    // Assertions accept P-256 keys only, so ES256 (-7) must be the only algorithm on offer. An
    // authenticator that supports EdDSA would otherwise register a key that can never assert.
    let offered: Vec<i64> = options["options"]["pubKeyCredParams"]
        .as_array()
        .expect("the algorithms should be listed")
        .iter()
        .map(|param| param["alg"].as_i64().expect("alg"))
        .collect();
    assert_eq!(offered, vec![-7], "only ES256 may be offered");

    // Credential protection is requested at the strictest level but not enforced. Enforcing it
    // makes registration fail on authenticators without the extension, which includes platform
    // ones, while every assertion already requires user verification.
    let extensions = &options["options"]["extensions"];
    assert_eq!(
        extensions["credentialProtectionPolicy"], "userVerificationRequired",
        "credProtect should still be requested: {extensions}"
    );
    assert_eq!(
        extensions["enforceCredentialProtectionPolicy"], false,
        "credProtect must not be enforced: {extensions}"
    );

    let finish_request = json!({
        "wallet_id": "wallet-passkey",
        "challenge_id": challenge_id,
        "credential": {}
    });
    let (status, body) = post_with_headers(
        &app,
        "/v1/passkeys/register/finish",
        finish_request.clone(),
        device_headers(
            "/v1/passkeys/register/finish",
            &finish_request,
            &device_key,
            "passkey-finish-invalid",
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "invalid credential: {body}"
    );

    let (status, body) = post_with_headers(
        &app,
        "/v1/passkeys/register/finish",
        finish_request.clone(),
        device_headers(
            "/v1/passkeys/register/finish",
            &finish_request,
            &device_key,
            "passkey-finish-replay",
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a consumed challenge must not be reusable: {body}"
    );
}

#[tokio::test]
async fn passkey_assertion_binding_is_wallet_and_operation_bound() {
    let store = Store::open("sqlite::memory:")
        .await
        .expect("the database should open");
    store
        .put_passkey_credential(
            "wallet-assertion",
            br#"{"id":[1],"user_id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"static_state":[],"dynamic_state":[true,0,0,0,0,0,0]}"#,
            0,
        )
        .await
        .expect("the test credential should be stored");
    let app = router(AppState {
        store,
        sealing: SealingKey::new(&[42u8; 32]),
        passkey: PasskeyConfig::new("localhost", "http://localhost:8080")
            .expect("test passkey configuration"),
        recovery: RecoveryConfig::default(),
    });
    let device_key = SigningKey::from_bytes((&[12u8; 32]).into()).expect("device key");
    let public_key = device_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let (status, _) = post(
        &app,
        "/v1/device-key",
        json!({ "wallet_id": "wallet-assertion", "public_key": public_key }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let options_request = json!({
        "wallet_id": "wallet-assertion",
        "purpose": "sign",
        "operation_id": "sign-1",
        "digest": "aa".repeat(32)
    });
    let (status, options) = post_with_headers(
        &app,
        "/v1/passkeys/assert/options",
        options_request.clone(),
        device_headers(
            "/v1/passkeys/assert/options",
            &options_request,
            &device_key,
            "assert-options",
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "assertion options failed: {options}"
    );
    assert_eq!(options["options"]["userVerification"], "required");

    let challenge_id = options["challenge_id"]
        .as_str()
        .expect("the challenge id should be returned")
        .to_owned();
    let finish_request = json!({
        "wallet_id": "wallet-assertion",
        "challenge_id": challenge_id,
        "purpose": "recovery",
        "operation_id": "sign-1",
        "digest": "aa".repeat(32),
        "credential": {}
    });
    let (status, body) = post_with_headers(
        &app,
        "/v1/passkeys/assert/finish",
        finish_request.clone(),
        device_headers(
            "/v1/passkeys/assert/finish",
            &finish_request,
            &device_key,
            "assert-finish-substitution",
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "operation substitution: {body}"
    );
}

#[tokio::test]
async fn signing_rejects_tampered_and_replayed_device_proofs() {
    let store = Store::open("sqlite::memory:")
        .await
        .expect("the database should open");
    let app = router(AppState {
        store: store.clone(),
        sealing: SealingKey::new(&[42u8; 32]),
        passkey: PasskeyConfig::new("localhost", "http://localhost:8080")
            .expect("test passkey configuration"),
        recovery: RecoveryConfig::default(),
    });
    let (_shares, _public_key) = provision(&app, "wallet-auth", 0xd1).await;
    let device_key = SigningKey::from_bytes((&[8u8; 32]).into()).expect("device key");
    let public_key = device_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let (status, _) = post(
        &app,
        "/v1/device-key",
        json!({ "wallet_id": "wallet-auth", "public_key": public_key }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let body = json!({
        "wallet_id": "wallet-auth",
        "sign_id": "d2".repeat(32),
        "digest": "e3".repeat(32),
        "counterparty": 0,
    });
    store
        .put_passkey_authorization(
            "wallet-auth",
            "sign",
            body["sign_id"].as_str().expect("sign id"),
            body["digest"].as_str().expect("digest"),
            300,
        )
        .await
        .expect("the signing authorization should be stored");
    let headers = device_headers("/v1/sign/session", &body, &device_key, "auth-replay");
    let (status, _) =
        post_with_headers(&app, "/v1/sign/session", body.clone(), headers.clone()).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = post_with_headers(&app, "/v1/sign/session", body, headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn browser_handoff_uses_a_body_token_and_scoped_cookie() {
    let app = test_app().await;
    let device_key = SigningKey::from_bytes((&[21u8; 32]).into()).expect("device key");
    let public_key = device_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let (status, _) = post(
        &app,
        "/v1/device-key",
        json!({ "wallet_id": "wallet-browser", "public_key": public_key }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let handoff_request = json!({ "wallet_id": "wallet-browser", "purpose": "register" });
    let (status, handoff) = post_with_headers(
        &app,
        "/v1/passkeys/handoff",
        handoff_request.clone(),
        device_headers(
            "/v1/passkeys/handoff",
            &handoff_request,
            &device_key,
            "browser-handoff",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "handoff failed: {handoff}");
    let ceremony_id = handoff["ceremony_id"].as_str().expect("ceremony id");
    let token = handoff["handoff_token"].as_str().expect("handoff token");
    assert!(!token.is_empty());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/handoff")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("handoff_token={token}")))
                .expect("handoff request should build"),
        )
        .await
        .expect("handoff response should arrive");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["location"], "/auth");
    let set_cookie = response.headers()["set-cookie"]
        .to_str()
        .expect("cookie header")
        .to_owned();
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Strict"));
    assert!(!set_cookie.contains(token));
    let cookie = set_cookie.split(';').next().expect("session cookie");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/auth/session")
                .header("cookie", cookie)
                .body(Body::empty())
                .expect("options request should build"),
        )
        .await
        .expect("options response should arrive");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store, max-age=0");
    let options = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("options body");
    let options: Value = serde_json::from_slice(&options).expect("options JSON");
    assert_eq!(options["kind"], "register");
    assert!(options["options"]["challenge"].is_string());

    let status_request = json!({
        "wallet_id": "wallet-browser",
        "ceremony_id": ceremony_id,
    });
    let (status, status_body) = post_with_headers(
        &app,
        "/v1/passkeys/ceremony/status",
        status_request.clone(),
        device_headers(
            "/v1/passkeys/ceremony/status",
            &status_request,
            &device_key,
            "browser-status",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "status failed: {status_body}");
    assert_eq!(status_body["status"], "inProgress");

    let replay = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/handoff")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("handoff_token={token}")))
                .expect("replay request should build"),
        )
        .await
        .expect("replay response should arrive");
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
}

/// The extension signs the text `JSON.stringify` produces and sends that same text. A `register`
/// handoff (no operation id, no digest) was once rejected because the server checked a
/// re-serialization instead, which wrote `null` for the missing fields.
#[tokio::test]
async fn signed_requests_are_verified_over_the_exact_bytes_sent() {
    let app = test_app().await;
    let device_key = SigningKey::from_bytes((&[23u8; 32]).into()).expect("device key");
    let public_key = hex_of(
        device_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let (status, _) = post(
        &app,
        "/v1/device-key",
        json!({ "wallet_id": "wallet-js", "public_key": public_key }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Exactly what `JSON.stringify({ wallet_id, purpose, operation_id: undefined, ... })` yields.
    let sent = r#"{"wallet_id":"wallet-js","purpose":"register"}"#;
    let (status, body) = post_text(
        &app,
        "/v1/passkeys/handoff",
        sent,
        device_headers_for_text("/v1/passkeys/handoff", sent, &device_key, "js-exact"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the exact text must be accepted: {body}"
    );

    // The same fields with different spacing are different bytes, so a proof for one text must
    // not validate the other, whatever the parsed value.
    let spaced = r#"{ "wallet_id": "wallet-js", "purpose": "register" }"#;
    let (status, _) = post_text(
        &app,
        "/v1/passkeys/handoff",
        spaced,
        device_headers_for_text("/v1/passkeys/handoff", sent, &device_key, "js-spaced"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a proof over other bytes must be refused"
    );
}

#[tokio::test]
async fn browser_ceremony_assets_are_no_store_and_csp_restricted() {
    let app = test_app().await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/auth")
                .body(Body::empty())
                .expect("page request should build"),
        )
        .await
        .expect("page response should arrive");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store, max-age=0");
    assert!(response.headers()["content-security-policy"]
        .to_str()
        .expect("CSP header")
        .contains("script-src 'self'"));
    let page = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("page body");
    assert!(String::from_utf8_lossy(&page).contains("/auth.js"));

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/auth.js")
                .body(Body::empty())
                .expect("script request should build"),
        )
        .await
        .expect("script response should arrive");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "application/javascript; charset=utf-8"
    );
}

async fn post(app: &axum::Router, path: &str, body: Value) -> (StatusCode, Value) {
    post_with_headers(app, path, body, HeaderMap::new()).await
}

async fn post_with_headers(
    app: &axum::Router,
    path: &str,
    body: Value,
    headers: HeaderMap,
) -> (StatusCode, Value) {
    post_text(app, path, &body.to_string(), headers).await
}

/// Sends `text` byte for byte, which is what a signed request has to do.
async fn post_text(
    app: &axum::Router,
    path: &str,
    text: &str,
    headers: HeaderMap,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    for (name, value) in &headers {
        request = request.header(name, value);
    }
    let response = app
        .clone()
        .oneshot(
            request
                .body(Body::from(text.to_owned()))
                .expect("the request should build"),
        )
        .await
        .expect("a response should arrive");

    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 32 * 1024 * 1024)
        .await
        .expect("the body should be readable");
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

/// Signs the body exactly as `post_with_headers` will send it. The server verifies the received
/// bytes, so a helper that re-serialized through a typed struct would only hide mismatches.
fn device_headers(path: &str, body: &Value, key: &SigningKey, nonce: &str) -> HeaderMap {
    device_headers_for_text(path, &body.to_string(), key, nonce)
}

/// Signs `text` as the body of a request to `path`.
fn device_headers_for_text(path: &str, text: &str, key: &SigningKey, nonce: &str) -> HeaderMap {
    let timestamp = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let serialized = text;
    let message = format!("POST\n{path}\n{timestamp}\n{nonce}\n{serialized}");
    let signature: p256::ecdsa::Signature = key.sign(message.as_bytes());
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-device-timestamp",
        HeaderValue::from_str(&timestamp.to_string()).expect("timestamp header"),
    );
    headers.insert(
        "x-device-nonce",
        HeaderValue::from_str(nonce).expect("nonce header"),
    );
    headers.insert(
        "x-device-signature",
        HeaderValue::from_str(
            &base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        )
        .expect("signature header"),
    );
    headers
}

fn to_wire(envelope: &Envelope) -> Value {
    json!({
        "round": envelope.round,
        "from": envelope.from.0,
        "to": envelope.to.map(|p| p.0),
        "payload": base64::engine::general_purpose::STANDARD.encode(&envelope.payload),
    })
}

fn from_wire(value: &Value) -> Envelope {
    Envelope {
        round: u8::try_from(value["round"].as_u64().expect("round")).expect("round fits"),
        from: PartyId(u8::try_from(value["from"].as_u64().expect("from")).expect("from fits")),
        to: value["to"]
            .as_u64()
            .map(|v| PartyId(u8::try_from(v).expect("to fits"))),
        payload: base64::engine::general_purpose::STANDARD
            .decode(value["payload"].as_str().expect("payload"))
            .expect("the payload should be base64"),
    }
}

#[tokio::test]
async fn server_participates_in_a_full_dkg() {
    let app = test_app().await;
    let session_hex = "a5".repeat(32);
    let session_id = [0xa5u8; 32];

    // The two parties the extension drives.
    let mut local = Vec::new();
    let mut in_flight: Vec<Envelope> = Vec::new();
    for id in [PartyId(0), PartyId(1)] {
        let (party, outgoing) = DkgParty::start(id, &session_id).expect("the party should start");
        local.push(party);
        in_flight.extend(outgoing);
    }

    // Party C, driven by the server.
    let (status, body) = post(
        &app,
        "/v1/dkg/session",
        json!({ "wallet_id": "wallet-1", "session_id": session_hex }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the session should open: {body}");
    for envelope in body["envelopes"].as_array().expect("envelopes") {
        in_flight.push(from_wire(envelope));
    }

    let mut public_key: Option<String> = None;
    let mut shares = Vec::new();

    for _round in 0..4 {
        let mut next: Vec<Envelope> = Vec::new();
        let mut done = 0;

        for party in &mut local {
            let me = party.party();
            let inbox: Vec<Envelope> = in_flight
                .iter()
                .filter(|e| e.from != me && e.to.is_none_or(|to| to == me))
                .cloned()
                .collect();
            match party.advance(&inbox).expect("the round should advance") {
                Progress::Send(outgoing) => next.extend(outgoing),
                Progress::Done {
                    share,
                    public_key: pk,
                } => {
                    done += 1;
                    shares.push(share);
                    public_key
                        .get_or_insert_with(|| pk.0.iter().map(|b| format!("{b:02x}")).collect());
                }
            }
        }

        // Advance the server's party over HTTP. Its state is restored from the database each
        // time.
        let for_server: Vec<Value> = in_flight
            .iter()
            .filter(|e| {
                e.from != PartyId(SERVER_PARTY) && e.to.is_none_or(|to| to.0 == SERVER_PARTY)
            })
            .map(to_wire)
            .collect();

        let (status, body) = post(
            &app,
            "/v1/dkg/round",
            json!({
                "session_id": session_hex,
                "wallet_id": "wallet-1",
                "envelopes": for_server,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the round should advance: {body}");

        match body["state"].as_str().expect("state") {
            "inProgress" => {
                for envelope in body["envelopes"].as_array().expect("envelopes") {
                    next.push(from_wire(envelope));
                }
            }
            "completed" => {
                let server_key = body["public_key"].as_str().expect("public_key").to_string();
                assert_eq!(
                    Some(&server_key),
                    public_key.as_ref(),
                    "server and extension should agree on the public key"
                );
                assert_eq!(done, 2, "both extension parties should have finished too");
                assert_eq!(shares.len(), 2);
                return;
            }
            other => panic!("unknown state: {other}"),
        }

        in_flight = next;
    }

    panic!("DKG did not finish within four rounds");
}

#[tokio::test]
async fn rejects_an_unknown_session() {
    let app = test_app().await;

    let (status, body) = post(
        &app,
        "/v1/dkg/round",
        json!({ "session_id": "00".repeat(32), "wallet_id": "nope", "envelopes": [] }),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn rejects_a_malformed_session_id() {
    let app = test_app().await;

    let (status, _) = post(
        &app,
        "/v1/dkg/session",
        json!({ "wallet_id": "wallet-1", "session_id": "too-short" }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Runs a full DKG and returns the extension's two shares plus the wallet's public key.
async fn provision(app: &axum::Router, wallet: &str, tag: u8) -> (Vec<mpc_core::KeyShare>, String) {
    let session_hex = format!("{tag:02x}").repeat(32);
    let session_id = [tag; 32];

    let mut local = Vec::new();
    let mut in_flight: Vec<Envelope> = Vec::new();
    for id in [PartyId(0), PartyId(1)] {
        let (party, outgoing) = DkgParty::start(id, &session_id).expect("the party should start");
        local.push(party);
        in_flight.extend(outgoing);
    }

    let (status, body) = post(
        app,
        "/v1/dkg/session",
        json!({ "wallet_id": wallet, "session_id": session_hex }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the session should open: {body}");
    for envelope in body["envelopes"].as_array().expect("envelopes") {
        in_flight.push(from_wire(envelope));
    }

    let mut shares = Vec::new();
    let mut public_key = String::new();

    for _round in 0..4 {
        let mut next: Vec<Envelope> = Vec::new();
        for party in &mut local {
            let me = party.party();
            let inbox: Vec<Envelope> = in_flight
                .iter()
                .filter(|e| e.from != me && e.to.is_none_or(|to| to == me))
                .cloned()
                .collect();
            match party.advance(&inbox).expect("the round should advance") {
                Progress::Send(outgoing) => next.extend(outgoing),
                Progress::Done { share, .. } => shares.push(share),
            }
        }

        let for_server: Vec<Value> = in_flight
            .iter()
            .filter(|e| {
                e.from != PartyId(SERVER_PARTY) && e.to.is_none_or(|to| to.0 == SERVER_PARTY)
            })
            .map(to_wire)
            .collect();
        let (status, body) = post(
            app,
            "/v1/dkg/round",
            json!({ "session_id": session_hex, "wallet_id": wallet, "envelopes": for_server }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the round should advance: {body}");

        match body["state"].as_str().expect("state") {
            "inProgress" => {
                for envelope in body["envelopes"].as_array().expect("envelopes") {
                    next.push(from_wire(envelope));
                }
            }
            "completed" => {
                public_key = body["public_key"].as_str().expect("public_key").to_string();
                break;
            }
            other => panic!("unknown state: {other}"),
        }
        in_flight = next;
    }

    shares.sort_by_key(|s| s.party().0);
    (shares, public_key)
}

#[tokio::test]
async fn extension_and_server_sign_together() {
    let store = Store::open("sqlite::memory:")
        .await
        .expect("the database should open");
    let app = router(AppState {
        store: store.clone(),
        sealing: SealingKey::new(&[42u8; 32]),
        passkey: PasskeyConfig::new("localhost", "http://localhost:8080")
            .expect("test passkey configuration"),
        recovery: RecoveryConfig::default(),
    });
    let (shares, public_key_hex) = provision(&app, "wallet-sign", 0xb7).await;
    let device_key = SigningKey::from_bytes((&[7u8; 32]).into()).expect("device key");
    let public_key = device_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let (status, _) = post(
        &app,
        "/v1/device-key",
        json!({ "wallet_id": "wallet-sign", "public_key": public_key }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let sign_hex = "c4".repeat(32);
    let digest = [0x39u8; 32];
    let digest_hex = "39".repeat(32);
    store
        .put_passkey_authorization("wallet-sign", "sign", &sign_hex, &digest_hex, 300)
        .await
        .expect("the signing authorization should be stored");

    // The extension drives share A; the server drives share C.
    let (mut extension, mut in_flight) =
        SignParty::start(&shares[0], PartyId(SERVER_PARTY), &[0xc4; 32], &digest)
            .expect("the party should start");

    let start_body = json!({
        "wallet_id": "wallet-sign",
        "sign_id": sign_hex,
        "digest": digest_hex,
        "counterparty": 0,
    });
    let (status, body) = post_with_headers(
        &app,
        "/v1/sign/session",
        start_body.clone(),
        device_headers("/v1/sign/session", &start_body, &device_key, "sign-start"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the signing session should open: {body}"
    );
    for envelope in body["envelopes"].as_array().expect("envelopes") {
        in_flight.push(from_wire(envelope));
    }

    let mut signature: Option<String> = None;

    for round in 0..4 {
        let mut next: Vec<Envelope> = Vec::new();

        let inbox: Vec<Envelope> = in_flight
            .iter()
            .filter(|e| e.from != PartyId(0) && e.to.is_none_or(|to| to == PartyId(0)))
            .cloned()
            .collect();
        match extension.advance(&inbox).expect("the round should advance") {
            SignProgress::Send(outgoing) => next.extend(outgoing),
            SignProgress::Done(_) => {}
        }

        let for_server: Vec<Value> = in_flight
            .iter()
            .filter(|e| {
                e.from != PartyId(SERVER_PARTY) && e.to.is_none_or(|to| to.0 == SERVER_PARTY)
            })
            .map(to_wire)
            .collect();
        let round_body = json!({
            "wallet_id": "wallet-sign",
            "sign_id": sign_hex,
            "envelopes": for_server,
        });
        let (status, body) = post_with_headers(
            &app,
            "/v1/sign/round",
            round_body.clone(),
            device_headers(
                "/v1/sign/round",
                &round_body,
                &device_key,
                &format!("sign-round-{round}"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the round should advance: {body}");

        match body["state"].as_str().expect("state") {
            "inProgress" => {
                for envelope in body["envelopes"].as_array().expect("envelopes") {
                    next.push(from_wire(envelope));
                }
            }
            "completed" => {
                signature = Some(body["signature"].as_str().expect("signature").to_string());
                break;
            }
            other => panic!("unknown state: {other}"),
        }
        in_flight = next;
    }

    let signature = signature.expect("signing should finish");
    assert_eq!(signature.len(), 130, "a signature is 65 bytes as hex");

    // The signature must verify against the wallet's public key.
    let mut public_key = [0u8; 33];
    for (i, slot) in public_key.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&public_key_hex[i * 2..i * 2 + 2], 16).expect("hex");
    }
    let mut raw = [0u8; 65];
    for (i, slot) in raw.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&signature[i * 2..i * 2 + 2], 16).expect("hex");
    }
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&raw[..32]);
    s.copy_from_slice(&raw[32..64]);

    assert!(
        mpc_core::verify(
            &mpc_core::PublicKey(public_key),
            &digest,
            &mpc_core::Signature {
                r,
                s,
                recovery_id: raw[64]
            },
        )
        .expect("verification should run"),
        "the signature should verify against the wallet public key"
    );
}

#[tokio::test]
async fn signing_rejects_an_unknown_wallet() {
    let app = test_app().await;

    let (status, _) = post(
        &app,
        "/v1/sign/session",
        json!({
            "wallet_id": "nobody",
            "sign_id": "aa".repeat(32),
            "digest": "bb".repeat(32),
            "counterparty": 0,
        }),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn signing_requires_a_matching_one_use_passkey_authorization() {
    let store = Store::open("sqlite::memory:")
        .await
        .expect("the database should open");
    let app = router(AppState {
        store: store.clone(),
        sealing: SealingKey::new(&[42u8; 32]),
        passkey: PasskeyConfig::new("localhost", "http://localhost:8080")
            .expect("test passkey configuration"),
        recovery: RecoveryConfig::default(),
    });
    let _ = provision(&app, "wallet-grant", 0xe1).await;
    let device_key = SigningKey::from_bytes((&[21u8; 32]).into()).expect("device key");
    let public_key = device_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let (status, _) = post(
        &app,
        "/v1/device-key",
        json!({ "wallet_id": "wallet-grant", "public_key": public_key }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let sign_id = "a1".repeat(32);
    let digest = "b2".repeat(32);
    let start = json!({
        "wallet_id": "wallet-grant",
        "sign_id": sign_id,
        "digest": digest,
        "counterparty": 0,
    });
    let (status, _) = post_with_headers(
        &app,
        "/v1/sign/session",
        start.clone(),
        device_headers("/v1/sign/session", &start, &device_key, "grant-missing"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "missing grant must fail");

    store
        .put_passkey_authorization("wallet-grant", "sign", &sign_id, &digest, 300)
        .await
        .expect("the grant should be stored");
    let (status, _) = post_with_headers(
        &app,
        "/v1/sign/session",
        start.clone(),
        device_headers("/v1/sign/session", &start, &device_key, "grant-first-use"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the matching grant must open signing"
    );

    let (status, _) = post_with_headers(
        &app,
        "/v1/sign/session",
        start,
        device_headers(
            "/v1/sign/session",
            &json!({
                "wallet_id": "wallet-grant",
                "sign_id": sign_id,
                "digest": digest,
                "counterparty": 0,
            }),
            &device_key,
            "grant-replay",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a grant must be one-use");

    let mismatched_sign_id = "c3".repeat(32);
    store
        .put_passkey_authorization("wallet-grant", "sign", &mismatched_sign_id, &digest, 300)
        .await
        .expect("the mismatched grant should be stored");
    let mismatched = json!({
        "wallet_id": "wallet-grant",
        "sign_id": "d4".repeat(32),
        "digest": digest,
        "counterparty": 0,
    });
    let (status, _) = post_with_headers(
        &app,
        "/v1/sign/session",
        mismatched.clone(),
        device_headers(
            "/v1/sign/session",
            &mismatched,
            &device_key,
            "grant-mismatch",
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a mismatched grant must fail"
    );

    // Driving the recovery share needs a `recovery` grant; a `sign` grant must not open it.
    let recovery_id = "e5".repeat(32);
    let recovery = json!({
        "wallet_id": "wallet-grant",
        "sign_id": recovery_id,
        "digest": digest,
        "counterparty": 1,
    });
    store
        .put_passkey_authorization("wallet-grant", "sign", &recovery_id, &digest, 300)
        .await
        .expect("the sign grant should be stored");
    let (status, _) = post_with_headers(
        &app,
        "/v1/sign/session",
        recovery.clone(),
        device_headers(
            "/v1/sign/session",
            &recovery,
            &device_key,
            "recovery-wrong-purpose",
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a sign grant must not open a recovery session"
    );
    store
        .put_passkey_authorization("wallet-grant", "recovery", &recovery_id, &digest, 300)
        .await
        .expect("the recovery grant should be stored");
    let (status, _) = post_with_headers(
        &app,
        "/v1/sign/session",
        recovery.clone(),
        device_headers(
            "/v1/sign/session",
            &recovery,
            &device_key,
            "recovery-right-purpose",
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a recovery grant must open a recovery session"
    );
}

// ---------------------------------------------------------------------------------------------
// Distributed reshare (docs/adr/0007-distributed-reshare.md)
// ---------------------------------------------------------------------------------------------

const RESHARE_WALLET: &str = "wallet-reshare";

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn public_key_from_hex(value: &str) -> PublicKey {
    let mut key = [0u8; 33];
    for (i, slot) in key.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).expect("hex");
    }
    PublicKey(key)
}

/// A server, its store, and a registered device key for `wallet`.
async fn wallet_with_device(wallet: &str) -> (axum::Router, Store, SigningKey) {
    let store = Store::open("sqlite::memory:")
        .await
        .expect("the database should open");
    let app = router(AppState {
        store: store.clone(),
        sealing: SealingKey::new(&[42u8; 32]),
        passkey: PasskeyConfig::new("localhost", "http://localhost:8080")
            .expect("test passkey configuration"),
        recovery: RecoveryConfig::default(),
    });
    let device_key = SigningKey::from_bytes((&[7u8; 32]).into()).expect("device key");
    let registered = hex_of(
        device_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let (status, _) = post(
        &app,
        "/v1/device-key",
        json!({ "wallet_id": wallet, "public_key": registered }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    (app, store, device_key)
}

/// Authorizes one reshare the way a verified passkey assertion would.
async fn grant_reshare(store: &Store, wallet: &str, public_key: &PublicKey, id: &[u8; 32]) {
    store
        .put_passkey_authorization(
            wallet,
            "recovery",
            &hex_of(id),
            &mpc_server::reshare::grant_digest(&public_key.0, id),
            300,
        )
        .await
        .expect("the reshare authorization should be stored");
}

/// Posts with a device proof. Every call gets its own nonce, so a retry with the same arguments
/// is judged on its merits and not rejected as a replay.
async fn signed_post(
    app: &axum::Router,
    device_key: &SigningKey,
    path: &str,
    body: Value,
    nonce: &str,
) -> (StatusCode, Value) {
    static CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let unique = format!(
        "{nonce}-{}",
        CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    post_with_headers(
        app,
        path,
        body.clone(),
        device_headers(path, &body, device_key, &unique),
    )
    .await
}

/// Runs the extension's side of a reshare (the survivor B and the joiner A') against the server.
///
/// Returns the HTTP status of the last request and, when the server staged its share, the new
/// extension shares `[A', B']` with the public key the server reported.
async fn run_reshare(
    app: &axum::Router,
    device_key: &SigningKey,
    wallet: &str,
    id: [u8; 32],
    old_b: &KeyShare,
    public_key: &PublicKey,
) -> (StatusCode, Option<(Vec<KeyShare>, String)>) {
    let id_hex = hex_of(&id);
    let survivors = [PartyId(1), PartyId(SERVER_PARTY)];
    let (joiner, mut in_flight) =
        DkgParty::start_reshare(PartyId(0), &id, &ReshareRole::Joiner, public_key)
            .expect("the joiner should start");
    let (survivor, more) = DkgParty::start_reshare(
        PartyId(1),
        &id,
        &ReshareRole::Survivor {
            share: old_b,
            survivors,
        },
        public_key,
    )
    .expect("the survivor should start");
    in_flight.extend(more);
    let mut local = vec![joiner, survivor];

    let (status, body) = signed_post(
        app,
        device_key,
        "/v1/reshare/session",
        json!({ "wallet_id": wallet, "reshare_id": id_hex }),
        &format!("{id_hex}-start"),
    )
    .await;
    if status != StatusCode::OK {
        return (status, None);
    }
    for envelope in body["envelopes"].as_array().expect("envelopes") {
        in_flight.push(from_wire(envelope));
    }

    let mut shares = Vec::new();
    for round in 0..4 {
        let mut next: Vec<Envelope> = Vec::new();
        for party in &mut local {
            let me = party.party();
            let inbox: Vec<Envelope> = in_flight
                .iter()
                .filter(|e| e.from != me && e.to.is_none_or(|to| to == me))
                .cloned()
                .collect();
            match party.advance(&inbox).expect("the round should advance") {
                Progress::Send(outgoing) => next.extend(outgoing),
                Progress::Done { share, .. } => shares.push(share),
            }
        }

        let for_server: Vec<Value> = in_flight
            .iter()
            .filter(|e| {
                e.from != PartyId(SERVER_PARTY) && e.to.is_none_or(|to| to.0 == SERVER_PARTY)
            })
            .map(to_wire)
            .collect();
        let (status, body) = signed_post(
            app,
            device_key,
            "/v1/reshare/round",
            json!({ "wallet_id": wallet, "reshare_id": id_hex, "envelopes": for_server }),
            &format!("{id_hex}-round-{round}"),
        )
        .await;
        if status != StatusCode::OK {
            return (status, None);
        }
        match body["state"].as_str().expect("state") {
            "inProgress" => {
                for envelope in body["envelopes"].as_array().expect("envelopes") {
                    next.push(from_wire(envelope));
                }
            }
            "staged" => {
                let reported = body["public_key"].as_str().expect("public_key").to_string();
                shares.sort_by_key(|s| s.party().0);
                return (status, Some((shares, reported)));
            }
            other => panic!("unknown state: {other}"),
        }
        in_flight = next;
    }
    panic!("the reshare did not finish in four rounds");
}

/// Signs with the extension's party-0 share and the server over HTTP, and checks the signature
/// against `public_key`.
async fn sign_and_check(
    app: &axum::Router,
    store: &Store,
    device_key: &SigningKey,
    wallet: &str,
    extension_share: &KeyShare,
    public_key: &PublicKey,
    tag: u8,
) -> bool {
    let sign_id = [tag; 32];
    let sign_hex = hex_of(&sign_id);
    let digest = [tag ^ 0x55; 32];
    let digest_hex = hex_of(&digest);
    store
        .put_passkey_authorization(wallet, "sign", &sign_hex, &digest_hex, 300)
        .await
        .expect("the signing authorization should be stored");

    let (mut extension, mut in_flight) =
        SignParty::start(extension_share, PartyId(SERVER_PARTY), &sign_id, &digest)
            .expect("the party should start");
    let start = json!({
        "wallet_id": wallet, "sign_id": sign_hex, "digest": digest_hex, "counterparty": 0,
    });
    let (status, body) = signed_post(
        app,
        device_key,
        "/v1/sign/session",
        start,
        &format!("sign-{tag}-start"),
    )
    .await;
    if status != StatusCode::OK {
        return false;
    }
    for envelope in body["envelopes"].as_array().expect("envelopes") {
        in_flight.push(from_wire(envelope));
    }

    for round in 0..4 {
        let mut next: Vec<Envelope> = Vec::new();
        let inbox: Vec<Envelope> = in_flight
            .iter()
            .filter(|e| e.from != PartyId(0) && e.to.is_none_or(|to| to == PartyId(0)))
            .cloned()
            .collect();
        // Shares from different epochs fail the multiplication check and abort here. That is a
        // failed signature, not a broken test.
        match extension.advance(&inbox) {
            Ok(SignProgress::Send(outgoing)) => next.extend(outgoing),
            Ok(SignProgress::Done(_)) => {}
            Err(_) => return false,
        }

        let for_server: Vec<Value> = in_flight
            .iter()
            .filter(|e| {
                e.from != PartyId(SERVER_PARTY) && e.to.is_none_or(|to| to.0 == SERVER_PARTY)
            })
            .map(to_wire)
            .collect();
        let (status, body) = signed_post(
            app,
            device_key,
            "/v1/sign/round",
            json!({ "wallet_id": wallet, "sign_id": sign_hex, "envelopes": for_server }),
            &format!("sign-{tag}-round-{round}"),
        )
        .await;
        if status != StatusCode::OK {
            return false;
        }
        match body["state"].as_str().expect("state") {
            "inProgress" => {
                for envelope in body["envelopes"].as_array().expect("envelopes") {
                    next.push(from_wire(envelope));
                }
            }
            "completed" => {
                let raw = body["signature"].as_str().expect("signature");
                let mut bytes = [0u8; 65];
                for (i, slot) in bytes.iter_mut().enumerate() {
                    *slot = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16).expect("hex");
                }
                let mut r = [0u8; 32];
                let mut s = [0u8; 32];
                r.copy_from_slice(&bytes[..32]);
                s.copy_from_slice(&bytes[32..64]);
                return mpc_core::verify(
                    public_key,
                    &digest,
                    &mpc_core::Signature {
                        r,
                        s,
                        recovery_id: bytes[64],
                    },
                )
                .unwrap_or(false);
            }
            other => panic!("unknown state: {other}"),
        }
        in_flight = next;
    }
    false
}

#[tokio::test]
async fn reshare_replaces_the_servers_share_and_keeps_the_key() {
    let (app, store, device_key) = wallet_with_device(RESHARE_WALLET).await;
    let (old, public_key_hex) = provision(&app, RESHARE_WALLET, 0xd1).await;
    let public_key = public_key_from_hex(&public_key_hex);
    let before = store
        .key_share(RESHARE_WALLET)
        .await
        .expect("the share should load")
        .expect("the wallet should have a share");

    // A is lost. B survives in the recovery file, and C is on the server.
    let id = [0xe1u8; 32];
    grant_reshare(&store, RESHARE_WALLET, &public_key, &id).await;
    let (status, outcome) =
        run_reshare(&app, &device_key, RESHARE_WALLET, id, &old[1], &public_key).await;
    assert_eq!(status, StatusCode::OK);
    let (fresh, reported) = outcome.expect("the server should stage its share");
    assert_eq!(reported, public_key_hex, "the address must not change");

    // Staged is not live: the previous share is untouched until the commit.
    let staged = store
        .key_share(RESHARE_WALLET)
        .await
        .expect("the share should load")
        .expect("the wallet should have a share");
    assert_eq!(
        staged.ciphertext, before.ciphertext,
        "staging must not touch the live share"
    );

    let commit = json!({ "wallet_id": RESHARE_WALLET, "reshare_id": hex_of(&id) });
    let (status, body) = signed_post(
        &app,
        &device_key,
        "/v1/reshare/commit",
        commit.clone(),
        "commit-1",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the commit should succeed: {body}"
    );

    let after = store
        .key_share(RESHARE_WALLET)
        .await
        .expect("the share should load")
        .expect("the wallet should have a share");
    assert_ne!(
        after.ciphertext, before.ciphertext,
        "the server must hold a new share"
    );
    assert_eq!(
        store
            .public_key(RESHARE_WALLET)
            .await
            .expect("key")
            .expect("key"),
        public_key.0.to_vec(),
        "the stored public key must not change"
    );

    // A second commit finds nothing staged.
    let (status, _) =
        signed_post(&app, &device_key, "/v1/reshare/commit", commit, "commit-2").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The fresh A' signs with the fresh C, and the signature verifies under the same key.
    assert!(
        sign_and_check(
            &app,
            &store,
            &device_key,
            RESHARE_WALLET,
            &fresh[0],
            &public_key,
            0x31
        )
        .await,
        "the new extension share and the new server share must sign"
    );

    // The lost A no longer signs with the server's new share.
    assert!(
        !sign_and_check(
            &app,
            &store,
            &device_key,
            RESHARE_WALLET,
            &old[0],
            &public_key,
            0x32
        )
        .await,
        "the lost share must not sign with the new server share"
    );
}

#[tokio::test]
async fn aborting_a_reshare_leaves_the_previous_share_live() {
    let (app, store, device_key) = wallet_with_device(RESHARE_WALLET).await;
    let (old, public_key_hex) = provision(&app, RESHARE_WALLET, 0xd2).await;
    let public_key = public_key_from_hex(&public_key_hex);
    let before = store
        .key_share(RESHARE_WALLET)
        .await
        .expect("the share should load")
        .expect("the wallet should have a share");

    let id = [0xe2u8; 32];
    grant_reshare(&store, RESHARE_WALLET, &public_key, &id).await;
    let (status, outcome) =
        run_reshare(&app, &device_key, RESHARE_WALLET, id, &old[1], &public_key).await;
    assert_eq!(status, StatusCode::OK);
    assert!(outcome.is_some());

    let finish = json!({ "wallet_id": RESHARE_WALLET, "reshare_id": hex_of(&id) });
    let (status, _) = signed_post(
        &app,
        &device_key,
        "/v1/reshare/abort",
        finish.clone(),
        "abort-1",
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Nothing is left to commit, and the old shares still work together.
    let (status, _) = signed_post(
        &app,
        &device_key,
        "/v1/reshare/commit",
        finish,
        "commit-after-abort",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let after = store
        .key_share(RESHARE_WALLET)
        .await
        .expect("the share should load")
        .expect("the wallet should have a share");
    assert_eq!(
        after.ciphertext, before.ciphertext,
        "an abort must not touch the live share"
    );
    assert!(
        sign_and_check(
            &app,
            &store,
            &device_key,
            RESHARE_WALLET,
            &old[0],
            &public_key,
            0x33
        )
        .await,
        "the previous shares must still sign"
    );
}

#[tokio::test]
async fn reshare_needs_a_matching_one_use_recovery_grant() {
    let (app, store, device_key) = wallet_with_device(RESHARE_WALLET).await;
    let (old, public_key_hex) = provision(&app, RESHARE_WALLET, 0xd3).await;
    let public_key = public_key_from_hex(&public_key_hex);
    let id = [0xe3u8; 32];

    // No grant at all.
    let (status, outcome) =
        run_reshare(&app, &device_key, RESHARE_WALLET, id, &old[1], &public_key).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a reshare without a grant must fail"
    );
    assert!(outcome.is_none());

    // A `sign` grant is the wrong policy.
    store
        .put_passkey_authorization(
            RESHARE_WALLET,
            "sign",
            &hex_of(&id),
            &mpc_server::reshare::grant_digest(&public_key.0, &id),
            300,
        )
        .await
        .expect("the grant should be stored");
    let (status, _) =
        run_reshare(&app, &device_key, RESHARE_WALLET, id, &old[1], &public_key).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a sign grant must not start a reshare"
    );

    // A recovery grant bound to another digest does not fit.
    store
        .put_passkey_authorization(
            RESHARE_WALLET,
            "recovery",
            &hex_of(&id),
            &"00".repeat(32),
            300,
        )
        .await
        .expect("the grant should be stored");
    let (status, _) =
        run_reshare(&app, &device_key, RESHARE_WALLET, id, &old[1], &public_key).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a grant for another digest must fail"
    );

    // The right grant works once and only once.
    grant_reshare(&store, RESHARE_WALLET, &public_key, &id).await;
    let (status, outcome) =
        run_reshare(&app, &device_key, RESHARE_WALLET, id, &old[1], &public_key).await;
    assert_eq!(status, StatusCode::OK);
    assert!(outcome.is_some());
    let (status, _) =
        run_reshare(&app, &device_key, RESHARE_WALLET, id, &old[1], &public_key).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a grant must be one-use");
}

#[tokio::test]
async fn reshare_endpoints_need_the_device_key() {
    let (app, _store, _device_key) = wallet_with_device(RESHARE_WALLET).await;
    for path in [
        "/v1/reshare/session",
        "/v1/reshare/round",
        "/v1/reshare/commit",
        "/v1/reshare/abort",
    ] {
        let body =
            json!({ "wallet_id": RESHARE_WALLET, "reshare_id": "ab".repeat(32), "envelopes": [] });
        let (status, _) = post(&app, path, body).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{path} must require a device proof"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Recovery start and device key replacement (docs/adr/0008-recovery-start-and-device-key-replacement.md)
// ---------------------------------------------------------------------------------------------

const RECOVERY_WALLET: &str = "wallet-recovery";

fn device_key_of(seed: u8) -> SigningKey {
    SigningKey::from_bytes((&[seed; 32]).into()).expect("device key")
}

fn public_hex(key: &SigningKey) -> String {
    hex_of(key.verifying_key().to_encoded_point(false).as_bytes())
}

/// A server whose wallet has a key share, a passkey and a registered device key, and the current
/// device's key. The share and the passkey are stand-ins: recovery never opens either.
async fn recovery_fixture(cooling_seconds: i64) -> (axum::Router, Store, SigningKey) {
    let store = Store::open("sqlite::memory:")
        .await
        .expect("the database should open");
    let app = router(AppState {
        store: store.clone(),
        sealing: SealingKey::new(&[42u8; 32]),
        passkey: PasskeyConfig::new("localhost", "http://localhost:8080")
            .expect("test passkey configuration"),
        recovery: RecoveryConfig { cooling_seconds },
    });
    store
        .finish_dkg(
            "recovery-dkg",
            RECOVERY_WALLET,
            &mpc_server::crypto::Sealed {
                ciphertext: vec![1],
                nonce: vec![2],
            },
            &[3u8; 33],
        )
        .await
        .expect("the wallet should exist");
    store
        .put_passkey_credential(RECOVERY_WALLET, b"{}", 0)
        .await
        .expect("the passkey should be stored");
    let current = device_key_of(31);
    let (status, _) = post(
        &app,
        "/v1/device-key",
        json!({ "wallet_id": RECOVERY_WALLET, "public_key": public_hex(&current) }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    (app, store, current)
}

/// Asks to recover onto `new_key`, with no device proof. Returns the request id.
async fn ask_to_recover(app: &axum::Router, new_key: &SigningKey) -> (StatusCode, Value) {
    post(
        app,
        "/v1/recovery/request",
        json!({ "wallet_id": RECOVERY_WALLET, "device_public_key": public_hex(new_key) }),
    )
    .await
}

fn request_id_bytes(request_id: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&request_id[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}

/// Stores the passkey approval a verified browser ceremony would leave for this request.
async fn approve(store: &Store, request_id: &str, new_key: &SigningKey) {
    let digest = mpc_server::recovery::assertion_digest(
        RECOVERY_WALLET,
        new_key.verifying_key().to_encoded_point(false).as_bytes(),
        &request_id_bytes(request_id),
    );
    store
        .put_passkey_authorization(RECOVERY_WALLET, "recovery", request_id, &digest, 300)
        .await
        .expect("the approval should be stored");
}

async fn call_as(
    app: &axum::Router,
    key: &SigningKey,
    path: &str,
    request_id: &str,
) -> (StatusCode, Value) {
    signed_post(
        app,
        key,
        path,
        json!({ "wallet_id": RECOVERY_WALLET, "request_id": request_id }),
        "recovery",
    )
    .await
}

#[tokio::test]
async fn recovery_replaces_the_device_key_once_approved_and_waited_out() {
    let (app, store, current) = recovery_fixture(0).await;
    let new_key = device_key_of(32);

    let (status, requested) = ask_to_recover(&app, &new_key).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the request should be recorded: {requested}"
    );
    let request_id = requested["request_id"]
        .as_str()
        .expect("request id")
        .to_owned();
    assert!(requested["handoff_token"]
        .as_str()
        .is_some_and(|t| !t.is_empty()));

    // Before the passkey approves, the request only waits, and it cannot be completed.
    let (_, waiting) = call_as(&app, &new_key, "/v1/recovery/status", &request_id).await;
    assert_eq!(waiting["state"], "awaitingAssertion");
    let (status, _) = call_as(&app, &new_key, "/v1/recovery/complete", &request_id).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an unapproved request must not complete"
    );

    approve(&store, &request_id, &new_key).await;
    let (status, approved) = call_as(&app, &new_key, "/v1/recovery/status", &request_id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        approved["state"], "ready",
        "a zero cooling period is ready at once: {approved}"
    );

    let (status, body) = call_as(&app, &new_key, "/v1/recovery/complete", &request_id).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "completing failed: {body}");

    // The new key now speaks for the wallet, and the old one no longer does.
    let list = json!({ "wallet_id": RECOVERY_WALLET });
    let (status, _) =
        signed_post(&app, &new_key, "/v1/recovery/pending", list.clone(), "new").await;
    assert_eq!(status, StatusCode::OK, "the new key should be accepted");
    let (status, _) = signed_post(&app, &current, "/v1/recovery/pending", list, "old").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the old key must be replaced"
    );

    // A completed request cannot be completed twice.
    let (status, _) = call_as(&app, &new_key, "/v1/recovery/complete", &request_id).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn recovery_waits_out_the_cooling_off_period_before_replacing_anything() {
    let (app, store, current) = recovery_fixture(3600).await;
    let new_key = device_key_of(33);
    let (_, requested) = ask_to_recover(&app, &new_key).await;
    let request_id = requested["request_id"]
        .as_str()
        .expect("request id")
        .to_owned();

    approve(&store, &request_id, &new_key).await;
    let (_, cooling) = call_as(&app, &new_key, "/v1/recovery/status", &request_id).await;
    assert_eq!(cooling["state"], "cooling", "{cooling}");
    let ready_at = cooling["ready_at"].as_i64().expect("ready_at");
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    assert!(
        (ready_at - now - 3600).abs() <= 5,
        "ready_at should be an hour away"
    );

    let (status, body) = call_as(&app, &new_key, "/v1/recovery/complete", &request_id).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "completing early must fail: {body}"
    );

    // Nothing changed: the current device key still works.
    let (status, _) = signed_post(
        &app,
        &current,
        "/v1/recovery/pending",
        json!({ "wallet_id": RECOVERY_WALLET }),
        "still",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the current key must keep working while waiting"
    );
}

#[tokio::test]
async fn an_approval_for_another_key_does_not_start_the_wait() {
    let (app, store, _current) = recovery_fixture(3600).await;
    let honest = device_key_of(34);
    let attacker = device_key_of(35);
    let (_, honest_request) = ask_to_recover(&app, &honest).await;
    let honest_id = honest_request["request_id"]
        .as_str()
        .expect("id")
        .to_owned();
    let (_, attacker_request) = ask_to_recover(&app, &attacker).await;
    let attacker_id = attacker_request["request_id"]
        .as_str()
        .expect("id")
        .to_owned();

    // The passkey approved the honest request, bound to the honest key.
    approve(&store, &honest_id, &honest).await;

    let (_, state) = call_as(&app, &attacker, "/v1/recovery/status", &attacker_id).await;
    assert_eq!(
        state["state"], "awaitingAssertion",
        "someone else's approval must not start this request's wait: {state}"
    );

    // Nor can the attacker's key ask about the honest request.
    let (status, _) = call_as(&app, &attacker, "/v1/recovery/status", &honest_id).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a request answers only to its own key"
    );

    let (_, state) = call_as(&app, &honest, "/v1/recovery/status", &honest_id).await;
    assert_eq!(state["state"], "cooling");
}

#[tokio::test]
async fn a_recovery_needs_a_wallet_and_a_passkey() {
    let (app, store, _current) = recovery_fixture(0).await;
    let new_key = device_key_of(36);

    let (status, _) = post(
        &app,
        "/v1/recovery/request",
        json!({ "wallet_id": "no-such-wallet", "device_public_key": public_hex(&new_key) }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A wallet with a key share but no passkey has nothing that could approve a recovery.
    store
        .finish_dkg(
            "no-passkey-dkg",
            "wallet-no-passkey",
            &mpc_server::crypto::Sealed {
                ciphertext: vec![1],
                nonce: vec![2],
            },
            &[3u8; 33],
        )
        .await
        .expect("the wallet should exist");
    let (status, _) = post(
        &app,
        "/v1/recovery/request",
        json!({ "wallet_id": "wallet-no-passkey", "device_public_key": public_hex(&new_key) }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "no passkey means no recovery"
    );
}

#[tokio::test]
async fn a_recovery_request_must_carry_a_real_device_key() {
    let (app, _store, _current) = recovery_fixture(0).await;
    for bad in [
        "not-hex".to_owned(),
        format!("02{}", "ab".repeat(64)),
        // The right shape, but not a point on the curve.
        format!("04{}", "00".repeat(64)),
    ] {
        let (status, body) = post(
            &app,
            "/v1/recovery/request",
            json!({ "wallet_id": RECOVERY_WALLET, "device_public_key": bad }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{bad} was accepted: {body}"
        );
    }
}

#[tokio::test]
async fn a_wallet_may_open_only_five_recovery_requests_an_hour() {
    let (app, _store, _current) = recovery_fixture(0).await;
    for i in 0..5u8 {
        let (status, body) = ask_to_recover(&app, &device_key_of(40 + i)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "request {i} should be allowed: {body}"
        );
    }
    let (status, _) = ask_to_recover(&app, &device_key_of(50)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn the_current_device_sees_a_pending_recovery_and_can_cancel_it() {
    let (app, store, current) = recovery_fixture(3600).await;
    let new_key = device_key_of(37);
    let (_, requested) = ask_to_recover(&app, &new_key).await;
    let request_id = requested["request_id"].as_str().expect("id").to_owned();

    let list = json!({ "wallet_id": RECOVERY_WALLET });
    // Before the passkey approves there is nothing to warn about.
    let (_, none) = signed_post(&app, &current, "/v1/recovery/pending", list.clone(), "l1").await;
    assert_eq!(none["pending"].as_array().expect("list").len(), 0);

    approve(&store, &request_id, &new_key).await;
    call_as(&app, &new_key, "/v1/recovery/status", &request_id).await;

    let (status, seen) = signed_post(&app, &current, "/v1/recovery/pending", list, "l2").await;
    assert_eq!(status, StatusCode::OK);
    let pending = seen["pending"].as_array().expect("list");
    assert_eq!(pending.len(), 1, "{seen}");
    assert_eq!(pending[0]["request_id"], request_id.as_str());
    assert_eq!(
        pending[0]["key_fingerprint"],
        mpc_server::recovery::key_fingerprint(
            new_key.verifying_key().to_encoded_point(false).as_bytes()
        ),
        "the fingerprint lets the owner recognise the key"
    );

    let (status, _) = call_as(&app, &current, "/v1/recovery/cancel", &request_id).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the current device may object"
    );

    let (_, after) = call_as(&app, &new_key, "/v1/recovery/status", &request_id).await;
    assert_eq!(after["state"], "cancelled");
    let (status, _) = call_as(&app, &new_key, "/v1/recovery/complete", &request_id).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a cancelled recovery must not complete"
    );
}

#[tokio::test]
async fn only_the_wallet_or_the_requester_may_cancel() {
    let (app, _store, _current) = recovery_fixture(3600).await;
    let new_key = device_key_of(38);
    let stranger = device_key_of(39);
    let (_, requested) = ask_to_recover(&app, &new_key).await;
    let request_id = requested["request_id"].as_str().expect("id").to_owned();

    let (status, _) = call_as(&app, &stranger, "/v1/recovery/cancel", &request_id).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a stranger must not cancel"
    );

    let (status, _) = call_as(&app, &new_key, "/v1/recovery/cancel", &request_id).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "the requester may withdraw");
}

#[tokio::test]
async fn only_one_recovery_may_wait_at_a_time_and_completing_ends_the_others() {
    let (app, store, _current) = recovery_fixture(0).await;
    let first = device_key_of(60);
    let second = device_key_of(61);
    let (_, a) = ask_to_recover(&app, &first).await;
    let a_id = a["request_id"].as_str().expect("id").to_owned();
    let (_, b) = ask_to_recover(&app, &second).await;
    let b_id = b["request_id"].as_str().expect("id").to_owned();
    approve(&store, &a_id, &first).await;
    approve(&store, &b_id, &second).await;

    // Both are approved, but with a zero period the first is ready at once and the second is
    // refused while the first is still cooling.
    let (_, first_state) = call_as(&app, &first, "/v1/recovery/status", &a_id).await;
    assert_eq!(first_state["state"], "ready");
    let (status, body) = call_as(&app, &second, "/v1/recovery/status", &b_id).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a second wait must be refused: {body}"
    );

    let (status, _) = call_as(&app, &first, "/v1/recovery/complete", &a_id).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The other request ended with it. Its own key can still ask, and is told so, but it cannot
    // finish, and the wallet's key did not become its key.
    let (status, ended) = call_as(&app, &second, "/v1/recovery/status", &b_id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        ended["state"], "cancelled",
        "the losing request must have ended: {ended}"
    );
    let (status, _) = call_as(&app, &second, "/v1/recovery/complete", &b_id).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a request that lost must not complete"
    );
    let (status, _) = signed_post(
        &app,
        &second,
        "/v1/recovery/pending",
        json!({ "wallet_id": RECOVERY_WALLET }),
        "loser",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the losing key must not speak for the wallet"
    );
}

#[tokio::test]
async fn recovery_status_needs_a_proof_from_the_requests_own_key() {
    let (app, _store, current) = recovery_fixture(0).await;
    let new_key = device_key_of(62);
    let (_, requested) = ask_to_recover(&app, &new_key).await;
    let request_id = requested["request_id"].as_str().expect("id").to_owned();

    // No proof at all.
    let (status, _) = post(
        &app,
        "/v1/recovery/status",
        json!({ "wallet_id": RECOVERY_WALLET, "request_id": request_id }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The wallet's current key is not the request's key.
    let (status, _) = call_as(&app, &current, "/v1/recovery/status", &request_id).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_wallet_can_ask_whether_it_has_a_passkey_but_only_with_its_device_key() {
    let (app, store, device_key) = wallet_with_device("wallet-registered").await;
    let ask = json!({ "wallet_id": "wallet-registered" });

    let (status, body) = signed_post(
        &app,
        &device_key,
        "/v1/passkeys/registered",
        ask.clone(),
        "a",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["registered"], false, "a new wallet has no passkey");

    store
        .put_passkey_credential("wallet-registered", b"{}", 0)
        .await
        .expect("the passkey should be stored");
    let (_, body) = signed_post(
        &app,
        &device_key,
        "/v1/passkeys/registered",
        ask.clone(),
        "b",
    )
    .await;
    assert_eq!(body["registered"], true);

    // Nobody else may ask, so this does not tell a stranger which wallets are ready to sign.
    let (status, _) = post(&app, "/v1/passkeys/registered", ask.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no proof must be refused");
    let stranger = device_key_of(77);
    let (status, _) = signed_post(&app, &stranger, "/v1/passkeys/registered", ask, "c").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "another key must be refused"
    );
}

// ---------------------------------------------------------------------------------------------
// Managing recoveries with the passkey alone (docs/adr/0009-managing-recoveries-with-the-passkey.md)
//
// A real assertion needs a registered authenticator, which these tests cannot fake, so they open a
// session through the store the way a verified assertion would. What they check is everything
// around it: nothing works without a session, a session belongs to one wallet, and the checks the
// page depends on hold. The assertion itself is exercised by the browser smoke tests.
// ---------------------------------------------------------------------------------------------

const MANAGE_ORIGIN: &str = "http://localhost:8080";

/// Opens a session as a verified assertion would, and returns the token a browser would hold.
async fn open_session(store: &Store, wallet: &str, ttl: i64) -> String {
    use sha2::{Digest, Sha256};
    let token = format!("{:0>64}", format!("{wallet}-session"));
    let token = hex_of(token.as_bytes())[..64].to_owned();
    store
        .open_manage_session(&Sha256::digest(token.as_bytes()), wallet, ttl)
        .await
        .expect("the session should open");
    token
}

async fn manage_post(
    app: &axum::Router,
    path: &str,
    body: Value,
    cookie: Option<&str>,
    origin: Option<&str>,
) -> (StatusCode, Value) {
    let mut headers = HeaderMap::new();
    if let Some(token) = cookie {
        headers.insert(
            "cookie",
            HeaderValue::from_str(&format!("mpc_manage_session={token}")).expect("cookie header"),
        );
    }
    if let Some(origin) = origin {
        headers.insert(
            "origin",
            HeaderValue::from_str(origin).expect("origin header"),
        );
    }
    post_with_headers(app, path, body, headers).await
}

/// A waiting recovery on the fixture wallet, cooling and past its passkey approval.
async fn waiting_recovery(app: &axum::Router, store: &Store, seed: u8) -> (String, SigningKey) {
    let key = device_key_of(seed);
    let (_, requested) = ask_to_recover(app, &key).await;
    let request_id = requested["request_id"].as_str().expect("id").to_owned();
    approve(store, &request_id, &key).await;
    call_as(app, &key, "/v1/recovery/status", &request_id).await;
    (request_id, key)
}

#[tokio::test]
async fn cancelling_needs_a_live_session_and_the_pages_own_origin() {
    let (app, store, _current) = recovery_fixture(3600).await;
    let (request_id, key) = waiting_recovery(&app, &store, 90).await;
    let body = json!({ "request_id": request_id });

    // No session at all.
    let (status, _) = manage_post(
        &app,
        "/manage/cancel",
        body.clone(),
        None,
        Some(MANAGE_ORIGIN),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "no session must not cancel"
    );

    // A made-up token.
    let (status, _) = manage_post(
        &app,
        "/manage/cancel",
        body.clone(),
        Some(&"ab".repeat(32)),
        Some(MANAGE_ORIGIN),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an unknown token must not cancel"
    );

    // A real session, but the request comes from another site or from no page at all.
    let token = open_session(&store, RECOVERY_WALLET, 300).await;
    let (status, _) = manage_post(
        &app,
        "/manage/cancel",
        body.clone(),
        Some(&token),
        Some("https://evil.example"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a foreign origin must not cancel"
    );
    let (status, _) = manage_post(&app, "/manage/cancel", body.clone(), Some(&token), None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a request with no origin must not cancel"
    );

    // Nothing was cancelled by any of that.
    let (_, still) = call_as(&app, &key, "/v1/recovery/status", &request_id).await;
    assert_eq!(
        still["state"], "cooling",
        "the recovery must still be waiting: {still}"
    );

    // With the session and the right origin it works, and reports what is left.
    let (status, view) = manage_post(
        &app,
        "/manage/cancel",
        body,
        Some(&token),
        Some(MANAGE_ORIGIN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["recoveries"].as_array().expect("list").len(), 0);
    let (_, after) = call_as(&app, &key, "/v1/recovery/status", &request_id).await;
    assert_eq!(after["state"], "cancelled");
}

#[tokio::test]
async fn a_session_cancels_only_its_own_wallets_recoveries() {
    let (app, store, _current) = recovery_fixture(3600).await;
    let (request_id, key) = waiting_recovery(&app, &store, 91).await;

    // Another wallet's passkey has a session, but the recovery is not that wallet's.
    let other = open_session(&store, "some-other-wallet", 300).await;
    let (status, _) = manage_post(
        &app,
        "/manage/cancel",
        json!({ "request_id": request_id }),
        Some(&other),
        Some(MANAGE_ORIGIN),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "another wallet must not reach this recovery"
    );
    let (_, still) = call_as(&app, &key, "/v1/recovery/status", &request_id).await;
    assert_eq!(still["state"], "cooling");
}

#[tokio::test]
async fn an_expired_session_cancels_nothing() {
    let (app, store, _current) = recovery_fixture(3600).await;
    let (request_id, key) = waiting_recovery(&app, &store, 92).await;

    // A session that ended a minute ago.
    let token = open_session(&store, RECOVERY_WALLET, -60).await;
    let (status, _) = manage_post(
        &app,
        "/manage/cancel",
        json!({ "request_id": request_id }),
        Some(&token),
        Some(MANAGE_ORIGIN),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an expired session must not cancel"
    );
    let (_, still) = call_as(&app, &key, "/v1/recovery/status", &request_id).await;
    assert_eq!(still["state"], "cooling");
}

#[tokio::test]
async fn the_management_session_endpoint_refuses_an_unverified_assertion() {
    let (app, _store, _current) = recovery_fixture(3600).await;

    // A challenge can be had without any proof: it names no wallet and reveals nothing.
    let mut request = Request::builder().method("GET").uri("/manage/challenge");
    request = request.header("accept", "application/json");
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).expect("request"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    let challenge: Value = serde_json::from_slice(&bytes).expect("json");
    let challenge_id = challenge["challenge_id"]
        .as_str()
        .expect("challenge id")
        .to_owned();
    assert!(challenge["options"]["challenge"].is_string());
    assert!(
        challenge["options"]
            .get("allowCredentials")
            .is_none_or(|list| list.as_array().is_some_and(Vec::is_empty)),
        "a usernameless challenge must not name a credential: {challenge}"
    );

    // Answering it with something that is not an assertion fails and opens no session.
    let (status, body) = manage_post(
        &app,
        "/manage/session",
        json!({ "challenge_id": challenge_id, "credential": {} }),
        None,
        Some(MANAGE_ORIGIN),
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "a bogus assertion must fail: {status} {body}"
    );

    // And a foreign origin is refused before anything else is looked at.
    let (status, _) = manage_post(
        &app,
        "/manage/session",
        json!({ "challenge_id": "x", "credential": {} }),
        None,
        Some("https://evil.example"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a foreign origin must be refused"
    );

    // The challenge is one-use: it is gone after that attempt.
    let (status, _) = manage_post(
        &app,
        "/manage/session",
        json!({ "challenge_id": challenge_id, "credential": {} }),
        None,
        Some(MANAGE_ORIGIN),
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "a used challenge must not work again"
    );
}

#[tokio::test]
async fn only_a_limited_number_of_management_challenges_may_wait() {
    let (app, _store, _current) = recovery_fixture(3600).await;
    let challenge = || async {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/manage/challenge")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response")
            .status()
    };

    // The page asks without any proof, so the number waiting at once has to be bounded. Ask through
    // the endpoint, since that is what stores them, until it refuses.
    let mut accepted = 0;
    let mut refused_at = None;
    for i in 0..400 {
        match challenge().await {
            StatusCode::OK => accepted += 1,
            StatusCode::TOO_MANY_REQUESTS => {
                refused_at = Some(i);
                break;
            }
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!(refused_at, Some(200), "the 201st challenge must be refused");
    assert_eq!(accepted, 200);
}

#[tokio::test]
async fn the_management_page_is_served_with_the_same_protections_as_the_ceremony_page() {
    let (app, _store, _current) = recovery_fixture(3600).await;
    for path in ["/manage", "/manage.js"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let headers = response.headers();
        assert_eq!(
            headers["cache-control"], "no-store, max-age=0",
            "{path} must not be cached"
        );
        let csp = headers["content-security-policy"].to_str().expect("csp");
        assert!(
            csp.contains("script-src 'self'") && !csp.contains("unsafe-inline"),
            "{path}: {csp}"
        );
        assert_eq!(headers["x-content-type-options"], "nosniff");
    }
}
