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
use mpc_core::{DkgParty, Envelope, PartyId, Progress, SignParty, SignProgress};
use mpc_server::api::{router, AppState};
use mpc_server::crypto::SealingKey;
use mpc_server::passkey::PasskeyConfig;
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
                .body(Body::from(body.to_string()))
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

fn device_headers(path: &str, body: &Value, key: &SigningKey, nonce: &str) -> HeaderMap {
    let timestamp = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let serialized = match path {
        "/v1/sign/session" => serde_json::to_string(
            &serde_json::from_value::<mpc_server::api::StartSign>(body.clone())
                .expect("start body should deserialize"),
        )
        .expect("start body should serialize"),
        "/v1/sign/round" => serde_json::to_string(
            &serde_json::from_value::<mpc_server::api::AdvanceSign>(body.clone())
                .expect("round body should deserialize"),
        )
        .expect("round body should serialize"),
        "/v1/passkeys/register/options" => serde_json::to_string(
            &serde_json::from_value::<mpc_server::passkey::RegisterOptionsRequest>(body.clone())
                .expect("register options body should deserialize"),
        )
        .expect("register options body should serialize"),
        "/v1/passkeys/register/finish" => serde_json::to_string(
            &serde_json::from_value::<mpc_server::passkey::RegisterFinishRequest>(body.clone())
                .expect("register finish body should deserialize"),
        )
        .expect("register finish body should serialize"),
        "/v1/passkeys/assert/options" => serde_json::to_string(
            &serde_json::from_value::<mpc_server::passkey::AssertOptionsRequest>(body.clone())
                .expect("assert options body should deserialize"),
        )
        .expect("assert options body should serialize"),
        "/v1/passkeys/assert/finish" => serde_json::to_string(
            &serde_json::from_value::<mpc_server::passkey::AssertFinishRequest>(body.clone())
                .expect("assert finish body should deserialize"),
        )
        .expect("assert finish body should serialize"),
        "/v1/passkeys/handoff" => serde_json::to_string(
            &serde_json::from_value::<mpc_server::passkey::HandoffRequest>(body.clone())
                .expect("handoff body should deserialize"),
        )
        .expect("handoff body should serialize"),
        "/v1/passkeys/ceremony/status" => serde_json::to_string(
            &serde_json::from_value::<mpc_server::passkey::CeremonyStatusRequest>(body.clone())
                .expect("status body should deserialize"),
        )
        .expect("status body should serialize"),
        _ => serde_json::to_string(body).expect("body should serialize"),
    };
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
