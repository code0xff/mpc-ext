//! The full flow with the server acting as a DKG party.
//!
//! The test drives the extension's two parties (A and B) while the server handles party C over
//! HTTP. It also confirms that the server's state survives a round trip through the database
//! between rounds.

// Panicking is how a test asserts. Production code keeps these lints.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use mpc_core::{DkgParty, Envelope, PartyId, Progress};
use mpc_server::api::{router, AppState};
use mpc_server::crypto::SealingKey;
use mpc_server::store::Store;
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
    })
}

async fn post(app: &axum::Router, path: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
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
