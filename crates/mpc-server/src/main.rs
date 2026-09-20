//! Server entry point.
//!
//! Its job is to store share C and to take part in DKG and in everyday and recovery signing
//! (`docs/adr/0005-share-placement.md`).

use std::net::SocketAddr;

use mpc_server::api::{router, AppState};
use mpc_server::crypto::SealingKey;
use mpc_server::passkey::PasskeyConfig;
use mpc_server::store::Store;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let database_url =
        std::env::var("MPC_SERVER_DATABASE").unwrap_or_else(|_| "sqlite://mpc-ext.db".into());
    let addr: SocketAddr = std::env::var("MPC_SERVER_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()?;

    let state = AppState {
        store: Store::open(&database_url).await?,
        sealing: SealingKey::from_env()?,
        passkey: PasskeyConfig::from_env()?,
        recovery: mpc_server::recovery::RecoveryConfig::from_env()?,
    };

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, docs = "/docs", "mpc-server listening");
    tracing::info!(rp_id = %state.passkey.rp_id, origin = %state.passkey.origin, "WebAuthn RP configured");
    tracing::info!(
        cooling_seconds = state.recovery.cooling_seconds,
        "recovery cooling-off period"
    );

    axum::serve(listener, router(state)).await?;
    Ok(())
}
