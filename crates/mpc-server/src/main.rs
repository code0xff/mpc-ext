//! 서버 진입점.
//!
//! 역할은 셰어 C 보관, DKG 참여, 복구 모드 서명 참여뿐이다.
//! **평시 서명에는 관여하지 않는다** (`docs/server.md`).

mod api;

use std::net::SocketAddr;

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let addr: SocketAddr = std::env::var("MPC_SERVER_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()?;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, docs = "/docs", "mpc-server listening");

    axum::serve(listener, api::router()).await?;
    Ok(())
}
