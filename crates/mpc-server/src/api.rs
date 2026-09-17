//! HTTP API와 OpenAPI 스펙.
//!
//! 공개 엔드포인트는 모두 `utoipa`로 문서화한다. 문서화되지 않은 공개
//! 엔드포인트를 두지 않는다 (`docs/server.md`).

use axum::{routing::get, Json, Router};
use serde::Serialize;
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

/// 헬스체크 응답.
#[derive(Debug, Serialize, ToSchema)]
pub struct Health {
    /// 항상 `"ok"`.
    pub status: &'static str,
    /// 이 빌드의 임계 설정, 예: `"2-of-3"`.
    pub threshold: String,
}

/// 서버 상태를 반환한다.
#[utoipa::path(
    get,
    path = "/v1/health",
    responses((status = 200, description = "서버 정상", body = Health)),
)]
async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        threshold: format!("{}-of-{}", mpc_core::THRESHOLD, mpc_core::TOTAL_PARTIES),
    })
}

/// OpenAPI 스펙 루트.
#[derive(OpenApi)]
#[openapi(
    paths(health),
    components(schemas(Health)),
    info(
        title = "mpc-ext server",
        description = "2-of-3 MPC 셰어 보관 및 복구 서버. 평시 서명에는 관여하지 않는다.",
    )
)]
pub struct ApiDoc;

/// 라우터를 구성한다. Swagger UI는 `/docs`, 스펙은 `/openapi.json`.
pub fn router() -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .merge(SwaggerUi::new("/docs").url("/openapi.json", ApiDoc::openapi()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openapi_documents_health() {
        let spec = ApiDoc::openapi();
        assert!(
            spec.paths.paths.contains_key("/v1/health"),
            "health 엔드포인트가 스펙에 없다"
        );
    }
}
