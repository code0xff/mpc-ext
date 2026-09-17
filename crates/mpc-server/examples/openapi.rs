//! Writes the OpenAPI spec to a file.
//!
//! The generated spec is committed so API changes show up in review (`docs/server.md`).
//! Run it with `make openapi`.

use utoipa::OpenApi;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let spec = mpc_server::api::ApiDoc::openapi().to_pretty_json()?;
    std::fs::write("docs/openapi.json", format!("{spec}\n"))?;
    println!("wrote docs/openapi.json");
    Ok(())
}
