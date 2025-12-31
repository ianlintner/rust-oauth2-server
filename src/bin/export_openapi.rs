use oauth2_openapi::ApiDoc;
use std::path::PathBuf;
use utoipa::OpenApi;

fn default_output_path() -> PathBuf {
    PathBuf::from("docs/assets/openapi/openapi.json")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(default_output_path);

    let openapi = ApiDoc::openapi();
    let json = serde_json::to_string_pretty(&openapi)?;

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&output_path, json)?;

    eprintln!(
        "Wrote OpenAPI spec to {}",
        output_path.canonicalize().unwrap_or(output_path).display()
    );

    Ok(())
}
