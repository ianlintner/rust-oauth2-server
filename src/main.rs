// Thin delegating binary.
//
// The actual server assembly lives in the extracted `oauth2-server` crate.
#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    oauth2_server::run().await
}

