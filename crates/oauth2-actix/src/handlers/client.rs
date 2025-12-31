use actix::Addr;
use actix_web::{web, HttpResponse, Result};

use crate::actors::{ClientActor, RegisterClient};
use oauth2_core::{ClientCredentials, ClientRegistration, OAuth2Error};

/// Register a new OAuth2 client
pub async fn register_client(
    registration: web::Json<ClientRegistration>,
    client_actor: web::Data<Addr<ClientActor>>,
) -> Result<HttpResponse, OAuth2Error> {
    let client = client_actor
        .send(RegisterClient {
            registration: registration.into_inner(),
            span: tracing::Span::current(),
        })
        .await
        .map_err(|e| OAuth2Error::new("server_error", Some(&e.to_string())))??;

    let credentials = ClientCredentials {
        client_id: client.client_id,
        client_secret: client.client_secret,
    };

    Ok(HttpResponse::Created().json(credentials))
}
