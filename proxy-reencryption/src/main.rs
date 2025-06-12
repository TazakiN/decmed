mod handlers;
mod macros;
mod middlewares;
mod types;
mod utils;

use std::{env, sync::Arc};

use axum::{middleware, routing::get, Router};
use handlers::request_reencrypt;
use iota_sdk::IotaClientBuilder;
use tower::ServiceBuilder;
use types::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Load envs from .env file
    dotenvy::dotenv()?;

    let port = env::var("PORT").unwrap();
    let shared_state = Arc::new(AppState {
        iota_client: IotaClientBuilder::default().build_localnet().await.unwrap(),
    });
    let app = Router::new()
        .route("/", get(|| async { "Hello, world!" }))
        .route("/re-encrypt", get(request_reencrypt))
        .layer(ServiceBuilder::new().layer(middleware::from_fn(middlewares::auth_middleware)))
        .with_state(shared_state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();

    Ok(())
}
