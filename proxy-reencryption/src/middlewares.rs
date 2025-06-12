use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};

use crate::{
    current_fn,
    utils::{debug_print, decode_authorization_header},
};

pub async fn auth_middleware(request: Request, next: Next) -> Result<Response, Response> {
    let headers = request.headers();
    let authorization_header = headers.get("Authorization");

    let bearer_token = decode_authorization_header(authorization_header)?;

    debug_print(current_fn!(), bearer_token);

    let response = next.run(request).await;

    Ok(response)
}
