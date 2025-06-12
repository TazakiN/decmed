use std::fmt::Debug;

use axum::{
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

use crate::types::ErrorResponse;

pub fn debug_print<T>(func_name: &str, data: T)
where
    T: Debug,
{
    println!("{}: {:#?}", func_name, data);
}

pub fn build_error_response(message: String, status_code: StatusCode) -> Response {
    (
        status_code,
        Json(ErrorResponse {
            status_code: status_code.as_u16(),
            error: message,
        }),
    )
        .into_response()
}

pub fn decode_authorization_header(
    authorization_header: Option<&HeaderValue>,
) -> Result<String, Response> {
    if authorization_header.is_none() {
        return Err(build_error_response(
            "Authorization header not found".to_string(),
            StatusCode::UNAUTHORIZED,
        ));
    }

    let bearer_token = authorization_header.unwrap().to_str().map_err(|_| {
        build_error_response(
            "Failed to decode bearer token".to_string(),
            StatusCode::UNAUTHORIZED,
        )
    })?;
    let bearer_token: Vec<&str> = bearer_token.split(" ").collect();

    if bearer_token.len() != 2 || bearer_token[0] != "Bearer" {
        return Err(build_error_response(
            "Failed to decode bearer token".to_string(),
            StatusCode::UNAUTHORIZED,
        ));
    }

    Ok(bearer_token[1].to_string())
}
