use anyhow::Context;
use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::get,
    Extension, Router,
};

use oauth2::{
    basic::BasicClient, AuthorizationCode, CsrfToken, PkceCodeChallenge, Scope, TokenResponse,
};
use oauth2::{reqwest::async_http_client, PkceCodeVerifier};
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use tracing::debug;

use crate::{
    constants::{
        COOKIE_AUTH_CODE_VERIFIER, COOKIE_AUTH_CSRF_STATE, COOKIE_AUTH_SESSION, SESSION_DURATION,
    },
    misc::error::AppError,
    models::AuthProvider,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use sqlx::PgPool;

//  Checkout available fields on: https://discord.com/developers/docs/resources/user
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Auth0User {
    sub: String,
    nickname: String,
    email: Option<String>,
    picture: Option<String>,
}

pub fn auth0_router() -> Router {
    Router::new()
        .route("/api/auth/auth0/login", get(login))
        .route("/api/auth/auth0/callback", get(callback))
}

fn get_oauth_client() -> Result<BasicClient, anyhow::Error> {
    let client_id = ClientId::new(
        std::env::var("AUTH0_CLIENT_ID")
            .context("Missing the AUTH0_CLIENT_ID environment variable")?,
    );

    let client_secret = ClientSecret::new(
        std::env::var("AUTH0_CLIENT_SECRET")
            .context("Missing the AUTH0_CLIENT_SECRET environment variable")?,
    );

    let domain =
        std::env::var("AUTH0_DOMAIN").context("Missing the AUTH0_DOMAIN environment variable")?;

    debug!("Got domain {}", domain);

    let auth_url = AuthUrl::new(format!("{domain}/oauth/authorize"))
        .context("Invalid authorization endpoint URL")?;
    let token_url =
        TokenUrl::new(format!("{domain}/oauth/token")).context("Invalid token endpoint URL")?;

    debug!(
        "Got auth_url and token_url {:?} {:?}",
        &auth_url, &token_url
    );

    let base_url = std::env::var("BASE_URL").context("Failed to get app base url")?;
    let redirect_url = RedirectUrl::new(format!("{base_url}/api/auth/auth0/callback"))
        .context("Invalid redirect url")?;

    let client = BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
        .set_redirect_uri(redirect_url);

    Ok(client)
}

async fn login() -> Result<impl IntoResponse, AppError> {
    let client = get_oauth_client().context("Failed to create Auth0 auth client")?;
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid profile email".to_string()))
        .set_pkce_challenge(pkce_code_challenge)
        .url();

    // Set csrf and code verifier cookies, these are short lived cookies
    let cookie_max_age = cookie::time::Duration::minutes(5);
    let csrf_cookie: Cookie =
        Cookie::build((COOKIE_AUTH_CSRF_STATE, csrf_state.secret().to_owned()))
            .http_only(true)
            .path("/")
            .same_site(SameSite::Lax)
            .max_age(cookie_max_age)
            .into();

    let code_verifier: Cookie = Cookie::build((
        COOKIE_AUTH_CODE_VERIFIER,
        pkce_code_verifier.secret().to_owned(),
    ))
    .http_only(true)
    .path("/")
    .same_site(SameSite::Lax)
    .max_age(cookie_max_age)
    .into();

    let cookies = CookieJar::new().add(csrf_cookie).add(code_verifier);

    Ok((cookies, Redirect::to(authorize_url.as_str())))
}

#[derive(Debug, serde::Deserialize)]
struct AuthRequest {
    code: String,
    state: String,
}

async fn callback(
    cookies: CookieJar,
    Extension(pool): Extension<PgPool>,
    Query(query): Query<AuthRequest>,
) -> Result<impl IntoResponse, AppError> {
    let code = query.code;
    let state = query.state;
    let stored_state = cookies.get(COOKIE_AUTH_CSRF_STATE);
    let stored_code_verifier = cookies.get(COOKIE_AUTH_CODE_VERIFIER);

    let (Some(csrf_state), Some(code_verifier)) = (stored_state, stored_code_verifier) else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };

    if csrf_state.value() != state {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    }

    let client = get_oauth_client().context("Failed to create Auth0 auth client")?;
    let code = AuthorizationCode::new(code);
    let pkce_code_verifier = PkceCodeVerifier::new(code_verifier.value().to_owned());

    let token_response = client
        .exchange_code(code)
        .set_pkce_verifier(pkce_code_verifier)
        .request_async(async_http_client)
        .await
        .context("Failed to get token response")?;

    let domain =
        std::env::var("AUTH0_DOMAIN").context("Missing the AUTH0_DOMAIN environment variable")?;

    debug!(
        "Bearer token {}",
        token_response.access_token().secret().to_string()
    );

    // Get the Auth0 user info
    let auth0_user = reqwest::Client::new()
        .get(format!("{domain}/userinfo"))
        .bearer_auth(token_response.access_token().secret())
        .send()
        .await
        .context("Failed to get user info")?
        .json::<Auth0User>()
        .await
        .context("Failed to convert user info to Json")?;

    // Add user session
    let account_id = auth0_user.sub.clone();
    // .split("|")
    // .last()
    // .ok_or(anyhow!("Expected pipe separated UUID in sub"))?
    // .to_string();

    let existing_user =
        crate::db::get_user_by_account_id(&pool, AuthProvider::Auth0, account_id.clone())
            .await
            .context("Failed to get user")?;

    let user = match existing_user {
        Some(x) => x,
        None => crate::db::create_user(
            &pool,
            account_id.clone(),
            AuthProvider::Auth0,
            auth0_user.nickname,
            auth0_user.picture,
        )
        .await
        .context("Failed to create user")?,
    };

    let user_session = crate::db::create_user_session(&pool, user.id, SESSION_DURATION)
        .await
        .context("Failed to create user session")?;

    // Remove code_verifier and csrf_state cookies
    let mut remove_csrf_cookie = Cookie::new(COOKIE_AUTH_CSRF_STATE, "");
    remove_csrf_cookie.set_path("/");
    remove_csrf_cookie.make_removal();

    let mut remove_code_verifier = Cookie::new(COOKIE_AUTH_CODE_VERIFIER, "");
    remove_code_verifier.set_path("/");
    remove_code_verifier.make_removal();

    let session_cookie: Cookie = Cookie::build((COOKIE_AUTH_SESSION, user_session.id.to_string()))
        .same_site(SameSite::Lax)
        .http_only(true)
        .path("/")
        .max_age(cookie::time::Duration::milliseconds(
            SESSION_DURATION.as_millis() as i64,
        ))
        .into();

    let cookies = CookieJar::new()
        .add(remove_csrf_cookie)
        .add(remove_code_verifier)
        .add(session_cookie);

    let response = (cookies, Redirect::to("/")).into_response();
    Ok(response)
}
