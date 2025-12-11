use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use pasetors::{
    Public,
    claims::{Claims, ClaimsValidationRules},
    keys::{AsymmetricPublicKey, AsymmetricSecretKey},
    public,
    token::UntrustedToken,
    version4::V4,
};

use crate::repositories::KeyRepository;

pub async fn decode_keys(
    keys_repo: KeyRepository,
) -> Result<(AsymmetricPublicKey<V4>, AsymmetricSecretKey<V4>), String> {
    let keys = keys_repo.get_key_pair().await.map_err(|error| error)?;
    let decoded_private_key = STANDARD
        .decode(&keys.private_key)
        .map_err(|error| error.to_string())?;
    let private_key =
        AsymmetricSecretKey::<V4>::from(&decoded_private_key).map_err(|error| error.to_string())?;
    let decoded_public_key = STANDARD
        .decode(keys.public_key)
        .map_err(|error| error.to_string())?;
    let public_key =
        AsymmetricPublicKey::<V4>::from(&decoded_public_key).map_err(|error| error.to_string())?;
    Ok((public_key, private_key))
}

pub async fn create_claims(
    token_life_hours: i64,
    user_payload: String,
    issuer: String,
    permissions: Option<String>,
) -> Result<Claims, String> {
    let mut claims = Claims::new().map_err(|error| error.to_string())?;
    let expiration = Utc::now() + Duration::hours(token_life_hours);
    let expiration = expiration.to_rfc3339();
    claims
        .expiration(&expiration)
        .map_err(|error| error.to_string())?;
    claims
        .subject(&user_payload)
        .map_err(|error| error.to_string())?;
    claims.issuer(&issuer).map_err(|error| error.to_string())?;
    if let Some(permissions) = permissions {
        claims
            .add_additional("permissions", permissions)
            .map_err(|error| error.to_string())?;
    }

    Ok(claims)
}

pub async fn create_token(
    claims: Claims,
    key_pair: (AsymmetricPublicKey<V4>, AsymmetricSecretKey<V4>),
) -> Result<String, String> {
    let token =
        public::sign(&key_pair.1, &claims, None, None).map_err(|error| error.to_string())?;
    Ok(token)
}

pub async fn verify_token(
    token: String,
    key_pair: (AsymmetricPublicKey<V4>, AsymmetricSecretKey<V4>),
) -> Result<Claims, String> {
    let validation_rules = ClaimsValidationRules::new();
    let untrusted_token =
        UntrustedToken::<Public, V4>::try_from(&token).map_err(|error| error.to_string())?;
    let trusted_token =
        public::verify(&key_pair.0, &untrusted_token, &validation_rules, None, None)
            .map_err(|error| error.to_string())?;

    if let Some(claims) = trusted_token.payload_claims() {
        let claims = claims.clone();
        return Ok(claims);
    }

    Err("Invalid token".to_string())
}
