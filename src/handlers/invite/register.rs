use {
    super::{
        super::{validate_caip10_account, Response},
        InviteKeyClaims,
    },
    crate::{
        auth::{
            did::{extract_did_data, DID_METHOD_PKH},
            jwt::Jwt,
        },
        error::{self},
        increment_counter,
        log::prelude::{info, warn},
        state::AppState,
    },
    axum::extract::{Json, State},
    serde::Deserialize,
    std::sync::Arc,
    validator::Validate,
};

#[derive(Deserialize)]
pub struct RegisterInviteKeyPayload {
    #[serde(rename = "idAuth")]
    id_auth: String,
}

#[derive(Validate, Debug)]
pub struct RegisterInviteKeyParams {
    #[validate(custom = "validate_caip10_account")]
    account: String,
    #[validate(length(max = 64))]
    invite_key: String,
}

/// Registers invite key for given account.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterInviteKeyPayload>,
) -> error::Result<Response> {
    info!("Handling - Register invite with jwt: {:?}", payload.id_auth);

    let jwt = Jwt::<InviteKeyClaims>::new(&payload.id_auth).map_err(|error| {
        increment_counter!(state.metrics, invalid_invite_register_jwt);
        info!(
            "Failure - Register invite with jwt: {:?}, error: {:?}",
            payload.id_auth, error
        );
        error
    })?;

    jwt.verify().map_err(|error| {
        increment_counter!(state.metrics, invalid_invite_register_jwt);
        info!(
            "Failure - Register invite with jwt: {:?}, error: {:?}",
            payload.id_auth, error
        );
        error
    })?;

    let claims: InviteKeyClaims = jwt.claims;
    let account = extract_did_data(&claims.pkh, DID_METHOD_PKH)?;

    let account = if account.starts_with("eip155") {
        account.to_lowercase()
    } else {
        account.to_string()
    };

    let identity_keys = state
        .keys_persitent_storage
        .get_identity_keys(&account)
        .await?;

    if !identity_keys.contains(&claims.iss) {
        info!(
            "Failure - Register invite with jwt: {:?}, error: Invalid identity key binding",
            payload.id_auth
        );
        return Err(error::Error::Authorization(
            "Invalid identity key for account".to_string(),
        ));
    }

    let params = RegisterInviteKeyParams {
        account: account.clone(),
        invite_key: claims.sub,
    };

    params.validate().map_err(|error| {
        info!(
            "Failure - Register invite with jwt: {:?}, error: {:?}",
            payload.id_auth, error
        );
        error
    })?;

    state
        .keys_persitent_storage
        .upsert_invite_key(&params.account, &params.invite_key)
        .await
        .map_err(|error| {
            warn!(
                "Failure - Register invite with jwt: {:?}, error: {:?}",
                payload.id_auth, error
            );
            error
        })?;

    info!("Success - Register invite with jwt: {:?}", payload.id_auth);
    increment_counter!(state.metrics, invite_register);

    Ok(Response::default())
}
