use {
    super::super::{validate_caip10_account, validate_identity_key, Response},
    crate::{
        error::{self},
        increment_counter,
        log::prelude::{info, warn},
        state::AppState,
    },
    axum::extract::{Json, State},
    relay_rpc::auth::cacao::Cacao,
    serde::Deserialize,
    std::sync::Arc,
    validator::Validate,
};

#[derive(Deserialize)]
pub struct RegisterIdentityPayload {
    pub cacao: Cacao,
}

#[derive(Validate, Debug)]
pub struct RegisterIdentityParams {
    #[validate(custom = "validate_caip10_account")]
    account: String,
    #[validate(custom = "validate_identity_key")]
    identity_key: String,
    cacao: Cacao,
}

pub async fn handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterIdentityPayload>,
) -> error::Result<Response> {
    let cacao = payload.cacao.clone();

    info!(
        "Handling - Register identity with cacao: {:?}",
        payload.cacao
    );

    cacao
        .verify(state.provider.as_ref())
        .await
        .map_err(|error| {
            increment_counter!(state.metrics, invalid_identity_register_cacao);
            info!(
                "Failure - Register identity with cacao: {:?}, error: {:?}",
                payload.cacao, error
            );
            error
        })?;

    // Validating exp, nbf and nonce
    let now = chrono::Utc::now();
    let p = &cacao.p;

    let exp_time = if let Some(exp_str) = &p.exp {
        let exp = chrono::DateTime::parse_from_rfc3339(exp_str)
            .map_err(|_| error::Error::Validation(validator::ValidationErrors::new()))?
            .with_timezone(&chrono::Utc);

        if exp < now {
            info!("Failure - Register identity: CACAO expired");
            return Err(error::Error::Validation(validator::ValidationErrors::new()));
        }
        Some(exp)
    } else {
        None
    };

    if let Some(nbf_str) = &p.nbf {
        let nbf = chrono::DateTime::parse_from_rfc3339(nbf_str)
            .map_err(|_| error::Error::Validation(validator::ValidationErrors::new()))?
            .with_timezone(&chrono::Utc);

        if nbf > now {
            info!("Failure - Register identity: CACAO nbf in future");
            return Err(error::Error::Validation(validator::ValidationErrors::new()));
        }
    }

    if let Some(nonce) = &p.nonce {
        if let Some(exp) = exp_time {
            state
                .keys_persitent_storage
                .check_and_store_nonce(nonce, exp)
                .await
                .map_err(|e| match e {
                    crate::stores::StoreError::NonceAlreadyUsed(_) => {
                        info!("Failure - Register identity: Nonce reuse detected");
                        error::Error::Authorization("Nonce already used".to_string())
                    }
                    _ => error::Error::Store(e),
                })?;
        } else {
            warn!("Failure - Register identity: Nonce present but exp missing");
            return Err(error::Error::Validation(validator::ValidationErrors::new()));
        }
    }

    let identity_key = cacao.p.identity_key()?;
    let account = cacao.p.caip_10_address()?;
    let params = RegisterIdentityParams {
        account,
        identity_key,
        cacao,
    };

    params.validate().map_err(|error| {
        info!(
            "Failure - Register identity with cacao: {:?}, error: {:?}",
            payload.cacao, error
        );
        error
    })?;

    // Note to future: accounts can have both ERC-55 and lowercase variants, with duplicates. Make sure these are merged/treated as the same account
    // See for context: https://github.com/WalletConnect/keys-server/pull/173
    state
        .keys_persitent_storage
        .create_account_if_not_exists_and_add_identity_key(
            &params.account,
            &params.identity_key,
            &params.cacao,
        )
        .await
        .map_err(|error| {
            warn!(
                "Failure - Register identity with cacao: {:?}, error: {:?}",
                payload.cacao, error
            );
            error
        })?;

    info!(
        "Success - Register identity with cacao: {:?}",
        payload.cacao
    );
    increment_counter!(state.metrics, identity_register);

    Ok(Response::default())
}
