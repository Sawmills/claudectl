use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use store::FlowRow;

const REDIRECT: &str = "https://console.anthropic.com/oauth/code/callback";
#[derive(Serialize, Deserialize)]
struct Flow {
    machine: String,
    verifier: String,
    state: String,
    expires_at: i64,
    expected: Option<Identity>,
}
#[derive(Serialize)]
pub struct Login {
    pub id: String,
    pub authorize_url: String,
    pub expires_at: i64,
}
impl Engine {
    pub async fn start_login(
        &self,
        user: &str,
        machine: &str,
        alias: &str,
        renew: bool,
    ) -> Result<Login> {
        let alias = validate_alias(alias)?;
        let existing = self
            .accounts(user)
            .await?
            .into_iter()
            .find(|a| a.alias.eq_ignore_ascii_case(alias));
        if existing.is_some() != renew {
            bail!("use login renewal for an existing alias, or a new alias for login");
        }
        let flow = Flow {
            machine: machine.into(),
            verifier: URL_SAFE_NO_PAD.encode(vault::random_bytes()),
            state: revision(),
            expires_at: now() + 300_000,
            expected: existing.map(|a| a.identity),
        };
        let id = revision();
        let row = FlowRow {
            user: user.into(),
            alias: alias.into(),
            sealed: self.seal(&flow)?,
            exchanging: false,
            retained: None,
            cancelled: false,
            consumed: false,
        };
        self.store.put_flow(&id, &row).await?;
        let mut url = reqwest::Url::parse("https://claude.ai/oauth/authorize")?;
        url.query_pairs_mut().extend_pairs([
            ("code", "true"),
            ("client_id", CLIENT_ID),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT),
            ("scope", "org:create_api_key user:profile user:inference"),
            (
                "code_challenge",
                &URL_SAFE_NO_PAD.encode(Sha256::digest(flow.verifier.as_bytes())),
            ),
            ("code_challenge_method", "S256"),
            ("state", &flow.state),
        ]);
        Ok(Login {
            id,
            authorize_url: url.to_string(),
            expires_at: flow.expires_at,
        })
    }
    /// Finish a login. A retry verifies a kept response; an uncertain exchange is never
    /// replayed. A delete removes the flow, and a response that arrives later is dropped.
    pub async fn finish_login(
        &self,
        user: &str,
        machine: &str,
        id: &str,
        pasted: &str,
    ) -> Result<Receipt> {
        if id.len() != 64 || !id.bytes().all(|c| c.is_ascii_hexdigit()) {
            bail!("invalid login identifier");
        }
        if let Some(receipt) = self.receipt(user, id).await? {
            return Ok(receipt);
        }
        let row = self
            .store
            .flow(user, id)
            .await?
            .filter(|f| !f.cancelled && !f.consumed)
            .context("login not found, finished, or cancelled; start a new login")?;
        let flow: Flow = self.unseal(&row.sealed)?;
        if flow.machine != machine {
            bail!("login does not belong to this user and machine");
        }
        let retained: Retained = match &row.retained {
            Some(sealed) => self.unseal(sealed)?,
            None if row.exchanging => {
                bail!("login exchange outcome uncertain; start a new login")
            }
            None => {
                if flow.expires_at < now() {
                    bail!("login expired");
                }
                let (code, state) = pasted
                    .trim()
                    .split_once('#')
                    .context("paste code#state from the Claude sign-in page")?;
                if code.is_empty() || state != flow.state {
                    bail!("login state mismatch");
                }
                // Exactly one exchange per flow, across replicas.
                if !self.store.start_exchange(user, id).await? {
                    bail!("login exchange already started or the login was cancelled");
                }
                let response = self
                    .http
                    .post(&self.endpoints.token)
                    .json(&json!({
                        "grant_type":"authorization_code", "code":code, "state":flow.state,
                        "client_id":CLIENT_ID, "redirect_uri":REDIRECT, "code_verifier":flow.verifier
                    }))
                    .send()
                    .await
                    .map_err(|_| anyhow::anyhow!("login exchange outcome uncertain"))?;
                if !response.status().is_success() {
                    bail!("Claude rejected the login exchange");
                }
                let bytes = match capped_body(response).await {
                    Ok(bytes) => bytes,
                    Err(Body::TooLarge) => {
                        bail!("login response too large to keep; start a new login")
                    }
                    Err(Body::Incomplete) => bail!("login response incomplete"),
                };
                let retained = Retained {
                    received_at: now(),
                    body: bytes,
                };
                if !self.store.retain(user, id, &self.seal(&retained)?).await? {
                    bail!("the login was cancelled by a delete; the response was not kept");
                }
                retained
            }
        };
        #[derive(Deserialize)]
        struct Response {
            access_token: String,
            refresh_token: String,
            expires_in: i64,
            scope: String,
        }
        let token: Response = serde_json::from_slice(&retained.body)
            .map_err(|_| anyhow::anyhow!("login response invalid; acquired response retained"))?;
        let expiry = token
            .expires_in
            .checked_mul(1000)
            .and_then(|t| retained.received_at.checked_add(t))
            .filter(|_| token.expires_in > 0)
            .context("invalid login expiry; acquired response retained")?;
        let grant = Grant {
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            expires_at: expiry,
            scopes: token.scope.split_whitespace().map(str::to_owned).collect(),
        };
        self.admit_with(
            user,
            &row.alias,
            id,
            grant,
            flow.expected.as_ref(),
            false,
            Some(id),
        )
        .await
    }
}
