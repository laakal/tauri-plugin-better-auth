//! Controller flow operations.

use super::*;

impl Controller {
    // ------------------------------------------------------------ the flow

    /// Starts a browser sign-in.
    pub async fn request_auth(
        self: &Arc<Self>,
        options: RequestAuthOptions,
    ) -> Result<RequestAuthResult> {
        if let Some(provider) = &options.provider
            && !valid_provider(provider)
        {
            return Err(Error::InvalidRequest("invalid provider id".into()));
        }
        let transport = match options.transport.unwrap_or(self.config.transport) {
            Transport::Auto => auto_transport(self.deep_links_deliverable),
            other => other,
        };
        let pkce = generate_pkce()?;
        let state = generate_state()?;

        let mut inner = self.inner.lock().await;
        inner.generation += 1;
        // Replacing the pending flow drops its loopback listener.
        inner.pending = None;

        let loopback = if transport == Transport::Loopback {
            let controller = Arc::downgrade(self);
            let claim = Arc::new(move |callback: Callback| {
                let controller = controller.clone();
                Box::pin(async move {
                    match controller.upgrade() {
                        Some(controller) => controller.claim_from_loopback(callback).await,
                        None => false,
                    }
                }) as Pin<Box<dyn Future<Output = bool> + Send>>
            });
            Some(
                LoopbackServer::start(
                    self.config.callback_path.clone(),
                    self.config.pending_ttl,
                    self.app_name.clone(),
                    claim,
                )
                .await?,
            )
        } else {
            None
        };

        let mut url: Url = self.config.sign_in_url.clone();
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("client_id", &self.config.client_id)
                .append_pair("state", &state)
                .append_pair("code_challenge", &pkce.challenge)
                .append_pair("code_challenge_method", "S256")
                .append_pair("v", PROTOCOL_VERSION);
            if let Some(server) = &loopback {
                query.append_pair("redirect_uri", &server.redirect_uri);
            }
            if let Some(provider) = &options.provider {
                query.append_pair("provider", provider);
            }
        }

        inner.pending = Some(Pending {
            state,
            verifier: pkce.verifier,
            transport,
            created_at: Instant::now(),
            _loopback: loopback,
        });
        drop(inner);

        let opened = match self.opener.open(url.as_str()) {
            Ok(()) => true,
            Err(error) => {
                log::warn!("[better-auth] could not open the browser: {error}");
                false
            }
        };
        Ok(RequestAuthResult {
            url: url.into(),
            opened,
            transport,
        })
    }

    /// Cancels the pending sign-in, if any.
    pub async fn cancel_auth(&self) {
        let mut inner = self.inner.lock().await;
        inner.generation += 1;
        inner.pending = None;
    }

    /// Takes the pending flow if `state` matches. A mismatch leaves it alone.
    pub(super) async fn claim(
        &self,
        state: &str,
        require: Option<Transport>,
    ) -> Result<(u64, String, String)> {
        let mut inner = self.inner.lock().await;
        let pending = inner.pending.as_ref().ok_or(Error::NoPendingFlow)?;
        if !constant_time_eq(&pending.state, state) {
            return Err(Error::InvalidCallback);
        }
        if require.is_some_and(|transport| transport != pending.transport) {
            return Err(Error::InvalidCallback);
        }
        if pending.created_at.elapsed() > self.config.pending_ttl {
            inner.pending = None;
            return Err(Error::FlowExpired);
        }
        let pending = inner.pending.take().ok_or(Error::NoPendingFlow)?;
        Ok((inner.generation, pending.state, pending.verifier))
    }

    /// Claims the pending flow without a state (a bare pasted code).
    pub(super) async fn claim_current(&self) -> Result<(u64, String, String)> {
        let mut inner = self.inner.lock().await;
        let pending = inner.pending.as_ref().ok_or(Error::NoPendingFlow)?;
        if pending.created_at.elapsed() > self.config.pending_ttl {
            inner.pending = None;
            return Err(Error::FlowExpired);
        }
        let pending = inner.pending.take().ok_or(Error::NoPendingFlow)?;
        Ok((inner.generation, pending.state, pending.verifier))
    }

    /// Exchange + commit for a claimed flow.
    pub(super) async fn finish(
        &self,
        generation: u64,
        state: String,
        verifier: String,
        outcome: CallbackOutcome,
    ) -> Result<SessionSnapshot> {
        let code = match outcome {
            CallbackOutcome::Code(code) => code,
            CallbackOutcome::Denied => return Err(Error::AccessDenied),
        };
        let exchanged = self
            .http
            .exchange(&self.config.client_id, &code, &state, &verifier)
            .await?;
        self.sign_in(exchanged.token, generation).await
    }

    /// Handles a deep link delivered by the OS. Background flow: reports
    /// through events, ignores links that are not for the current request.
    pub async fn handle_deep_link(self: &Arc<Self>, url: &str) {
        let Ok(parsed) = Url::parse(url) else { return };
        let Some(callback) =
            parse_deep_link(&parsed, &self.config.scheme, &self.config.callback_path)
        else {
            return;
        };
        let claimed = self.claim(&callback.state, None).await;
        let (generation, state, verifier) = match claimed {
            Ok(claimed) => claimed,
            Err(Error::NoPendingFlow) => {
                log::debug!(
                    "[better-auth] ignored a callback with no sign-in in progress. On Windows and \
                     Linux, register tauri-plugin-single-instance with the `deep-link` feature first, \
                     or the link starts a second app instance."
                );
                return;
            }
            Err(Error::InvalidCallback) => return,
            Err(error) => {
                self.events.error(&error);
                return;
            }
        };
        self.events.focus();
        if let Err(error) = self
            .finish(generation, state, verifier, callback.outcome)
            .await
            && !matches!(error, Error::Superseded)
        {
            self.events.error(&error);
        }
    }

    /// Called by the loopback listener. Returns whether the callback was
    /// claimed (then the listener closes); the exchange runs in the
    /// background and reports through events.
    pub(crate) async fn claim_from_loopback(self: Arc<Self>, callback: Callback) -> bool {
        let (generation, state, verifier) =
            match self.claim(&callback.state, Some(Transport::Loopback)).await {
                Ok(claimed) => claimed,
                Err(Error::FlowExpired) => {
                    self.events.error(&Error::FlowExpired);
                    return false;
                }
                Err(_) => return false,
            };
        self.events.focus();
        let controller = self.clone();
        tokio::spawn(async move {
            if let Err(error) = controller
                .finish(generation, state, verifier, callback.outcome)
                .await
                && !matches!(error, Error::Superseded)
            {
                controller.events.error(&error);
            }
        });
        true
    }

    /// Completes a sign-in from a pasted code or link. Reports to the caller.
    pub async fn authenticate(&self, input: &str) -> Result<SessionSnapshot> {
        let (generation, state, verifier, outcome) =
            match parse_pasted(input, &self.config.scheme, &self.config.callback_path)? {
                Pasted::Callback(callback) => {
                    let (generation, state, verifier) = self.claim(&callback.state, None).await?;
                    (generation, state, verifier, callback.outcome)
                }
                Pasted::Code(code) => {
                    let (generation, state, verifier) = self.claim_current().await?;
                    (generation, state, verifier, CallbackOutcome::Code(code))
                }
            };
        self.finish(generation, state, verifier, outcome).await
    }
}
