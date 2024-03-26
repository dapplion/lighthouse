use eth2::types::builder_bid::SignedBuilderBid;
use eth2::types::{
    EthSpec, ExecutionBlockHash, ForkVersionedResponse, PublicKeyBytes,
    SignedValidatorRegistrationData, Slot,
};
use eth2::types::{FullPayloadContents, SignedBlindedBeaconBlock};
pub use eth2::Error;
use eth2::{ok_or_error, StatusCode};
use reqwest::{IntoUrl, Response};
use sensitive_url::SensitiveUrl;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::time::Duration;

pub const DEFAULT_TIMEOUT_MILLIS: u64 = 15000;

/// This timeout is in accordance with v0.2.0 of the [builder specs](https://github.com/flashbots/mev-boost/pull/20).
pub const DEFAULT_GET_HEADER_TIMEOUT_MILLIS: u64 = 1000;

/// Default user agent for HTTP requests.
pub const DEFAULT_USER_AGENT: &str = lighthouse_version::VERSION;

#[derive(Clone)]
pub struct Timeouts {
    get_header: Duration,
    post_validators: Duration,
    post_blinded_blocks: Duration,
    get_builder_status: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            get_header: Duration::from_millis(DEFAULT_GET_HEADER_TIMEOUT_MILLIS),
            post_validators: Duration::from_millis(DEFAULT_TIMEOUT_MILLIS),
            post_blinded_blocks: Duration::from_millis(DEFAULT_TIMEOUT_MILLIS),
            get_builder_status: Duration::from_millis(DEFAULT_TIMEOUT_MILLIS),
        }
    }
}

#[derive(Clone)]
pub struct BuilderHttpClient {
    client: reqwest::Client,
    server: SensitiveUrl,
    timeouts: Timeouts,
    user_agent: String,
}

impl BuilderHttpClient {
    pub fn new(server: SensitiveUrl, user_agent: Option<String>) -> Result<Self, Error> {
        let user_agent = user_agent.unwrap_or(DEFAULT_USER_AGENT.to_string());
        let client = reqwest::Client::builder().user_agent(&user_agent).build()?;
        Ok(Self {
            client,
            server,
            timeouts: Timeouts::default(),
            user_agent,
        })
    }

    pub fn get_user_agent(&self) -> &str {
        &self.user_agent
    }

    fn get_with_timeout<T: DeserializeOwned, U: IntoUrl>(
        &self,
        url: U,
        timeout: Duration,
    ) -> Result<T, Error> {
        todo!();
        // self.get_response_with_timeout(url, Some(timeout))?
        //    .json()
        //    .map_err(Into::into)
    }

    /// Perform a HTTP GET request, returning the `Response` for further processing.
    fn get_response_with_timeout<U: IntoUrl>(
        &self,
        url: U,
        timeout: Option<Duration>,
    ) -> Result<Response, Error> {
        let mut builder = self.client.get(url);
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }
        todo!();
        // let response = builder.send().await.map_err(Error::from)?;
        // ok_or_error(response).await
    }

    /// Generic POST function supporting arbitrary responses and timeouts.
    fn post_generic<T: Serialize, U: IntoUrl>(
        &self,
        url: U,
        body: &T,
        timeout: Option<Duration>,
    ) -> Result<Response, Error> {
        let mut builder = self.client.post(url);
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }
        todo!();
        // let response = builder.json(body).send().await?;
        // ok_or_error(response).await
    }

    fn post_with_raw_response<T: Serialize, U: IntoUrl>(
        &self,
        url: U,
        body: &T,
        timeout: Option<Duration>,
    ) -> Result<Response, Error> {
        let mut builder = self.client.post(url);
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }
        todo!();
        // let response = builder.json(body).send().await.map_err(Error::from)?;
        // ok_or_error(response).await
    }

    /// `POST /eth/v1/builder/validators`
    pub async fn post_builder_validators(
        &self,
        validator: &[SignedValidatorRegistrationData],
    ) -> Result<(), Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("builder")
            .push("validators");

        self.post_generic(path, &validator, Some(self.timeouts.post_validators))?;
        Ok(())
    }

    /// `POST /eth/v1/builder/blinded_blocks`
    pub fn post_builder_blinded_blocks<E: EthSpec>(
        &self,
        blinded_block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<ForkVersionedResponse<FullPayloadContents<E>>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("builder")
            .push("blinded_blocks");

        todo!();
        // Ok(self
        //     .post_with_raw_response(
        //        path,
        //        &blinded_block,
        //        Some(self.timeouts.post_blinded_blocks),
        //    )?
        //    .json()?)
    }

    /// `GET /eth/v1/builder/header`
    pub fn get_builder_header<E: EthSpec>(
        &self,
        slot: Slot,
        parent_hash: ExecutionBlockHash,
        pubkey: &PublicKeyBytes,
    ) -> Result<Option<ForkVersionedResponse<SignedBuilderBid<E>>>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("builder")
            .push("header")
            .push(slot.to_string().as_str())
            .push(format!("{parent_hash:?}").as_str())
            .push(pubkey.as_hex_string().as_str());

        let resp = self.get_with_timeout(path, self.timeouts.get_header);

        if matches!(resp, Err(Error::StatusCode(StatusCode::NO_CONTENT))) {
            Ok(None)
        } else {
            resp.map(Some)
        }
    }

    /// `GET /eth/v1/builder/status`
    pub fn get_builder_status<E: EthSpec>(&self) -> Result<(), Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("builder")
            .push("status");

        self.get_with_timeout(path, self.timeouts.get_builder_status)
    }
}
