use super::{LookupRequestResult, ReqId, RpcRequestSendError};
use lighthouse_network::PeerId;
use std::collections::HashSet;

const MAX_ATTEMPTS: u8 = 5;

#[derive(Debug)]
pub enum DownloadError {
    TooManyAttempts,
    SendFailed(#[allow(dead_code)] RpcRequestSendError),
}

#[derive(Clone)]
enum DownloadState<T, I> {
    AwaitingDownload,
    Downloading(I),
    Downloaded(T),
}

#[derive(Clone)]
pub(crate) struct DownloadRequest<T, I = ReqId> {
    state: DownloadState<T, I>,
    failed_downloading: u8,
    failed_peers: HashSet<PeerId>,
}

impl<T, I> DownloadRequest<T, I> {
    pub(crate) fn new() -> Self {
        Self {
            state: DownloadState::AwaitingDownload,
            failed_downloading: 0,
            failed_peers: HashSet::new(),
        }
    }
}

impl<T, I: PartialEq> DownloadRequest<T, I> {
    /// True when `id` names the attempt currently out. A response failing this is from a
    /// superseded attempt and must not be acted on.
    pub(crate) fn is_current(&self, id: &I) -> bool {
        matches!(&self.state, DownloadState::Downloading(expected) if expected == id)
    }

    /// Records a failed attempt against `peer` and re-arms the request. The retry budget is
    /// enforced by `maybe_start_downloading` when the next attempt is issued.
    pub(crate) fn failed(&mut self, peer: Option<PeerId>) {
        self.failed_peers.extend(peer);
        self.failed_downloading = self.failed_downloading.saturating_add(1);
        self.state = DownloadState::AwaitingDownload;
    }

    pub(crate) fn complete(&self) -> Option<&T> {
        match &self.state {
            DownloadState::Downloaded(value) => Some(value),
            DownloadState::AwaitingDownload | DownloadState::Downloading(_) => None,
        }
    }

    pub(crate) fn maybe_start_downloading(
        &mut self,
        request_fn: impl FnOnce(
            &HashSet<PeerId>,
        ) -> Result<LookupRequestResult<T, I>, RpcRequestSendError>,
    ) -> Result<(), DownloadError> {
        if !matches!(self.state, DownloadState::AwaitingDownload) {
            return Ok(());
        }
        if self.failed_downloading >= MAX_ATTEMPTS {
            return Err(DownloadError::TooManyAttempts);
        }
        self.state = match request_fn(&self.failed_peers).map_err(DownloadError::SendFailed)? {
            LookupRequestResult::RequestSent(id) => DownloadState::Downloading(id),
            LookupRequestResult::NoRequestNeeded(_, value) => DownloadState::Downloaded(value),
            LookupRequestResult::Pending(_) => DownloadState::AwaitingDownload,
        };
        Ok(())
    }

    /// Feeds the response of attempt `id` into the request. Returns false for a response
    /// from a superseded attempt, which must be ignored: it is not an error, the current
    /// attempt is still pending.
    #[must_use]
    pub(crate) fn on_response(
        &mut self,
        id: I,
        result: Result<T, ()>,
        peer: Option<PeerId>,
    ) -> bool {
        match &self.state {
            DownloadState::Downloading(expected) if *expected == id => {}
            DownloadState::AwaitingDownload
            | DownloadState::Downloading(_)
            | DownloadState::Downloaded(_) => return false,
        }
        match result {
            Ok(value) => self.state = DownloadState::Downloaded(value),
            Err(()) => self.failed(peer),
        }
        true
    }
}
