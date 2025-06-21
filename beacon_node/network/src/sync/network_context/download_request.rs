use crate::sync::network_context::RpcResponseError;
use lighthouse_network::PeerId;
use std::time::Duration;
use strum::IntoStaticStr;

/// TODO(das): Reconsider this retry count, it was choosen as a placeholder value. Each
/// `custody_by_*` request is already retried multiple inside of a lookup or batch
const MAX_CUSTODY_COLUMN_DOWNLOAD_ATTEMPTS: usize = 3;

pub struct DownloadRequest<I: std::fmt::Display + PartialEq, T> {
    status: Status<I, T>,
    download_failures: Vec<RpcResponseError>,
}

#[derive(Debug, Clone, IntoStaticStr)]
pub enum Status<I, T> {
    NotStarted,
    Downloading(I),
    Downloaded(PeerId, T, Duration),
}

#[derive(Debug)]
pub enum Error {
    InternalError(String),
}

impl<I: std::fmt::Display + PartialEq, T> DownloadRequest<I, T> {
    pub fn new() -> Self {
        Self {
            status: Status::NotStarted,
            download_failures: vec![],
        }
    }

    pub fn is_awaiting_download(&self) -> bool {
        match self.status {
            Status::NotStarted => true,
            Status::Downloading { .. } | Status::Downloaded { .. } => false,
        }
    }

    pub fn is_downloading(&self) -> bool {
        match self.status {
            Status::NotStarted => false,
            Status::Downloading { .. } => true,
            Status::Downloaded { .. } => false,
        }
    }

    pub fn is_downloaded(&self) -> bool {
        match self.status {
            Status::NotStarted | Status::Downloading { .. } => false,
            Status::Downloaded { .. } => true,
        }
    }

    pub fn too_many_failures(&self) -> Option<RpcResponseError> {
        if self.download_failures.len() > MAX_CUSTODY_COLUMN_DOWNLOAD_ATTEMPTS {
            Some(
                self.download_failures
                    .last()
                    .cloned()
                    .expect("download_failures is not empty"),
            )
        } else {
            None
        }
    }

    pub fn on_download_start(&mut self, req_id: I) -> Result<(), Error> {
        match &self.status {
            Status::NotStarted => {
                self.status = Status::Downloading(req_id);
                Ok(())
            }
            other => Err(Error::InternalError(format!(
                "bad state on_download_start expected NotStarted got {}",
                Into::<&'static str>::into(other),
            ))),
        }
    }

    pub fn on_download_error(&mut self, req_id: I) -> Result<(), Error> {
        match &self.status {
            Status::Downloading(expected_req_id) => {
                if req_id != *expected_req_id {
                    return Err(Error::InternalError(format!(
                        "Received download result for req_id {req_id} expecting {expected_req_id}"
                    )));
                }
                self.status = Status::NotStarted;
                Ok(())
            }
            other => Err(Error::InternalError(format!(
                "bad state on_download_error expected Downloading got {}",
                Into::<&'static str>::into(other),
            ))),
        }
    }

    pub fn on_download_error_and_mark_failure(
        &mut self,
        req_id: I,
        e: RpcResponseError,
    ) -> Result<(), Error> {
        self.download_failures.push(e);
        self.on_download_error(req_id)
    }

    pub fn on_download_success(
        &mut self,
        req_id: I,
        peer_id: PeerId,
        data: T,
        seen_timestamp: Duration,
    ) -> Result<(), Error> {
        match &self.status {
            Status::Downloading(expected_req_id) => {
                if req_id != *expected_req_id {
                    return Err(Error::InternalError(format!(
                        "Received download result for req_id {req_id} expecting {expected_req_id}"
                    )));
                }
                self.status = Status::Downloaded(peer_id, data, seen_timestamp);
                Ok(())
            }
            other => Err(Error::InternalError(format!(
                "bad state on_download_success expected Downloading got {}",
                Into::<&'static str>::into(other),
            ))),
        }
    }

    pub fn is_complete(&self) -> Option<&T> {
        match &self.status {
            Status::Downloaded(_, data, _) => Some(data),
            other => None,
        }
    }

    pub fn complete(self) -> Result<(PeerId, T, Duration), Error> {
        match self.status {
            Status::Downloaded(peer_id, data, seen_timestamp) => {
                Ok((peer_id, data, seen_timestamp))
            }
            other => Err(Error::InternalError(format!(
                "bad state complete expected Downloaded got {}",
                Into::<&'static str>::into(other),
            ))),
        }
    }
}
