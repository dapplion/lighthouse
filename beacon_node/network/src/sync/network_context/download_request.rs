use crate::sync::network_context::RpcResponseError;
use lighthouse_network::PeerId;
use std::time::Duration;
use strum::IntoStaticStr;

/// TODO(das): Reconsider this retry count, it was choosen as a placeholder value. Each
/// `custody_by_*` request is already retried multiple inside of a lookup or batch
const MAX_DOWNLOAD_ATTEMPTS: usize = 5;

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
    TooManyErrors(RpcResponseError),
}

impl<I: std::fmt::Display + PartialEq, T> DownloadRequest<I, T> {
    pub fn new() -> Self {
        Self {
            status: Status::NotStarted,
            download_failures: vec![],
        }
    }

    pub fn status_str(&self) -> &'static str {
        (&self.status).into()
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

    pub fn on_download_error(
        &mut self,
        req_id: I,
        error_to_register: Option<RpcResponseError>,
    ) -> Result<(), Error> {
        match &self.status {
            Status::Downloading(expected_req_id) => {
                if req_id != *expected_req_id {
                    return Err(Error::InternalError(format!(
                        "Received download result for req_id {req_id} expecting {expected_req_id}"
                    )));
                }

                if let Some(e) = error_to_register {
                    self.download_failures.push(e);
                    if self.download_failures.len() > MAX_DOWNLOAD_ATTEMPTS {
                        if let Some(last_error) = self.download_failures.pop() {
                            return Err(Error::TooManyErrors(last_error));
                        }
                    }
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
            _ => None,
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
