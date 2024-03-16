use beacon_chain::{data_availability_checker::DataAvailabilityChecker, BeaconChainTypes};
use futures::Stream;
use lighthouse_network::{rpc::methods::DataColumnsByRootRequest, PeerId};
use rand::seq::SliceRandom;
use rand::thread_rng;
use slog::{debug, error, trace, warn, Logger};
use std::{
    collections::{hash_map::Entry, HashMap},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use types::{
    data_column_sidecar::{ColumnIndex, DataColumnIdentifier, FixedDataColumnSidecarList},
    ChainSpec, DataColumnSidecar, EthSpec, Hash256, Slot,
};

use super::{
    manager::{BlockProcessType, BlockProcessingResult, Id, SampleReqId},
    network_context::SyncNetworkContext,
};

pub struct Sampling<T: BeaconChainTypes> {
    requests: HashMap<Hash256, SamplingRequest>,
    spec: ChainSpec,
    log: Logger,
    // TODO, necessary?
    da_checker: Arc<DataAvailabilityChecker<T>>,
}

#[derive(Debug)]
pub enum SamplingError {
    SendFailed(&'static str),
}

impl<T: BeaconChainTypes> Sampling<T> {
    pub fn new(log: Logger) -> Self {
        Self {
            requests: <_>::default(),
            spec: todo!(),
            log,
            da_checker: todo!(),
        }
    }

    /// Inserts a new sampling request for a block root. Returns true if the request is not known
    /// before.
    pub fn add_request(
        &mut self,
        block_root: Hash256,
        slot: Slot,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<bool, SamplingError> {
        let sampling_request = self
            .requests
            .remove(&block_root)
            .unwrap_or(SamplingRequest::new(cx.next_id(), slot, block_root));

        for column_id in sampling_request.columns_to_sample.iter().take(16) {
            // Find peer custodial of `column_id`
            let peer_id = self.custodial_of_column(*column_id);

            // Send request and track
            let data_column_id = DataColumnIdentifier {
                block_root,
                index: *column_id,
            };
            let request = DataColumnsByRootRequest::new(vec![data_column_id], &self.spec);
            cx.data_column_lookup_request(
                SampleReqId {
                    id: sampling_request.id,
                    column_index: *column_id,
                },
                peer_id,
                request,
            )
            .map_err(SamplingError::SendFailed)?;
        }

        self.requests.insert(block_root, sampling_request);

        Ok(true)
    }

    pub fn handle_rpc_data_column(
        &mut self,
        id: SampleReqId,
        data_column: Option<Arc<DataColumnSidecar<T::EthSpec>>>,
        seen_timestamp: Duration,
        cx: &SyncNetworkContext<T>,
    ) {
        let Some(sampling_request) = self.get_request(id.id) else {
            error!(self.log, "Received rpc data column for unknown request");
            return;
        };

        if let Some(data_column) = data_column {
            self.send_data_column_for_processing(
                sampling_request.block_root,
                data_column,
                seen_timestamp,
                id,
                cx,
            );
        } else {
            todo!("handle stream termination");
        }

        self.requests
            .insert(sampling_request.block_root, sampling_request);
    }

    pub fn handle_data_column_processed(
        &mut self,
        id: SampleReqId,
        result: BlockProcessingResult<T::EthSpec>,
        cx: &SyncNetworkContext<T>,
    ) {
        let Some(mut sampling_request) = self.get_request(id.id) else {
            error!(self.log, "Received rpc data column for unknown request");
            return;
        };

        match result {
            BlockProcessingResult::Ok(status) => {
                // Sample is valid
                sampling_request.register_valid(id.column_index);
                cx.beacon_processor()
                    .sampling_completed(sampling_request.block_root);
            }
            BlockProcessingResult::Ignored => {
                todo!("when does this condition happen?")
            }
            BlockProcessingResult::Err(e) => {
                // Sample invalid, penalize
                sampling_request.register_invalid(id.column_index);
            }
        }

        self.requests
            .insert(sampling_request.block_root, sampling_request);
    }

    fn send_data_column_for_processing(
        &self,
        block_root: Hash256,
        data_column: Arc<DataColumnSidecar<T::EthSpec>>,
        seen_timestamp: Duration,
        id: SampleReqId,
        cx: &SyncNetworkContext<T>,
    ) -> Result<(), SamplingError> {
        match cx.beacon_processor_if_enabled() {
            Some(beacon_processor) => {
                trace!(self.log,
                    "Sending data columns for processing";
                    "block" => ?block_root,
                    "id" => ?id
                );
                if let Err(e) =
                    beacon_processor.send_rpc_data_column(data_column, seen_timestamp, id)
                {
                    error!(
                        self.log,
                        "Failed to send sync data columns to processor";
                        "error" => ?e
                    );
                    Err(SamplingError::SendFailed("beacon processor send failure"))
                } else {
                    Ok(())
                }
            }
            None => {
                trace!(self.log, "Dropping data columns ready for processing. Beacon processor not available"; "block_root" => %block_root);
                Err(SamplingError::SendFailed("beacon processor unavailable"))
            }
        }
    }

    fn get_request(&mut self, id: Id) -> Option<SamplingRequest> {
        let Some(block_root) = self
            .requests
            .values()
            .find(|value| value.id == id)
            .map(|value| value.block_root)
        else {
            return None;
        };

        self.requests.remove(&block_root)
    }

    fn custodial_of_column(&self, column_id: ColumnIndex) -> PeerId {
        todo!()
    }
}

fn to_fixed_data_columns<E: EthSpec>(
    data_column: Arc<DataColumnSidecar<E>>,
) -> FixedDataColumnSidecarList<E> {
    todo!();
}

#[derive(Debug, Clone)]
pub enum SamplingMessage {}

impl<T: BeaconChainTypes> Stream for Sampling<T> {
    type Item = SamplingMessage;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        todo!()
    }
}

struct SamplingRequest {
    id: Id,
    slot: Slot,
    block_root: Hash256,
    columns_to_sample: Vec<ColumnIndex>,
}

impl SamplingRequest {
    fn new(id: Id, slot: Slot, block_root: Hash256) -> Self {
        let mut rng = thread_rng();
        let mut columns_to_sample: Vec<ColumnIndex> = (0..64).collect();
        columns_to_sample.shuffle(&mut rng);

        Self {
            id,
            slot,
            block_root,
            columns_to_sample,
        }
    }

    fn register_valid(&mut self, column_index: ColumnIndex) {
        todo!()
    }

    fn register_invalid(&mut self, column_index: ColumnIndex) {
        todo!()
    }
}
