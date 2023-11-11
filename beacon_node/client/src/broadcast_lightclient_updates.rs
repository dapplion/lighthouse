use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::types::{EventKind, SseBlock};
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use slog::{debug, error, Logger};
use slot_clock::SlotClock;
use tokio::sync::mpsc::UnboundedSender;
use types::{ForkName, Slot};

// Block event is emitted during sync. Do not emit lightclient updates until close enough to head.
const MAX_OLD_SLOT_TO_PUBLISH: Slot = Slot::new(100);

pub async fn broadcast_lightclient_updates<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    network_send: UnboundedSender<NetworkMessage<T::EthSpec>>,
    log: &Logger,
) {
    // event_handler.register(EventKind::Block(SseBlock {

    // TODO: event_handler is only present if HTTP API is enabled
    if let Some(event_handler) = chain.event_handler.as_ref() {
        while let Ok(block_event) = event_handler.subscribe_block().recv().await {
            if let EventKind::Block(block_event) = block_event {
                if let Err(e) =
                    do_broadcast_lightclient_updates(chain, network_send.clone(), log, block_event)
                {
                    error!(log, "error computing lightclient updates {:?}", e);
                }
            }
        }
    }
}

pub fn do_broadcast_lightclient_updates<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    network_send: UnboundedSender<NetworkMessage<T::EthSpec>>,
    log: &Logger,
    block_event: SseBlock,
) -> Result<(), BeaconChainError> {
    // Only post-altair
    if chain.spec.fork_name_at_slot::<T::EthSpec>(block_event.slot) == ForkName::Base {
        return Ok(());
    }

    // Block has recently been added to the DB on import_block.
    // TODO: consider emitting a different event with SyncAggregate
    let block =
        chain
            .get_blinded_block(&block_event.block)?
            .ok_or(BeaconChainError::DBInconsistent(format!(
                "Block not found {:?}",
                block_event.block
            )))?;

    if chain
        .slot_clock
        .now()
        .ok_or(BeaconChainError::UnableToReadSlot)?
        - block.slot()
        > MAX_OLD_SLOT_TO_PUBLISH
    {
        return Ok(());
    }

    chain.recompute_and_cache_lightclient_updates(
        &block.message().parent_root(),
        block.message().slot(),
        block.message().body().sync_aggregate()?,
    )?;

    let mut messages = vec![];

    if let Some(update) = chain.lightclient_server_cache.get_latest_finality_update() {
        messages.push(PubsubMessage::LightClientFinalityUpdate(Box::new(update)));
    }

    if let Some(update) = chain
        .lightclient_server_cache
        .get_latest_optimistic_update()
    {
        messages.push(PubsubMessage::LightClientOptimisticUpdate(Box::new(update)));
    }

    if let Err(e) = network_send.send(NetworkMessage::Publish { messages }) {
        debug!(
            log,
            "Failed to publish light client updates";
            "error" => ?e,
        );
    } else {
        debug!(
            log,
            "Published light client updates ";
        );
    }

    Ok(())
}