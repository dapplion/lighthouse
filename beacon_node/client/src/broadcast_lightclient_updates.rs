use beacon_chain::{BeaconChain, BeaconChainTypes, LightclientProducerEvent};
use eth2::types::EventKind;
use network::NetworkMessage;
use slog::{debug, error, Logger};
use tokio::sync::mpsc::{Receiver, UnboundedSender};

// Each LightclientProducerEvent is ~200 bytes. With the lightclient server producing only recent
// updates it is okay to drop some events in case of overloading. In normal network conditions
// there's one event emitted per block at most every 12 seconds, while consuming the event should
// take a few miliseconds. 32 is a small enough arbitrary number.
pub(crate) const LIGHTCLIENT_SERVER_CHANNEL_CAPACITY: usize = 32;

pub async fn compute_lightclient_updates<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    mut lightclient_server_rv: Receiver<LightclientProducerEvent<T::EthSpec>>,
    log: &Logger,
    network_send: Option<UnboundedSender<NetworkMessage<T::EthSpec>>>,
) {
    // lightclient_server_rv is Some if lightclient flag is enabled
    //
    // Should only receive events for recent blocks, import_block filters by blocks close to clock.
    //
    // Intents to process SyncAggregates of all recent blocks sequentially, without skipping.
    // Uses a bounded receiver, so may drop some SyncAggregates if very overloaded. This is okay
    // since only the most recent updates have value.
    while let Some((block_root, slot, sync_aggregate)) = lightclient_server_rv.recv().await {
        let (optimistic_update_to_broadcast, finality_update_to_broadcast) = match chain
            .recompute_and_cache_lightclient_updates((block_root, slot, sync_aggregate))
        {
            Ok(value) => value,
            Err(e) => {
                error!(log, "error computing lightclient updates {:?}", e);
                continue;
            }
        };

        if let Some(event_handler) = chain.event_handler.as_ref() {
            if let Some(optimistic_update) = optimistic_update_to_broadcast.clone() {
                event_handler.register(EventKind::LightClientOptimisticUpdate(Box::new(
                    optimistic_update,
                )));
            }
            if let Some(finality_update) = finality_update_to_broadcast.clone() {
                event_handler.register(EventKind::LightClientFinalityUpdate(Box::new(
                    finality_update,
                )));
            }
        }

        // network_send is Some when the network is enabled
        if let Some(ref network_send) = network_send {
            if let Some(optimistic_update) = optimistic_update_to_broadcast {
                let signature_slot = optimistic_update.signature_slot;
                let pubsub_message = lighthouse_network::PubsubMessage::LightClientOptimisticUpdate(
                    Box::new(optimistic_update),
                );
                if let Err(e) = network_send.send(NetworkMessage::Publish {
                    messages: vec![pubsub_message],
                }) {
                    debug!(
                        log,
                        "Failed to publish PubsubMessage::LightClientOptimisticUpdate message";
                        "slot" => signature_slot,
                        "error" => ?e,
                    );
                } else {
                    debug!(
                        log,
                        "Published PubsubMessage::LightClientOptimisticUpdate";
                        "slot" => signature_slot,
                    );
                }
            }

            if let Some(finality_update) = finality_update_to_broadcast {
                let signature_slot = finality_update.signature_slot;
                let pubsub_message = lighthouse_network::PubsubMessage::LightClientFinalityUpdate(
                    Box::new(finality_update),
                );
                if let Err(e) = network_send.send(NetworkMessage::Publish {
                    messages: vec![pubsub_message],
                }) {
                    debug!(
                        log,
                        "Failed to publish PubsubMessage::LightClientFinalityUpdate message";
                        "slot" => signature_slot,
                        "error" => ?e,
                    );
                } else {
                    debug!(
                        log,
                        "Published PubsubMessage::LightClientFinalityUpdate";
                        "slot" => signature_slot,
                    );
                }
            }
        }
    }
}
