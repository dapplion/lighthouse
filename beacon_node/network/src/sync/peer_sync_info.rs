use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::{SyncInfo, SyncStatus as PeerSyncStatus};
use strum::IntoStaticStr;

/// The type of peer relative to our current state.
pub enum PeerSyncType {
    /// The peer is on our chain and is fully synced with respect to our chain.
    FullySynced,
    /// The peer claims to have a finalized or head block we don't know about, trigger range sync.
    Advanced(RangeSyncType),
    /// A peer is behind in the sync and not useful to us for downloading blocks.
    Behind,
}

/// The type of Range sync that should be done relative to our current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoStaticStr)]
pub enum RangeSyncType {
    /// A finalized chain sync should be started with this peer.
    Finalized,
    /// A head chain sync should be started with this peer.
    Head,
}

impl PeerSyncType {
    pub fn as_sync_status(&self, info: &SyncInfo) -> PeerSyncStatus {
        match self {
            PeerSyncType::FullySynced => PeerSyncStatus::Synced { info: info.clone() },
            PeerSyncType::Behind => PeerSyncStatus::Behind { info: info.clone() },
            PeerSyncType::Advanced { .. } => PeerSyncStatus::Advanced { info: info.clone() },
        }
    }
}

pub fn remote_sync_type<T: BeaconChainTypes>(
    local: &SyncInfo,
    remote: &SyncInfo,
    chain: &BeaconChain<T>,
) -> PeerSyncType {
    // Range sync role is to discover and download all blocks that may be potentially useful to us.
    // Because the head and finalized store of peers updates asyncronously from us, peer can appear
    // to be advanced or behind us when they are not. However, this function will err on the side of
    // download anything that could be potentially unknown.
    //
    // checkpoints:  | N-m   | ... | N-1   | N    | N+1   | ... | N+m   |
    //                ^              ^       ^      ^             ^
    //                Peer clearly   Peer maybe synced            Peer clearly
    //                behind         or not                       advanced
    //

    // Clearly behind, plus we don't want to dig into the DB to check if we know this finalzed root
    if remote.finalized_epoch < local.finalized_epoch {
        // The node has a lower finalized epoch, their chain is not useful to us. There are two
        // cases where a node can have a lower finalized epoch:
        //
        // ## The node is on the same chain
        //
        // If a node is on the same chain but has a lower finalized epoch, their head must be
        // lower than ours. Therefore, we have nothing to request from them.
        //
        // ## The node is on a fork
        //
        // If a node is on a fork that has a lower finalized epoch, switching to that fork would
        // cause us to revert a finalized block. This is not permitted, therefore we have no
        // interest in their blocks.
        //
        // We keep these peers to allow them to sync from us.
        return PeerSyncType::Behind;
    }

    // Clearly ahead, remote peer has a finalized block we should download
    // TODO: does block_is_known_to_fork_choice return true for its current finalized block?
    if !chain.block_is_known_to_fork_choice(&remote.finalized_root) {
        return PeerSyncType::Advanced(RangeSyncType::Finalized);
    }

    // If we share the same finalized block we want to sync any unknown heads. It doesn't matter if
    // the remote head is ahead or behind ours in terms of slot
    if !chain.block_is_known_to_fork_choice(&remote.head_root) {
        return PeerSyncType::Advanced(RangeSyncType::Head);
    }

    PeerSyncType::FullySynced
}
