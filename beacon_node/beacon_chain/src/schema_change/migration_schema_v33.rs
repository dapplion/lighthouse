use crate::beacon_chain::{BeaconChainTypes, FORK_CHOICE_DB_KEY};
use crate::persisted_fork_choice::{PersistedForkChoiceV29, PersistedForkChoiceV33};
use store::hot_cold_store::HotColdDB;
use store::{DBColumn, Error as StoreError, KeyValueStore, KeyValueStoreOp};

/// Upgrade from schema v32 to v33.
///
/// Adds the inclusion list satisfaction of each fork choice node, recorded as satisfied.
///
/// Returns a list of store ops to be applied atomically with the schema version write.
pub fn upgrade_to_v33<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
) -> Result<Vec<KeyValueStoreOp>, StoreError> {
    let Some(fc_bytes) = db
        .hot_db
        .get_bytes(DBColumn::ForkChoice, FORK_CHOICE_DB_KEY.as_slice())?
    else {
        return Ok(vec![]);
    };

    let persisted_v29 = PersistedForkChoiceV29::from_bytes(&fc_bytes, db.get_config())?;
    let persisted_v33 = PersistedForkChoiceV33::from(persisted_v29);

    Ok(vec![
        persisted_v33.as_kv_store_op(FORK_CHOICE_DB_KEY, db.get_config())?,
    ])
}

/// Downgrade from schema v33 to v32.
///
/// Drops the inclusion list satisfaction of each fork choice node.
///
/// Returns a list of store ops to be applied atomically with the schema version write.
pub fn downgrade_from_v33<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
) -> Result<Vec<KeyValueStoreOp>, StoreError> {
    let Some(fc_bytes) = db
        .hot_db
        .get_bytes(DBColumn::ForkChoice, FORK_CHOICE_DB_KEY.as_slice())?
    else {
        return Ok(vec![]);
    };

    let persisted_v33 = PersistedForkChoiceV33::from_bytes(&fc_bytes, db.get_config())?;
    let persisted_v29 = PersistedForkChoiceV29::from(persisted_v33);

    Ok(vec![
        persisted_v29.as_kv_store_op(FORK_CHOICE_DB_KEY, db.get_config())?,
    ])
}
