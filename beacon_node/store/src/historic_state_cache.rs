use crate::hdiff::{Error, HDiffBuffer};
use crate::metrics;
use hashlink::lru_cache::LruCache;
use std::sync::Arc;
use tracing::warn;
use types::{BeaconState, ChainSpec, EthSpec, Slot};

/// Holds a combination of finalized states in two formats:
/// - `hdiff_buffers`: Format close to an SSZ serialized state for rapid application of diffs on top
///   of it
/// - `states`: Deserialized states for direct use or for rapid application of blocks (replay)
///
/// An example use: when requesting state data for consecutive slots, this cache allows the node to
/// apply diffs once on the first request, and latter just apply blocks one at a time.
#[derive(Debug)]
pub struct HistoricStateCache<E: EthSpec> {
    hdiff_buffers: LruCache<Slot, Arc<HDiffBuffer<E>>>,
    states: LruCache<Slot, BeaconState<E>>,
}

#[derive(Debug, Default)]
pub struct Metrics {
    pub num_hdiff: usize,
    pub num_state: usize,
    pub hdiff_byte_size: usize,
}

impl<E: EthSpec> HistoricStateCache<E> {
    pub fn new(hdiff_buffer_cache_size: usize, state_cache_size: usize) -> Self {
        Self {
            hdiff_buffers: LruCache::new(hdiff_buffer_cache_size),
            states: LruCache::new(state_cache_size),
        }
    }

    pub fn get_hdiff_buffer(&mut self, slot: Slot) -> Option<Arc<HDiffBuffer<E>>> {
        if let Some(buffer_ref) = self.hdiff_buffers.get(&slot) {
            let _timer = metrics::start_timer_vec(
                &metrics::BEACON_HDIFF_BUFFER_CLONE_TIME,
                metrics::COLD_METRIC,
            );
            Some(buffer_ref.clone())
        } else if let Some(state) = self.states.get(&slot) {
            let buffer = HDiffBuffer::from_state(state.clone())
                .map(Arc::new)
                .inspect_err(|e| warn!(error = ?e, "Failed to build hdiff buffer"))
                .ok()?;
            let _timer = metrics::start_timer_vec(
                &metrics::BEACON_HDIFF_BUFFER_CLONE_TIME,
                metrics::COLD_METRIC,
            );
            let cloned = buffer.clone();
            drop(_timer);
            self.hdiff_buffers.insert(slot, cloned);
            Some(buffer)
        } else {
            None
        }
    }

    pub fn get_state(
        &mut self,
        slot: Slot,
        spec: &ChainSpec,
    ) -> Result<Option<BeaconState<E>>, Error> {
        if let Some(state) = self.states.get(&slot) {
            Ok(Some(state.clone()))
        } else if let Some(buffer) = self.hdiff_buffers.get(&slot) {
            let state = buffer.as_state(spec)?;
            self.states.insert(slot, state.clone());
            Ok(Some(state))
        } else {
            Ok(None)
        }
    }

    pub fn put_state(&mut self, slot: Slot, state: BeaconState<E>) {
        self.states.insert(slot, state);
    }

    pub fn put_hdiff_buffer(&mut self, slot: Slot, buffer: Arc<HDiffBuffer<E>>) {
        // Record how much of the new buffer is actually private memory: Milhouse
        // sections shared with the most recently used cached buffer cost nothing.
        if let Some((_, base)) = self.hdiff_buffers.iter().next_back() {
            metrics::set_gauge(
                &metrics::STORE_BEACON_HDIFF_BUFFER_MARGINAL_BYTES,
                buffer.marginal_bytes_vs(base) as i64,
            );
        }
        self.hdiff_buffers.insert(slot, buffer);
    }

    pub fn put_both(&mut self, slot: Slot, state: BeaconState<E>, buffer: Arc<HDiffBuffer<E>>) {
        self.put_state(slot, state);
        self.put_hdiff_buffer(slot, buffer);
    }

    pub fn metrics(&self) -> Metrics {
        let hdiff_byte_size = self
            .hdiff_buffers
            .iter()
            .map(|(_, buffer)| buffer.size())
            .sum::<usize>();
        Metrics {
            num_hdiff: self.hdiff_buffers.len(),
            num_state: self.states.len(),
            hdiff_byte_size,
        }
    }
}
