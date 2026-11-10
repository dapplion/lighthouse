//! Decides when queued unaggregated gossip attestations are handed to a worker.
//!
//! Without this policy an attestation is verified individually whenever a worker is free, so
//! batches only form when every worker is busy. On a machine with many cores that almost never
//! happens.
//!
//! The policy holds attestations in the queue while another attestation worker is still running,
//! so the attestations that arrive during that verification form the next batch. It never waits
//! on a quiet node: with no attestation worker running the first attestation is released at once.
//!
//! Queued attestations are released when any of these is true:
//!
//! - No attestation worker is running.
//! - The queue holds a full batch.
//! - The queue has been non-empty for `max_hold`.
//!
//! The policy only decides. The `BeaconProcessor` manager owns the queue, the workers and the
//! timer.

use std::time::{Duration, Instant};
use strum::IntoStaticStr;

/// Why queued attestations are released to a worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum ReleaseReason {
    /// Holding is disabled, attestations are never held back from a free worker.
    Disabled,
    /// No attestation worker is running, so there is nothing to wait for.
    NoWorkerRunning,
    /// The queue holds at least one full batch.
    BatchFull,
    /// The queue has been non-empty for the maximum hold time.
    Deadline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldDecision {
    /// Hand the queued attestations to a worker now.
    Release(ReleaseReason),
    /// Keep the attestations queued until `deadline`, unless another release condition is met
    /// first.
    Hold { deadline: Instant },
}

pub struct AttestationHold {
    /// The longest time the queue may stay non-empty while a worker is free. Zero disables
    /// holding.
    max_hold: Duration,
    /// Number of running workers that are verifying unaggregated gossip attestations.
    workers_running: usize,
    /// When the queue last went from empty to non-empty. Every queued attestation arrived at or
    /// after this instant.
    queued_since: Option<Instant>,
}

impl AttestationHold {
    pub fn new(max_hold: Duration) -> Self {
        Self {
            max_hold,
            workers_running: 0,
            queued_since: None,
        }
    }

    pub fn is_enabled(&self) -> bool {
        !self.max_hold.is_zero()
    }

    /// An attestation was pushed to the queue.
    pub fn on_queued(&mut self, now: Instant) {
        if self.queued_since.is_none() {
            self.queued_since = Some(now);
        }
    }

    /// A worker was spawned with attestations popped from the queue, leaving `queue_len` behind.
    ///
    /// Returns the instant since which the released attestations may have been queued.
    pub fn on_released(&mut self, queue_len: usize, now: Instant) -> Instant {
        self.workers_running = self.workers_running.saturating_add(1);
        let queued_since = self.queued_since.unwrap_or(now);
        if queue_len == 0 {
            self.queued_since = None;
        }
        queued_since
    }

    /// A worker that was verifying unaggregated gossip attestations has finished.
    pub fn on_worker_finished(&mut self) {
        self.workers_running = self.workers_running.saturating_sub(1);
    }

    /// Returns what to do with the `queue_len` queued attestations, or `None` if there are none.
    pub fn decide(
        &self,
        queue_len: usize,
        max_batch_size: usize,
        now: Instant,
    ) -> Option<HoldDecision> {
        if queue_len == 0 {
            return None;
        }
        if !self.is_enabled() {
            return Some(HoldDecision::Release(ReleaseReason::Disabled));
        }
        if self.workers_running == 0 {
            return Some(HoldDecision::Release(ReleaseReason::NoWorkerRunning));
        }
        if queue_len >= max_batch_size {
            return Some(HoldDecision::Release(ReleaseReason::BatchFull));
        }
        let deadline = self
            .queued_since
            .and_then(|queued_since| queued_since.checked_add(self.max_hold));
        match deadline {
            Some(deadline) if now < deadline => Some(HoldDecision::Hold { deadline }),
            // A missing `queued_since` for a non-empty queue is a bookkeeping error. Release
            // rather than risk holding an attestation without a deadline.
            Some(_) | None => Some(HoldDecision::Release(ReleaseReason::Deadline)),
        }
    }

    /// Returns when the manager must next look at the queue without being prompted by another
    /// event, given that a worker is free. `None` means no wake-up is needed.
    ///
    /// With holding disabled this is always `None`: the queue is then only drained when a worker
    /// finishes, as it was before holding existed.
    pub fn next_wakeup(
        &self,
        queue_len: usize,
        max_batch_size: usize,
        now: Instant,
    ) -> Option<Instant> {
        match self.decide(queue_len, max_batch_size, now)? {
            HoldDecision::Release(ReleaseReason::Disabled) => None,
            HoldDecision::Release(ReleaseReason::NoWorkerRunning)
            | HoldDecision::Release(ReleaseReason::BatchFull)
            | HoldDecision::Release(ReleaseReason::Deadline) => Some(now),
            HoldDecision::Hold { deadline } => Some(deadline),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_HOLD: Duration = Duration::from_millis(50);
    const MAX_BATCH: usize = 64;

    fn release(reason: ReleaseReason) -> Option<HoldDecision> {
        Some(HoldDecision::Release(reason))
    }

    #[test]
    fn empty_queue_needs_no_decision() {
        let now = Instant::now();
        let hold = AttestationHold::new(MAX_HOLD);
        assert_eq!(hold.decide(0, MAX_BATCH, now), None);
        assert_eq!(hold.next_wakeup(0, MAX_BATCH, now), None);
    }

    #[test]
    fn released_at_once_when_no_worker_is_running() {
        let now = Instant::now();
        let mut hold = AttestationHold::new(MAX_HOLD);
        hold.on_queued(now);
        assert_eq!(
            hold.decide(1, MAX_BATCH, now),
            release(ReleaseReason::NoWorkerRunning)
        );
    }

    #[test]
    fn held_while_a_worker_is_running_until_it_finishes() {
        let start = Instant::now();
        let mut hold = AttestationHold::new(MAX_HOLD);
        hold.on_queued(start);
        assert_eq!(hold.on_released(0, start), start);

        let arrival = start + Duration::from_millis(1);
        hold.on_queued(arrival);
        assert_eq!(
            hold.decide(1, MAX_BATCH, arrival),
            Some(HoldDecision::Hold {
                deadline: arrival + MAX_HOLD
            })
        );
        assert_eq!(
            hold.next_wakeup(1, MAX_BATCH, arrival),
            Some(arrival + MAX_HOLD)
        );

        hold.on_worker_finished();
        assert_eq!(
            hold.decide(1, MAX_BATCH, arrival),
            release(ReleaseReason::NoWorkerRunning)
        );
    }

    #[test]
    fn full_batch_is_released_while_a_worker_is_running() {
        let now = Instant::now();
        let mut hold = AttestationHold::new(MAX_HOLD);
        hold.on_queued(now);
        hold.on_released(0, now);
        hold.on_queued(now);
        assert_eq!(
            hold.decide(MAX_BATCH - 1, MAX_BATCH, now),
            Some(HoldDecision::Hold {
                deadline: now + MAX_HOLD
            })
        );
        assert_eq!(
            hold.decide(MAX_BATCH, MAX_BATCH, now),
            release(ReleaseReason::BatchFull)
        );
    }

    #[test]
    fn deadline_is_measured_from_the_oldest_queued_attestation() {
        let start = Instant::now();
        let mut hold = AttestationHold::new(MAX_HOLD);
        hold.on_queued(start);
        hold.on_released(0, start);

        hold.on_queued(start);
        // A later arrival does not extend the deadline.
        hold.on_queued(start + Duration::from_millis(40));
        let just_before = start + MAX_HOLD - Duration::from_nanos(1);
        assert_eq!(
            hold.decide(2, MAX_BATCH, just_before),
            Some(HoldDecision::Hold {
                deadline: start + MAX_HOLD
            })
        );
        assert_eq!(
            hold.decide(2, MAX_BATCH, start + MAX_HOLD),
            release(ReleaseReason::Deadline)
        );
    }

    #[test]
    fn deadline_survives_a_release_that_leaves_attestations_behind() {
        let start = Instant::now();
        let mut hold = AttestationHold::new(MAX_HOLD);
        hold.on_queued(start);
        // One full batch is released, one attestation stays queued.
        assert_eq!(hold.on_released(1, start), start);
        assert_eq!(
            hold.decide(1, MAX_BATCH, start + MAX_HOLD),
            release(ReleaseReason::Deadline)
        );
        // Once the queue is drained the next arrival starts a new hold.
        hold.on_released(0, start + MAX_HOLD);
        let arrival = start + Duration::from_secs(1);
        hold.on_queued(arrival);
        assert_eq!(
            hold.decide(1, MAX_BATCH, arrival),
            Some(HoldDecision::Hold {
                deadline: arrival + MAX_HOLD
            })
        );
    }

    #[test]
    fn zero_max_hold_disables_holding() {
        let now = Instant::now();
        let mut hold = AttestationHold::new(Duration::ZERO);
        assert!(!hold.is_enabled());
        hold.on_queued(now);
        hold.on_released(0, now);
        hold.on_queued(now);
        assert_eq!(
            hold.decide(1, MAX_BATCH, now),
            release(ReleaseReason::Disabled)
        );
        assert_eq!(hold.next_wakeup(1, MAX_BATCH, now), None);
    }

    #[test]
    fn batch_size_of_one_never_holds() {
        let now = Instant::now();
        let mut hold = AttestationHold::new(MAX_HOLD);
        hold.on_queued(now);
        hold.on_released(0, now);
        hold.on_queued(now);
        assert_eq!(hold.decide(1, 1, now), release(ReleaseReason::BatchFull));
    }
}
