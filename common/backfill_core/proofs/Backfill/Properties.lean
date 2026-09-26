/- Properties of the backfill sync core, proved against the model Aeneas extracted from
   `../src/lib.rs` by `../extract.sh`. These are theorems about the code that ships. -/
import Backfill.Core
import Aeneas

open Aeneas Aeneas.Std Aeneas.Std.WP Result

namespace backfill_core

/-- What a response must be to be accepted: newest first, starting at the root we asked for,
    each header the parent of the one before it, slots strictly decreasing below `bound`. -/
def Chained (expected : Root) (bound : Std.U64) : List Header → Prop
  | [] => True
  | h :: t => h.root = expected ∧ h.slot.val < bound.val ∧ Chained h.parent_root h.slot t

/-- The extracted `Root` is a plain record of four words, so equality on it is decidable;
    Aeneas does not derive the instance. -/
instance : DecidableEq Root := fun x y =>
  decidable_of_iff (x.a = y.a ∧ x.b = y.b ∧ x.c = y.c ∧ x.d = y.d) (by cases x; cases y; simp)

/-- Root equality is all 256 bits, so the checker's test is exactly equality of roots. -/
@[simp]
theorem root_eq_spec (x y : Root) : root_eq x y = ok (decide (x = y)) := by
  unfold root_eq
  cases x; cases y
  simp [Bool.and_assoc]

/-- The loop's `last` accumulator holds the last header it has seen, so prepending a header
    to the remaining run is absorbed by it. -/
theorem getLast?_or_cons (x : Header) (l : List Header) (d : Option Header) :
    ((x :: l).getLast?).or d = l.getLast?.or (some x) := by
  cases l with
  | nil => simp
  | cons a t =>
    rw [List.getLast?_cons_cons]
    cases h : (a :: t).getLast? with
    | none => simp at h
    | some v => simp

theorem check_run_loop_spec (headers : alloc.vec.Vec Header) (linked : Bool)
    (want : Root) (limit : Std.U64) (last : Option Header) (i : Std.Usize)
    (_hi : i.val ≤ headers.length) :
    check_run_loop headers linked want limit last i ⦃ lk lst =>
      (lk = true → linked = true ∧ Chained want limit (headers.val.drop i.val)) ∧
      lst = (headers.val.drop i.val).getLast?.or last ⦄ := by
  unfold check_run_loop
  simp
  split
  · step as ⟨header, hheader⟩
    step as ⟨i2⟩
    have hdrop : headers.val.drop i.val = header :: headers.val.drop (i.val + 1) := by
      rw [hheader]
      exact (List.getElem_cons_drop (by scalar_tac)).symm
    have hi2 : i2.val = i.val + 1 := by scalar_tac
    apply spec_mono (check_run_loop_spec headers _ header.parent_root header.slot
      (some header) i2 (by scalar_tac))
    rintro ⟨lk, lst⟩ h
    obtain ⟨h1, h2⟩ := h
    rw [hi2] at h1 h2
    constructor
    · intro hlk
      obtain ⟨hlinked, hchained⟩ := h1 hlk
      simp only [Bool.and_eq_true, decide_eq_true_eq] at hlinked
      obtain ⟨⟨hl, hroot⟩, hslot⟩ := hlinked
      refine ⟨hl, ?_⟩
      rw [hdrop]
      exact ⟨hroot, hslot, hchained⟩
    · rw [hdrop, h2, getLast?_or_cons]
  · simp [Chained, List.drop_eq_nil_of_le (by scalar_tac : headers.val.length ≤ i.val)]
termination_by headers.length - i.val
decreasing_by scalar_decr_tac

/-- Slots strictly decrease along a run, so its oldest header is below the bound. -/
theorem chained_getLast_slot (expected : Root) (bound : Std.U64) (l : List Header) (oldest : Header)
    (hc : Chained expected bound l) (hl : l.getLast? = some oldest) :
    oldest.slot.val < bound.val := by
  induction l generalizing expected bound with
  | nil => simp at hl
  | cons a t ih =>
    obtain ⟨hroot, hslot, htail⟩ := hc
    cases t with
    | nil => simp at hl; subst hl; exact hslot
    | cons b u =>
      rw [List.getLast?_cons_cons] at hl
      exact Nat.lt_trans (ih a.parent_root a.slot htail hl) hslot

/-- **S**, at the level of the checker: what `check_run` accepts is a hash-linked descent
    from the root that was asked for, and what it returns is that run's oldest header. -/
theorem check_run_spec (expected : Root) (bound : Std.U64) (headers : alloc.vec.Vec Header) :
    check_run expected bound headers ⦃ r => ∀ oldest, r = some oldest →
      Chained expected bound headers.val ∧ headers.val.getLast? = some oldest ⦄ := by
  unfold check_run
  apply spec_bind (check_run_loop_spec headers true expected bound none 0#usize (by simp))
  rintro ⟨lk, lst⟩ ⟨h1, h2⟩
  simp at h1 h2
  cases lk with
  | false => simp
  | true =>
    simp
    intro oldest hr
    have hchained := h1 rfl
    refine ⟨hchained, ?_⟩
    rw [h2] at hr
    simpa using hr

/-- `retry` spends one attempt, or parks with none left. Nothing else about the state moves,
    which is what makes it usable in both the safety and the progress argument. -/
@[step]
theorem retry_spec (bf : Backfill) :
    retry bf ⦃ bf' =>
      (∃ a, bf' = { bf with attempts := a, wait := Wait.Idle } ∧ a.val + 1 = bf.attempts.val) ∨
      bf' = { bf with attempts := 0#u8, wait := Wait.Parked } ⦄ := by
  unfold retry
  split
  · step as ⟨a⟩
    exact Or.inl ⟨a, rfl, by scalar_tac⟩
  · exact Or.inr rfl

/-- **S**: nothing reaches the store but a run that is hash-linked from the frontier, and the
    header staged to become the new frontier is that run's oldest.

    Production has no such guarantee: `import_historical_block_batch` is the only thing that
    checks the linkage, so sync hands it unchecked candidates and learns by rejection. -/
theorem store_is_verified_descent (bf : Backfill) (ev : Event) :
    step bf ev ⦃ acts bf' => ∀ hs, Action.Store hs ∈ acts.val →
      ∃ oldest peer,
        Chained bf.frontier.parent_root bf.frontier.slot hs.val ∧
        hs.val.getLast? = some oldest ∧
        bf'.wait = Wait.Importing oldest peer ⦄ := by
  match ev with
  | Event.Tick =>
    simp only [step]
    unfold on_tick
    split
    · split
      · simp
      · step as ⟨out, hout⟩
        simp [hout]
    · simp
    · simp
    · simp
  | Event.Run peer headers =>
    simp only [step]
    unfold on_run
    split
    · simp
    · apply spec_bind (check_run_spec bf.frontier.parent_root bf.frontier.slot headers)
      intro r hr
      cases r with
      | none =>
        step as ⟨out, hout⟩
        step as ⟨bf1⟩
        simp [hout]
      | some oldest =>
        step as ⟨out, hout⟩
        intro hs hmem
        rw [hout] at hmem
        simp at hmem
        subst hmem
        exact ⟨oldest, peer, (hr oldest rfl).1, (hr oldest rfl).2, rfl⟩
    · simp
    · simp
  | Event.Fail peer =>
    simp only [step]
    unfold on_fail
    split
    · simp
    · step as ⟨bf1⟩
      simp
    · simp
    · simp
  | Event.Imported =>
    simp only [step]
    unfold on_imported
    split
    · simp
    · simp
    · split
      · step as ⟨out, hout⟩
        simp [hout]
      · simp
    · simp
  | Event.Rejected =>
    simp only [step]
    unfold on_rejected
    split
    · simp
    · simp
    · step as ⟨out, hout⟩
      step as ⟨bf1⟩
      simp [hout]
    · simp
  | Event.Abandoned =>
    simp only [step]
    unfold on_abandoned
    split
    · simp
    · simp
    · step as ⟨bf1⟩
      simp
    · simp
  | Event.PeerJoined =>
    simp only [step]
    unfold on_peer_joined
    split <;> simp

/-- **A**: a penalty always names the peer that served the thing being judged — the sender of
    a run that failed the check, or, when the store rejects a run that was hash-linked, the
    peer the state remembers as having served it.

    This is the one the range design cannot state. A response addressed by slot range is
    verified against its neighbours, so a fault has several suspects; addressed by root it has
    exactly one. Production's `participating_peers` set is drained into `report_peer` and
    filled nowhere in the repository, and a Gloas envelope fault penalises the blocks peer. -/
theorem penalize_names_the_server (bf : Backfill) (ev : Event) :
    step bf ev ⦃ acts _bf' => ∀ p, Action.Penalize p ∈ acts.val →
      (∃ hs, ev = Event.Run p hs) ∨
      (ev = Event.Rejected ∧ ∃ staged, bf.wait = Wait.Importing staged p) ⦄ := by
  match ev with
  | Event.Tick =>
    simp only [step]
    unfold on_tick
    split
    · split
      · simp
      · step as ⟨out, hout⟩
        simp [hout]
    · simp
    · simp
    · simp
  | Event.Run peer headers =>
    simp only [step]
    unfold on_run
    split
    · simp
    · apply spec_bind (check_run_spec bf.frontier.parent_root bf.frontier.slot headers)
      intro r _hr
      cases r with
      | none =>
        step as ⟨out, hout⟩
        step as ⟨bf1⟩
        intro p hmem
        rw [hout] at hmem
        simp at hmem
        subst hmem
        exact Or.inl ⟨headers, rfl⟩
      | some oldest =>
        step as ⟨out, hout⟩
        simp [hout]
    · simp
    · simp
  | Event.Fail peer =>
    simp only [step]
    unfold on_fail
    split
    · simp
    · step as ⟨bf1⟩
      simp
    · simp
    · simp
  | Event.Imported =>
    simp only [step]
    unfold on_imported
    split
    · simp
    · simp
    · split
      · step as ⟨out, hout⟩
        simp [hout]
      · simp
    · simp
  | Event.Rejected =>
    simp only [step]
    unfold on_rejected
    split
    · simp
    · simp
    · rename_i staged peer heq
      step as ⟨out, hout⟩
      step as ⟨bf1⟩
      intro p hmem
      rw [hout] at hmem
      simp at hmem
      subst hmem
      exact Or.inr ⟨staged, heq⟩
    · simp
  | Event.Abandoned =>
    simp only [step]
    unfold on_abandoned
    split
    · simp
    · simp
    · step as ⟨bf1⟩
      simp
    · simp
  | Event.PeerJoined =>
    simp only [step]
    unfold on_peer_joined
    split <;> simp

/-- Where the machine is in one round trip. Every transition that moves neither the frontier
    nor the budget still moves one place down this list. -/
def phase (w : Wait) : Nat :=
  match w with
  | Wait.Idle => 3
  | Wait.Pending => 2
  | Wait.Importing _ _ => 1
  | Wait.Parked => 0

/-- The measure. Importing a run is worth more than any amount of retrying: the frontier term
    dominates because `attempts` is a `u8` and `phase` is at most 3. -/
def mu (bf : Backfill) : Nat :=
  bf.frontier.slot.val * 1024 + bf.attempts.val * 4 + phase bf.wait

/-- The staged header is strictly older than the frontier, so an import is always progress;
    and `done` means the frontier really did reach the target. -/
def Inv (bf : Backfill) : Prop :=
  (∀ staged peer, bf.wait = Wait.Importing staged peer →
    staged.slot.val < bf.frontier.slot.val) ∧
  (bf.done = true → bf.frontier.slot.val ≤ bf.target_slot.val)

/-- **R**: the invariant is re-established from the anchor alone. The whole persisted state is
    the frontier — `AnchorInfo`'s `oldest_block_parent` and `oldest_block_slot` — so a restart
    is not a special case and there is nothing to drift. -/
theorem inv_from_anchor (cfg : Config) (oldest : Header) (target : Std.U64) :
    from_anchor cfg oldest target ⦃ bf => Inv bf ⦄ := by
  unfold from_anchor Inv
  simp

/-- **R**, second half: every step preserves it, so every reachable state is one `from_anchor`
    would accept. -/
theorem inv_step (bf : Backfill) (ev : Event) (hinv : Inv bf) :
    step bf ev ⦃ _acts bf' => Inv bf' ⦄ := by
  obtain ⟨hstaged, hdone⟩ := hinv
  match ev with
  | Event.Tick =>
    simp only [step]
    unfold on_tick
    split
    · split
      · exact ⟨hstaged, hdone⟩
      · step as ⟨out, _⟩
        exact ⟨by simp, hdone⟩
    · exact ⟨hstaged, hdone⟩
    · exact ⟨hstaged, hdone⟩
    · exact ⟨hstaged, hdone⟩
  | Event.Run peer headers =>
    simp only [step]
    unfold on_run
    split
    · exact ⟨hstaged, hdone⟩
    · apply spec_bind (check_run_spec bf.frontier.parent_root bf.frontier.slot headers)
      intro r hr
      cases r with
      | none =>
        step as ⟨out, _⟩
        step as ⟨bf1, hbf1⟩
        rcases hbf1 with ⟨a, rfl, _⟩ | rfl <;> exact ⟨by simp, hdone⟩
      | some oldest =>
        step as ⟨out, _⟩
        obtain ⟨hchained, hlast⟩ := hr oldest rfl
        refine ⟨?_, hdone⟩
        intro staged' peer' heq
        simp only [Wait.Importing.injEq] at heq
        obtain ⟨rfl, _⟩ := heq
        exact chained_getLast_slot _ _ _ _ hchained hlast
    · exact ⟨hstaged, hdone⟩
    · exact ⟨hstaged, hdone⟩
  | Event.Fail peer =>
    simp only [step]
    unfold on_fail
    split
    · exact ⟨hstaged, hdone⟩
    · step as ⟨bf1, hbf1⟩
      rcases hbf1 with ⟨a, rfl, _⟩ | rfl <;> exact ⟨by simp, hdone⟩
    · exact ⟨hstaged, hdone⟩
    · exact ⟨hstaged, hdone⟩
  | Event.Imported =>
    simp only [step]
    unfold on_imported
    split
    · exact ⟨hstaged, hdone⟩
    · exact ⟨hstaged, hdone⟩
    · rename_i staged peer heq
      have holder := hstaged staged peer heq
      split
      · rename_i htarget
        step as ⟨out, _⟩
        exact ⟨by simp, fun _ => by scalar_tac⟩
      · rename_i htarget
        exact ⟨by simp, fun hd => by have := hdone hd; scalar_tac⟩
    · exact ⟨hstaged, hdone⟩
  | Event.Rejected =>
    simp only [step]
    unfold on_rejected
    split
    · exact ⟨hstaged, hdone⟩
    · exact ⟨hstaged, hdone⟩
    · step as ⟨out, _⟩
      step as ⟨bf1, hbf1⟩
      rcases hbf1 with ⟨a, rfl, _⟩ | rfl <;> exact ⟨by simp, hdone⟩
    · exact ⟨hstaged, hdone⟩
  | Event.Abandoned =>
    simp only [step]
    unfold on_abandoned
    split
    · exact ⟨hstaged, hdone⟩
    · exact ⟨hstaged, hdone⟩
    · step as ⟨bf1, hbf1⟩
      rcases hbf1 with ⟨a, rfl, _⟩ | rfl <;> exact ⟨by simp, hdone⟩
    · exact ⟨hstaged, hdone⟩
  | Event.PeerJoined =>
    simp only [step]
    unfold on_peer_joined
    split
    · exact ⟨hstaged, hdone⟩
    · exact ⟨hstaged, hdone⟩
    · exact ⟨hstaged, hdone⟩
    · exact ⟨by simp, hdone⟩

/-- **P**: every event but `PeerJoined` either leaves the state exactly as it was and emits
    nothing, or strictly decreases the measure. So the machine has no internal loop: an
    infinite run contains infinitely many `PeerJoined` events.

    The budget is refilled only by an import — only when the first component of the measure
    strictly decreases. That is exactly what production gets wrong: `batch.rs`'s
    `non_faulty_processing_attempts` is incremented and never compared to a limit, which is a
    budget that never runs out and an unbounded re-download loop. -/
theorem progress (bf : Backfill) (ev : Event) (hinv : Inv bf) (hev : ev ≠ Event.PeerJoined) :
    step bf ev ⦃ acts bf' => (bf' = bf ∧ acts.val = []) ∨ mu bf' < mu bf ⦄ := by
  obtain ⟨hstaged, _⟩ := hinv
  match ev with
  | Event.Tick =>
    simp only [step]
    unfold on_tick
    split
    · split
      · exact Or.inl ⟨rfl, by simp⟩
      · rename_i hwait _
        step as ⟨out, _⟩
        exact Or.inr (by simp [mu, phase, hwait])
    · exact Or.inl ⟨rfl, by simp⟩
    · exact Or.inl ⟨rfl, by simp⟩
    · exact Or.inl ⟨rfl, by simp⟩
  | Event.Run peer headers =>
    simp only [step]
    unfold on_run
    split
    · exact Or.inl ⟨rfl, by simp⟩
    · rename_i hwait
      apply spec_bind (check_run_spec bf.frontier.parent_root bf.frontier.slot headers)
      intro r _hr
      cases r with
      | none =>
        step as ⟨out, _⟩
        step as ⟨bf1, hbf1⟩
        rcases hbf1 with ⟨a, rfl, ha⟩ | rfl <;>
          exact Or.inr (by simp [mu, phase, hwait]; scalar_tac)
      | some oldest =>
        step as ⟨out, _⟩
        exact Or.inr (by simp [mu, phase, hwait])
    · exact Or.inl ⟨rfl, by simp⟩
    · exact Or.inl ⟨rfl, by simp⟩
  | Event.Fail peer =>
    simp only [step]
    unfold on_fail
    split
    · exact Or.inl ⟨rfl, by simp⟩
    · rename_i hwait
      step as ⟨bf1, hbf1⟩
      rcases hbf1 with ⟨a, rfl, ha⟩ | rfl <;>
        exact Or.inr (by simp [mu, phase, hwait]; scalar_tac)
    · exact Or.inl ⟨rfl, by simp⟩
    · exact Or.inl ⟨rfl, by simp⟩
  | Event.Imported =>
    simp only [step]
    unfold on_imported
    split
    · exact Or.inl ⟨rfl, by simp⟩
    · exact Or.inl ⟨rfl, by simp⟩
    · rename_i staged peer hwait
      have holder := hstaged staged peer hwait
      split <;>
        [(step as ⟨out, _⟩; skip); skip] <;>
        exact Or.inr (by simp [mu, phase, hwait]; scalar_tac)
    · exact Or.inl ⟨rfl, by simp⟩
  | Event.Rejected =>
    simp only [step]
    unfold on_rejected
    split
    · exact Or.inl ⟨rfl, by simp⟩
    · exact Or.inl ⟨rfl, by simp⟩
    · rename_i staged peer hwait
      step as ⟨out, _⟩
      step as ⟨bf1, hbf1⟩
      rcases hbf1 with ⟨a, rfl, ha⟩ | rfl <;>
        exact Or.inr (by simp [mu, phase, hwait] <;> scalar_tac)
    · exact Or.inl ⟨rfl, by simp⟩
  | Event.Abandoned =>
    simp only [step]
    unfold on_abandoned
    split
    · exact Or.inl ⟨rfl, by simp⟩
    · exact Or.inl ⟨rfl, by simp⟩
    · rename_i staged peer hwait
      step as ⟨bf1, hbf1⟩
      rcases hbf1 with ⟨a, rfl, ha⟩ | rfl <;>
        exact Or.inr (by simp [mu, phase, hwait] <;> scalar_tac)
    · exact Or.inl ⟨rfl, by simp⟩
  | Event.PeerJoined => exact absurd rfl hev

#print axioms check_run_spec
#print axioms store_is_verified_descent
#print axioms penalize_names_the_server
#print axioms inv_from_anchor
#print axioms inv_step
#print axioms progress

end backfill_core
