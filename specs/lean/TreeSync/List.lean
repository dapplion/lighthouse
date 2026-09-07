/-!
# Generic list algebra used by the tree-sync formalisation

Everything the tree-sync invariants need about lists lives here, so that the spec files
below stay readable.  We deliberately depend on Lean core + `Init` only: no mathlib.

The single workhorse is `Linked R l`, "consecutive elements of `l` are related by `R`".
Three of the spec's invariants are instances of it:

* Inv 2 (`roots` contiguous by `parent_root`) is `Linked (fun a b => parent a.1 = b.1)`.
* Inv 4 (`slot` strictly decreases)            is `Linked (fun a b => b.2 < a.2)`.
* Inv 5's linkage (`parent (blocks[i]) = blocks[i-1]`) is `Linked (fun a b => b.parent = a.root)`.

Proving `take`/`drop`/`append` closure once therefore discharges all three.
-/

namespace TreeSync

universe u

variable {α : Type u}

/-- `Linked R l` holds when every adjacent pair of `l` is related by `R`. -/
def Linked (R : α → α → Prop) : List α → Prop
  | [] => True
  | [_] => True
  | a :: b :: t => R a b ∧ Linked R (b :: t)

@[simp] theorem linked_nil {R : α → α → Prop} : Linked R ([] : List α) := trivial

@[simp] theorem linked_singleton {R : α → α → Prop} (a : α) : Linked R [a] := trivial

@[simp] theorem linked_cons_cons {R : α → α → Prop} {a b : α} {t : List α} :
    Linked R (a :: b :: t) ↔ (R a b ∧ Linked R (b :: t)) := Iff.rfl

/-- Dropping the head preserves `Linked`. -/
theorem Linked.tail {R : α → α → Prop} : ∀ {a : α} {l : List α}, Linked R (a :: l) → Linked R l
  | _, [], _ => trivial
  | _, _ :: _, h => h.2

/-- Every prefix of a `Linked` list is `Linked`.  Used for the newer half `Z` of a `Split`. -/
theorem Linked.take {R : α → α → Prop} : ∀ {l : List α} (n : Nat), Linked R l → Linked R (l.take n)
  | [], n, _ => by simp
  | [_], n, _ => by cases n <;> simp
  | _ :: _ :: _, 0, _ => by simp
  | a :: b :: t, (n + 1), h => by
      cases n with
      | zero => simp
      | succ m =>
          have ih := Linked.take (l := b :: t) (m + 1) h.2
          simpa [List.take] using And.intro h.1 ih

/-- Every suffix of a `Linked` list is `Linked`.  Used for the older half `Y` of a `Split`. -/
theorem Linked.drop {R : α → α → Prop} : ∀ {l : List α} (n : Nat), Linked R l → Linked R (l.drop n)
  | _, 0, h => h
  | [], (_ + 1), _ => by simp
  | [_], (n + 1), _ => by simp
  | _ :: b :: t, (n + 1), h => by
      simpa [List.drop] using Linked.drop (l := b :: t) n h.2

@[simp] theorem getLast?_cons_cons {a b : α} {t : List α} :
    (a :: b :: t).getLast? = (b :: t).getLast? := rfl

/-- Concatenation: `Linked` on both halves plus a link across the seam. -/
theorem linked_append {R : α → α → Prop} :
    ∀ {l₁ l₂ : List α}, Linked R l₁ → Linked R l₂ →
      (∀ x ∈ l₁.getLast?, ∀ y ∈ l₂.head?, R x y) → Linked R (l₁ ++ l₂)
  | [], l₂, _, h₂, _ => by simpa using h₂
  | [a], l₂, _, h₂, hlink => by
      cases l₂ with
      | nil => simp
      | cons b t =>
          refine ⟨hlink a (by simp) b (by simp), by simpa using h₂⟩
  | a :: b :: t, l₂, h₁, h₂, hlink => by
      refine ⟨h₁.1, ?_⟩
      simpa using linked_append (l₁ := b :: t) h₁.2 h₂ (by simpa using hlink)

/-- Splitting: `Linked` on a concatenation restricts to both halves. -/
theorem linked_append_left {R : α → α → Prop} {l₁ l₂ : List α}
    (h : Linked R (l₁ ++ l₂)) : Linked R l₁ := by
  have := Linked.take (R := R) l₁.length h
  simpa using this

theorem linked_append_right {R : α → α → Prop} {l₁ l₂ : List α}
    (h : Linked R (l₁ ++ l₂)) : Linked R l₂ := by
  have := Linked.drop (R := R) l₁.length h
  simpa using this


/-! ### Transport of `Linked` along `map` and `reverse` -/

/-- `Linked` only sees adjacent pairs, so it commutes with `List.map`. -/
theorem linked_map {β : Type u} {R : β → β → Prop} {f : α → β} :
    ∀ {l : List α}, Linked (fun a b => R (f a) (f b)) l ↔ Linked R (l.map f)
  | [] => by simp
  | [_] => by simp
  | a :: b :: t => by
      simp only [List.map_cons, linked_cons_cons]
      exact and_congr Iff.rfl (linked_map (l := b :: t))

/-- Reversing a list reverses the relation. -/
theorem linked_reverse {R : α → α → Prop} :
    ∀ {l : List α}, Linked R l → Linked (fun a b => R b a) l.reverse
  | [], _ => by simp
  | a :: l, h => by
      rw [List.reverse_cons]
      refine linked_append (linked_reverse (Linked.tail h)) (by simp) ?_
      intro x hx y hy
      rw [List.getLast?_reverse] at hx
      simp only [List.head?_cons, Option.mem_def, Option.some.injEq] at hy
      subst hy
      cases l with
      | nil => simp at hx
      | cons b t =>
          simp only [List.head?_cons, Option.mem_def, Option.some.injEq] at hx
          subst hx
          exact h.1

/-- Weakening the relation, allowed to use membership in the list. -/
theorem Linked.imp_mem {R S : α → α → Prop} :
    ∀ {l : List α}, (∀ a ∈ l, ∀ b ∈ l, R a b → S a b) → Linked R l → Linked S l
  | [], _, _ => trivial
  | [_], _, _ => trivial
  | a :: b :: t, hs, h =>
      ⟨hs a (by simp) b (by simp) h.1,
       Linked.imp_mem (fun x hx y hy => hs x (List.mem_cons_of_mem a hx) y
         (List.mem_cons_of_mem a hy)) h.2⟩

/-! ### Small `take`/`drop`/`filter` facts we would otherwise have to guess the names of -/

theorem take_length_append (A B : List α) : (A ++ B).take A.length = A := by
  induction A with
  | nil => rfl
  | cons a t ih => simp

theorem drop_length_append (A B : List α) : (A ++ B).drop A.length = B := by
  induction A with
  | nil => rfl
  | cons a t ih => simp

/-- No element of the left half of a duplicate-free concatenation occurs on the right. -/
theorem notMem_right_of_nodup_append [DecidableEq α] :
    ∀ {A B : List α}, (A ++ B).Nodup → ∀ x ∈ A, x ∉ B
  | [], _, _, x, hx, _ => by simp at hx
  | a :: t, B, h, x, hx, hxB => by
      rw [List.cons_append, List.nodup_cons] at h
      rcases List.mem_cons.1 hx with rfl | hx'
      · exact h.1 (List.mem_append_right _ hxB)
      · exact notMem_right_of_nodup_append h.2 x hx' hxB

end TreeSync
