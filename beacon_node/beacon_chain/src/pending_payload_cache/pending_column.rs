use kzg::KzgProof;
use ssz_types::VariableList;
use std::sync::Arc;
use types::{Cell, ColumnIndex, DataColumnSidecar, DataColumnSidecarGloas, EthSpec, Hash256, Slot};

#[derive(Clone, Default)]
pub struct PendingColumn<E: EthSpec> {
    /// Cells indexed by their position within the column. Grown on demand by `insert` so the
    /// caller doesn't have to know the blob count up front.
    cells: Vec<Option<(Cell<E>, KzgProof)>>,
}

impl<E: EthSpec> PendingColumn<E> {
    pub fn insert(&mut self, index: usize, cell: &Cell<E>, proof: &KzgProof) {
        if index >= self.cells.len() {
            self.cells.resize(index + 1, None);
        }
        let slot = &mut self.cells[index];
        if slot.is_none() {
            *slot = Some((cell.clone(), *proof));
        }
    }

    pub fn cell_matches(&self, index: usize, cell: &Cell<E>, proof: &KzgProof) -> Option<bool> {
        self.cells
            .get(index)?
            .as_ref()
            .map(|(c, p)| c == cell && p == proof)
    }

    pub fn is_complete(&self, blob_count: usize) -> bool {
        self.cells.len() >= blob_count && self.cells[..blob_count].iter().all(Option::is_some)
    }

    /// Build a `DataColumnSidecar` from the cached cells.
    ///
    /// Caller MUST have checked `is_complete(blob_count)` first; this returns `Err` only on the
    /// (currently theoretically impossible) `VariableList` size-bound failures, which we surface
    /// as a typed error so the caller can log/metric it instead of silently producing nothing.
    pub fn to_sidecar(
        &self,
        index: ColumnIndex,
        slot: Slot,
        beacon_block_root: Hash256,
        blob_count: usize,
    ) -> Result<Arc<DataColumnSidecar<E>>, PendingColumnError> {
        let mut column = Vec::with_capacity(blob_count);
        let mut kzg_proofs = Vec::with_capacity(blob_count);

        for entry in self
            .cells
            .get(..blob_count)
            .ok_or(PendingColumnError::IncompleteColumn)?
        {
            let (cell, proof) = entry.as_ref().ok_or(PendingColumnError::IncompleteColumn)?;
            // TODO(gloas): we likely want to go and arc all cells
            column.push(cell.clone());
            kzg_proofs.push(*proof);
        }

        // TODO(gloas): this hard-codes the Gloas sidecar variant. Pass the fork in once
        // post-Gloas variants are introduced (or move construction to a fork-aware helper).
        Ok(Arc::new(DataColumnSidecar::Gloas(DataColumnSidecarGloas {
            index,
            column: VariableList::try_from(column)
                .map_err(|_| PendingColumnError::ColumnSizeExceedsBound)?,
            kzg_proofs: VariableList::try_from(kzg_proofs)
                .map_err(|_| PendingColumnError::ProofsSizeExceedsBound)?,
            slot,
            beacon_block_root,
        })))
    }
}

/// Errors returned by [`PendingColumn::to_sidecar`]. `IncompleteColumn` should never fire if the
/// caller checks [`PendingColumn::is_complete`] first; the size-bound variants reflect spec-bound
/// invariants and should never fire in practice.
#[derive(Debug, Clone)]
pub enum PendingColumnError {
    IncompleteColumn,
    ColumnSizeExceedsBound,
    ProofsSizeExceedsBound,
}
