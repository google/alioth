use super::*;

impl<L: PageLinks> Pool<'_, L> {
    fn scan(
        &self,
        map: &[AtomicU64],
        descending: bool,
        mut take: impl FnMut(usize) -> Result<Option<u64>, AllocationError>,
    ) -> Result<Option<u64>, AllocationError> {
        for offset in 0..map.len() {
            let word = if descending {
                map.len() - 1 - offset
            } else {
                offset
            };
            let mut bits = map[word].load(Ordering::Acquire);
            while bits != 0 {
                let bit = if descending {
                    63 - bits.leading_zeros()
                } else {
                    bits.trailing_zeros()
                };
                bits &= !(1 << bit);
                let index = word * 64 + bit as usize;
                if index < self.block_count {
                    if let Some(addr) = take(index)? {
                        return Ok(Some(addr));
                    }
                }
            }
        }
        Ok(None)
    }

    // None is the bootstrap path: it never consults CPU identity or claims.
    // P1b supplies a cursor only after the all-CPU publication is acquired.
    pub(super) fn allocate(
        &self,
        count: u16,
        cursor: Option<&AtomicUsize>,
        class: AllocationClass,
    ) -> Result<Option<u64>, AllocationError> {
        if count == 0 || count > PAGES {
            return Ok(None);
        }
        let previous = cursor.map_or(NO_CURSOR, |slot| slot.load(Ordering::Relaxed));
        if previous != NO_CURSOR {
            if let Some(addr) = self.take_small(previous, count, SmallSource::Split, true, class)? {
                return Ok(Some(addr));
            }
            let block = self.block(previous)?;
            let _guard = block.inner.lock(line!());
            block.flags.fetch_and(!CLAIMED, Ordering::Relaxed);
            cursor.unwrap().store(NO_CURSOR, Ordering::Relaxed);
        }
        loop {
            let take = |index, source| {
                let addr = self.take_small(index, count, source, cursor.is_some(), class)?;
                if addr.is_some() {
                    if let Some(slot) = cursor {
                        slot.store(index, Ordering::Relaxed);
                    }
                }
                Ok(addr)
            };
            if count == 1 && cursor.is_some() {
                if let Some(addr) = self.scan(self.free, false, |index| {
                    take(index, SmallSource::Unclaimed)
                })? {
                    return Ok(Some(addr));
                }
            }
            if let Some(addr) =
                self.scan(self.free, false, |index| take(index, SmallSource::Split))?
            {
                return Ok(Some(addr));
            }
            if let Some(addr) =
                self.scan(self.whole, false, |index| take(index, SmallSource::Whole))?
            {
                return Ok(Some(addr));
            }
            // Fragmented free pages cannot guarantee a run. For one page,
            // acquiring a free's released charge also observes its index bit.
            if count != 1 || self.state_snapshot().used() == self.counters.total {
                return Ok(None);
            }
        }
    }

    pub(super) fn allocate_huge(
        &self,
        class: AllocationClass,
    ) -> Result<Option<u64>, AllocationError> {
        self.scan(self.whole, true, |index| self.take_huge(index, class))
    }

    /// Allocates `num_blocks` physically adjacent 2 MiB `WHOLE` blocks as
    /// consecutive `SmallPage` frames (`num_blocks * 512` pages), rolling back
    /// cleanly if a concurrent allocation breaks a candidate run.
    pub(super) fn allocate_whole_run(
        &self,
        num_blocks: usize,
        class: AllocationClass,
    ) -> Result<Option<u64>, AllocationError> {
        if num_blocks == 0 || num_blocks > self.block_count {
            return Ok(None);
        }
        let is_whole = |idx: usize| -> bool {
            (self.whole[idx / 64].load(Ordering::Acquire) >> (idx % 64)) & 1 != 0
        };
        let rollback_blocks = |start: usize, count: usize| {
            for b in start..(start + count) {
                let base = (b as u64) << BLOCK_SHIFT;
                for p in 0..PAGES {
                    self.push(base + (u64::from(p) << PAGE_SHIFT))
                        .expect("phys: corrupt rollback of whole-block run");
                }
            }
        };

        let mut start = 0usize;
        while start + num_blocks <= self.block_count {
            let mut run = 0usize;
            while run < num_blocks && is_whole(start + run) {
                run += 1;
            }
            if run < num_blocks {
                start += run + 1;
                continue;
            }

            let mut taken = 0usize;
            let mut failed_err: Option<AllocationError> = None;
            while taken < num_blocks {
                match self.take_small(start + taken, PAGES, SmallSource::Whole, false, class) {
                    Ok(Some(_)) => taken += 1,
                    Ok(None) => break,
                    Err(e) => {
                        failed_err = Some(e);
                        break;
                    }
                }
            }
            if taken == num_blocks {
                return Ok(Some((start as u64) << BLOCK_SHIFT));
            }
            rollback_blocks(start, taken);
            if let Some(e) = failed_err {
                return Err(e);
            }
            start += taken + 1;
        }
        Ok(None)
    }
}
