# ERA File Test Report — PR #69

## Test Environment
- **Host:** clawdia server (Linux 6.1.0-42-amd64)
- **Date:** 2026-03-09
- **Branch:** era-lcli (dapplion/lighthouse)
- **Build:** release (`cargo build --release -p lcli`)
- **ERA source:** https://mainnet.era.nimbus.team/

## Test 1: ERA Import (consume-era-files)

### Setup
- Downloaded first 10 ERA files (eras 0-9, 178MB total) to `/mnt/ssd/era-mainnet-test/`
- Fresh empty DB at `/mnt/ssd/era-test-db/`

### Command
```bash
lcli consume-era-files --datadir /mnt/ssd/era-test-db --era-dir /mnt/ssd/era-mainnet-test --network mainnet
```

### Result: ✅ SUCCESS
- All 10 ERA files imported successfully
- Time: **15.1 seconds**
- Head slot: 73728 (era 9 boundary)
- Head block root: `0xc56c2a2c564921b81da4842bfd5787c5c4d19e115a1077c332a9bf4baf26dab5`
- State root: `0x445aa7e5a6ea97da15cb6e300bac93db4b02321ba9f2b7a77bd874254ec97ff9`
- Each ERA ~1-2 seconds to import (blocks + state + diffs)

### DB State After Import
```
anchor_slot: 73728
state_lower_limit: 73728
state_upper_limit: 18446744073709551615
oldest_block_slot: 18446744073709551615
split_slot: 73728
```

## Test 2: ERA Produce (round-trip)

### Command
```bash
lcli produce-era-files --datadir /mnt/ssd/era-test-db --output-dir /mnt/ssd/era-mainnet-roundtrip --network mainnet
```

### Result: ❌ FAILED — state reconstruction required
```
State reconstruction is not complete. state_lower_limit=73728, state_upper_limit=18446744073709551615.
Run with --reconstruct-historic-states first.
```

### Analysis
The consumer (`consume-era-files`) stores states only at ERA boundaries (every 8192 slots), 
plus intermediate diffs. It sets `state_lower_limit = head_slot` but `state_upper_limit` remains 
at u64::MAX (unset sentinel). 

The producer (`produce-era-files`) checks `all_historic_states_stored()` which requires 
`state_lower_limit == state_upper_limit`. This check passes when full state reconstruction 
has been performed (storing states at every slot), but NOT after ERA import which only stores
boundary states.

**However**, the ERA producer should be able to work with just boundary states — each ERA file 
contains one boundary state + blocks for 8192 slots. The state reconstruction check may be overly 
strict for the ERA produce use case.

**Possible fix:** Either:
1. The consumer should set `state_upper_limit = state_lower_limit` after import (since all boundary states are available), OR
2. The producer should use a less strict check (e.g., verify boundary states exist rather than full reconstruction), OR
3. Set `state_lower_limit = 0` since the consumer does store states at all boundaries

## Test 3: Lighthouse Boot (pending)
Building lighthouse binary for boot test...

## Test 4: --era-trusted-state (pending)
Awaiting boot test completion.
