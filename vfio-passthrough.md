# PCI Device Passthrough Design (`virtio-iommu`, `vmm-core`, & Dual-L0 Verification)

## 1. Overview, Goals, & Target Topologies

Today, when `wasm-vmm` runs on Motor OS in L1 (steps `(e)` and `(f)` in
[`airlock-motor-os.md`](airlock-motor-os.md)), L1's `sys-io` claims all host
VirtIO PCI devices (`virtio-blk` and `virtio-net`), and `motor-io-host` +
`vmm-io` exposes a *new* set of emulated VirtIO devices to L2 backed by an image
file on `motor-fs` and a userspace `IpDevice` tunnel.

Before porting `vmm-core-host` into Linux Ring 0 (step `(g)`), we want to add
**IOMMU-isolated PCIe device passthrough** (`virtio-iommu`, OASIS VirtIO v1.2
Device ID `23`) so an L1 Motor OS hypervisor safely assigns L0 PCI functions
directly to its L2 guest while protecting L1 Ring 0 against a malicious L2:

1. **Topology A — `virtio-net` Passthrough (Full Motor OS in L1)**:
   - L0 (`wasm-vmm` or `cloud-hypervisor-static`) boots L1 Motor OS with
     `00:01.0` (`virtio-iommu`), `00:02.0` (`virtio-blk`, `motor-os.qcow2`), and
     `00:03.0` (`virtio-net`, host `ipvtap` / `puff-tap` / `moto-tap`).
   - L1 hides `00:01.0` (`virtio-iommu`) and `00:03.0` (`virtio-net`) from stock
     `sys-io` via kernel cmdline (`pci_passthrough=00:03.0`). L1 mounts its root
     disk on `00:02.0` as usual and runs with **zero network devices**.
   - Inside L1, `motor-io-host` boots L2 (Alpine Linux or Motor OS) with an
     emulated `virtio-blk` image on `motor-fs` plus **`00:03.0` passed through**
     inside a dedicated `virtio-iommu` domain mapped strictly to L2's Guest RAM.
   - L2 talks directly to L0's `ipvtap`/`tap` (reachable directly from L0 via
     `ssh root@192.168.4.2` with **no** `ProxyCommand` jump).

2. **Topology B — `virtio-blk` (+ Optional `virtio-net`) Passthrough (`initrd-only` Motor OS in L1)**:
   - L0 (`wasm-vmm` or `cloud-hypervisor-static`) boots L1 Motor OS **diskless
     (`initrd-only`)** — no `motor-os.qcow2` and no `sys-io` — exposing
     `00:01.0` (`virtio-iommu`), `00:02.0` (`virtio-blk` backed by L2's disk
     image), and optionally `00:03.0` (`virtio-net` backed by L0's `ipvtap`/`tap`).
   - L1's `initrd` bundles the Ring-3 VMM launcher, `vmm-core-motor.cwasm`, and
     L2's boot kernel (`bzImage` for Linux, or `kloader` + `initrd` for Motor OS).
   - L1 isolates `00:02.0` (and `00:03.0`) in L2's `virtio-iommu` domain and
     passes them directly to L2.

3. **Topology C — Dual-L0 Verification (`wasm-vmm` & `cloud-hypervisor-static`) + Future Linux Ring 0 (`Step g`)**:
   - Every nested boot test in `tests/tests/boot_vms.rs` runs against **both**
     our Linux Ring-3 `wasm-vmm` (with `virtio-iommu`) **and** upstream
     `cloud-hypervisor-static` (`v54.1`, with `virtio-iommu`) in L0.
   - Every nested launcher script in `vm_scripts/` accepts `--vmm chv` (default
     `--vmm wasm`) to switch L0 to `cloud-hypervisor-static` with `virtio-iommu`.
   - Because PCI passthrough device modeling lives inside `vmm-core` behind
     narrow `VmmHostCore` primitives, the **exact same `vmm-core.wasm`** maps
     cleanly onto Linux `/dev/vfio/vfio` and future Linux Ring-0 `iommu_domain`
     in step `(g)`.

### Preserved Project Invariants
- **Single Pair of Byte-Identical Wasm Binaries**: Only `vmm-core.wasm` and
  `vmm-io.wasm` exist across all platforms (`0` host-specific `.wasm` variants
  or `#[cfg]` forks).
- **Read-Only `../motor-dev/motor-os`**: Stock `sys-io` and `motor-os` userland
  are consumed strictly unmodified; all kernel/loader/initrd/host changes live
  inside `alioth-vmm`.
- **Zero FP/SIMD in Ring 0**: Both `tests/kernel` and `vmm-core-motor.cwasm`
  remain 100% integer-only (`validate_cwasm_no_fp`).
- **Fail-Closed IOMMU Enforcement**: L1 Ring 0 refuses `pci_attach`
  (`Err(HvError::Unsupported)`) if no IOMMU is active, preventing unisolated DMA
  from a malicious L2 guest.

---

## 2. Split-Plane Architecture & Steady-State Data Path

### 2.1 Why Passthrough Lives in `vmm-core` + `VmmHostCore` (Not `vmm-io`)

`vmm-core` already owns `PciBus`, PCIe ECAM (`0xe000_0000`), legacy PCI PIO
(`0xcf8`–`0xcff`), guest BAR address allocation (`Memory`), and Stage-2 GPA
mappings (`VmmHostCore::gpa_map`). Placing `PassthroughPciDev` in `vmm-core`
means **100% of steady-state I/O bypasses both Wasm and L1 Ring 3**:

```text
  Control Plane (Boot / PCI Probe / GPA Map / MSI-X Setup — Cold Path):
    L2 Guest Driver --(ECAM / MSI-X Table MMIO)--> L1 SVM #NPF
      --> vmm-core.cwasm (PassthroughPciDev)
      --> MotorHvCore:
            - pci_attach / gpa_map --> Ring-0 VirtioIommuDriver (ATTACH / MAP)
            - pci_configure_msix   --> Ring-0 IDT Vector (64..191)

  Data Plane (Steady-State Queue Notify, IOMMU-Checked DMA, & Interrupts — Hot Path):
    1. Doorbell / Register MMIO:
       L2 Guest --(BAR MMIO write)--> L2 Stage-2 NPT (UC direct map)
         --> L1 HPA == L0 BAR GPA --> L0 KVM_IOEVENTFD / Physical Device
         (0 L1 VM-exits, 0 Wasm calls, 0 L1 Ring-3 hops)

    2. IOMMU-Isolated Device DMA:
       L0 Device --(IOVA = L2 GPA)--> L0 virtio-iommu (domain check + IOVA -> L1 PA)
         <======== Direct DMA ========> L2 Guest RAM (any L1 SysMem::alloc pages)
         (Malicious L2 DMA outside mapped Guest RAM is rejected at L0 IOMMU!)

    3. MSI-X Interrupts:
       L0 Device --(Host MSI)--> L1 Ring-0 IDT Vector (64..191)
         --> MotorHvCore::inject_msi(guest_addr, guest_data) --> L2 vLAPIC
         (0 Ring-3 context switches, 0 Wasm calls)
```

### 2.2 Configuration Flow (`vm.toml` -> `BridgeShm` -> `vmm-core`)

1. **`vm.toml` Syntax (`vmm-io/src/config.rs`)**:
   - `iommu = true` (optional boolean, default `false`): when set on an L0 VM,
     `vmm-io` + `vmm-core` expose a `virtio-iommu` PCI device at `00:01.0` and
     place all emulated PCI endpoints behind IOMMU DMA translation.
   - `pci = ["00:03.0"]` (or `["00:02.0", "00:03.0"]`): list of host PCI BDFs to
     pass through into the guest VM.
2. **`BridgeShm` Boot Metadata (`vmm-core/src/host.rs`)**:
   Extend `ShmBootInfo` / `BridgeShm` (and `VmmCoreBridge::boot_info`) with a
   fixed-size array of passthrough descriptors:
   ```rust
   pub const MAX_PASSTHROUGH_DEVS: usize = 8;

   #[repr(C)]
   #[derive(Debug, Default, Copy, Clone, FromZeroes, FromBytes, AsBytes)]
   pub struct ShmPciPassthroughSpec {
       /// Host PCI BDF (`(bus << 8) | (dev << 3) | func`), e.g. `0x0018` for `00:03.0`.
       pub host_bdf: u16,
       /// Optional guest device slot override (`0` = auto-assign next free `00:NN.0`).
       pub guest_dev: u8,
       pub flags: u8,
   }
   ```
3. **Consistent BDF Slot Layout Across `wasm-vmm` and `cloud-hypervisor-static`**:
   When `iommu` is enabled in L0:
   - `00:01.0`: `virtio-iommu` (`0x1af4:0x1057`)
   - `00:02.0`: primary `virtio-blk` (`pci_device_id=2` in `cloud-hypervisor-static`)
   - `00:03.0`: primary `virtio-net` (`pci_device_id=3` in `cloud-hypervisor-static`)
   - `00:04.0`: `virtio-rng` (`pci_device_id=4` in `cloud-hypervisor-static`, if enabled)
   This keeps L1's `pci_passthrough=...` cmdline and L2's `vm.toml` `pci = [...]`
   **100% identical** whether L0 is `wasm-vmm` or `cloud-hypervisor-static`.

---

## 3. Narrow `VmmHostCore` Extensions

To keep `vmm-core.wasm` OS-agnostic across Motor OS Ring 0, Linux VFIO, and
Linux Ring 0, we add eight scalar, non-blocking methods to `VmmHostCore` in
`vmm-core/src/host.rs` (defaulting to `Err(HvError::Unsupported)` on hosts
without passthrough support, and mirrored 1:1 as `"vmm"::hv_pci_*` Wasm imports):

```rust
pub type PciDevId = u32;

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PciBarKind {
    Empty = 0,
    Mem32 = 1,
    Mem64 = 2,
    Io    = 3,
}

#[derive(Debug, Copy, Clone)]
pub struct PciBarInfo {
    pub kind: PciBarKind,
    pub prefetchable: bool,
    pub size: u64,
    /// For `Mem32` / `Mem64` BARs: host-managed `MemObjId` covering `[0 .. size)`
    /// of the physical BAR so `vmm-core` can map page-aligned slices via `gpa_map`.
    pub mem_obj: Option<MemObjId>,
}

pub trait VmmHostCore: Send + Sync + 'static {
    // ... existing methods ...

    /// Claim host PCI function `host_bdf`, bind it to this VM's IOMMU domain,
    /// and reset the function. Fails with `HvError::Unsupported` if no IOMMU is active.
    fn pci_attach(&self, host_bdf: u16) -> HvResult<PciDevId> { ... }
    fn pci_detach(&self, dev: PciDevId) -> HvResult<()> { ... }
    fn pci_reset(&self, dev: PciDevId) -> HvResult<()> { ... }

    /// Raw host config-space access (1, 2, or 4 bytes).
    fn pci_read_config(&self, dev: PciDevId, offset: u16, size: u8) -> HvResult<u32> { ... }
    fn pci_write_config(&self, dev: PciDevId, offset: u16, size: u8, val: u32) -> HvResult<()> { ... }

    /// Query physical BAR sizing and (for MMIO BARs) its backing `MemObjId`.
    fn pci_bar_info(&self, dev: PciDevId, bar_idx: u8) -> HvResult<PciBarInfo> { ... }

    /// Fallback trapped access for PIO BARs or non-MSI-X bytes sharing a 4 KiB page
    /// with an MSI-X table/PBA (`write = None` -> read, `Some(val)` -> write).
    fn pci_bar_io(
        &self,
        dev: PciDevId,
        bar_idx: u8,
        offset: u64,
        size: u8,
        write: Option<u64>,
    ) -> HvResult<u64> { ... }

    /// Route physical MSI-X table entry `entry_idx` to `guest_msi = Some((addr, data))`
    /// when unmasked & enabled, or mask it in hardware when `guest_msi = None`.
    fn pci_configure_msix(
        &self,
        dev: PciDevId,
        entry_idx: u16,
        guest_msi: Option<(u64, u32)>,
    ) -> HvResult<()> { ... }
}
```

Notice how `pci_bar_info` and IOMMU DMA mappings both reuse `MemObjId` +
`gpa_map`:
- When `gpa_map` is called with a **Guest RAM `MemObjId`**, the host updates both
  Stage-2 NPT (`L2 GPA -> L1 PA`) **and** the VM's IOMMU domain (`IOVA = L2 GPA -> L1 PA`).
- When `gpa_map` is called with a **PCI BAR `MemObjId`**, the host maps those
  physical MMIO BAR pages into Stage-2 NPT with uncacheable (`UC`) attributes
  (no IOMMU RAM mapping needed unless peer-to-peer BAR DMA is explicitly enabled).

---

## 4. Virtualizing Config Space, BARs, & MSI-X in `vmm-core`

A new module `vmm-core/src/hw/pci/passthrough.rs` implements `Pci` for
`PassthroughPciDev`:

### 4.1 Config Header & Capability Filtering
1. **Standard Type-0 Header (`0x00..0x40`)**:
   - Read once from `hv.pci_read_config` at attach: `vendor`, `device`,
     `revision`, `prog_if`, `subclass`, `class`, `subsystem_vendor`,
     `subsystem`. Force `header_type = 0` (`HeaderType::Device`) and
     `intx_pin = 0` (MSI-X only; legacy INTx disabled via
     `Command::INTX_DISABLE` on the physical function).
   - **Virtualized `BAR0..BAR5` & `Command`**: Handled by `EmulatedConfig`
     (`UpdateCommandCallback` and `MoveBarCallback` in
     `vmm-core/src/hw/pci/config.rs`). When L2 sizes or relocates a BAR in guest
     GPA space, `vmm-core` moves the Stage-2 NPT mapping **without modifying the
     physical device's host BAR registers**.
   - **`Command::BUS_MASTER`**: Tracked in `PassthroughPciDev`; writes that
     toggle `Command::BUS_MASTER` forward the updated bus-master bit (with host
     `MEM`/`IO` kept enabled while attached) to the physical function via
     `hv.pci_write_config(dev, 0x04, 2, ...)`.
2. **Capability List (`0x34` Pointer)**:
   `vmm-core` walks the physical capability linked list (`0x40..0x100`) and
   constructs a sanitized `PciCapList`:
   - **`PciCapId::Vendor` (`0x09`) — Pass-Through Read-Only**: Copies raw
     `VirtioPciCap` structures (`CommonCfg`, `Isr`, `Notify`, `DeviceCfg`)
     verbatim at their exact physical BAR indices and byte offsets, **excluding**
     `VIRTIO_PCI_CAP_PCI_CFG` (`cfg_type == 5`) so a malicious L2 cannot use the
     PCI config-space backdoor window to access trapped MSI-X table bytes!
   - **`PciCapId::Msix` (`0x11`) — Virtualized via `MsixCapMmio`**: Reuses
     `MsixCapMmio` (`vmm-core/src/hw/pci/cap.rs`) initialized with the physical
     device's `table_len`, `table_offset`, and `pba_offset`. Toggling
     `MsixMsgCtrl::enabled` or `masked` re-syncs all vectors via
     `hv.pci_configure_msix(...)`.
   - **PCI Express (`0x10`) — Sanitized Endpoint Cap**: Exposes read-only
     dev/link caps; writes to `DevCtl.BCR_FLR` (`bit 15`) invoke
     `hv.pci_reset(dev)`.

### 4.2 BAR Mapping & Sub-Page MSI-X Table Carving

We add `MemRange::DevMem(ArcMemPages)` to `vmm-core/src/mem/mem.rs`, mapping
physical BAR pages via `hv.gpa_map(..., MemProt::READ | MemProt::WRITE)` during
`Memory::add_region` while keeping MMIO BARs strictly out of `RamBus` guest-RAM
lookups.

For each MMIO BAR (`bar_idx`), `vmm-core` partitions `[0 .. bar.size)` on 4 KiB
page boundaries:
- **4 KiB pages disjoint from MSI-X Table & PBA**: Added as
  `MemRange::DevMem(bar_mem.subslice(run_start, run_len))` -> mapped directly in
  Stage-2 NPT (**`0` L1 VM-exits on register accesses and `QueueNotify`
  doorbells!**).
  - Both `wasm-vmm` (`BAR0 [0x3000..0x4000)`) and `cloud-hypervisor-static`
    (which places MSI-X Table + PBA in a dedicated BAR separate from the VirtIO
    modern capability BAR!) keep VirtIO `CommonCfg`/`Isr`/`Notify`/`DeviceCfg`
    100% 4 KiB page-disjoint from MSI-X, guaranteeing zero-exit doorbells on
    both L0 VMMs.
- **4 KiB pages overlapping MSI-X Table or PBA**: Added as
  `MemRange::Emulated(...)`, dispatching `[table_off .. table_end)` to
  `MsixTableMmio`, `[pba_off .. pba_end)` to emulated PBA (`0`), and any other
  bytes on that shared 4 KiB page to `hv.pci_bar_io(...)`.

---

## 5. DMA Isolation & Translation via `virtio-iommu` (VirtIO v1.2, ID `23`)

### 5.1 Security Model Against a Malicious L2 Guest

Without an IOMMU, a malicious L2 guest controls the passed-through device's DMA
ring/buffer addresses (`CommonCfg.queue_desc`, `Desc.addr`) and could point DMA
transfers at L1's Ring-0 kernel memory, `vmm-core`, `sys-io`, or other VMs.

With `virtio-iommu` between L0's PCI endpoints and L1's physical memory:
1. **Default-Deny (`bypass = 0`)**: Global IOMMU bypass is disabled as soon as
   L1's Ring-0 `VirtioIommuDriver` initializes (prior to spawning PID 2).
2. **Strict Per-Domain Endpoint Isolation**:
   - **Passthrough BDFs (`pci_passthrough=...`)** are immediately attached at L1
     boot to an **empty blocking domain** (`0` mapped IOVAs). When `VmInstance`
     attaches a BDF (`pci_attach`), it moves to a dedicated `vm_domain` whose
     *only* `MAP` entries come from `VmInstance`'s Guest RAM `gpa_map` calls
     (`IOVA = L2 GPA -> L1 PA`, with `READ` / `WRITE` permission flags matching
     `MemProt`). Any L2 DMA to an unmapped `L2 GPA` or write to a read-only GPA
     is **rejected at L0 before touching L1 RAM**.
   - **L1-Owned BDFs** (devices *not* in `pci_passthrough`, driven by trusted
     L1 `sys-io` such as `00:02.0` `virtio-blk` in Topology A, or all Bus-0
     devices in non-passthrough nested tests) are attached by L1 Ring 0 at boot
     to `L1_SYSTEM_DOMAIN`, which maps L1's PVH `mem_map` RAM segments `1:1`.
     This allows **unmodified stock `sys-io`** to run seamlessly even when L0
     places the entire PCI segment behind `virtio-iommu`
     (`--platform iommu_segments=0` in `cloud-hypervisor-static` or
     `iommu = true` in `wasm-vmm`).
3. **Zero L1 Memory Layout Hacks**:
   Because `virtio-iommu` translates arbitrary 4 KiB / 2 MiB `L2 GPA -> L1 PA`
   mappings, L1 keeps `KERNEL_PHYS_START = 16 MiB`, uses standard `SysMem::alloc`
   Guest RAM allocations, and supports multiple concurrent passthrough L2 VMs.

### 5.2 L0 `virtio-iommu` Implementation in `wasm-vmm` (`vmm-core` + `vmm-io`)

1. **`vmm-core` (`VirtioDeviceSpec` at `00:01.0`)**:
   - `virtio-iommu` uses the existing `VirtioPciDevice` transport in
     `vmm-core/src/virtio/pci.rs` (`device_id = 23` -> PCI `0x1af4:0x1057`, 2
     virtqueues: `requestq = 0`, `eventq = 1`, and 64-byte `virtio_iommu_config`
     advertising `page_size_mask = !0xfff`, `input_range = 0..=u64::MAX`,
     `domain_range = 1..=u32::MAX`, `bypass`).
   - Also emit a minimal ACPI `VIOT` table in `vmm-core/src/hw/firmware/acpi/`
     describing PCI segment `0` (`bdf_range = 0x0000..=0xffff`) managed by
     `00:01.0` (matching Cloud Hypervisor so standard Linux guests with
     `CONFIG_VIRTIO_IOMMU` also recognize `wasm-vmm`'s IOMMU).
2. **`vmm-io` (`vmm-io/src/virtio/dev/iommu.rs` + `EndpointDmaView`)**:
   - Implements OASIS VirtIO v1.2 §5.12 features:
     `VIRTIO_IOMMU_F_INPUT_RANGE (0)`, `VIRTIO_IOMMU_F_DOMAIN_RANGE (1)`,
     `VIRTIO_IOMMU_F_MAP_UNMAP (2)`, `VIRTIO_IOMMU_F_BYPASS_CONFIG (6)`.
   - Handles `VIRTIO_IOMMU_T_ATTACH (1)`, `DETACH (2)`, `MAP (3)`, and
     `UNMAP (4)` on `requestq`, maintaining `RwLock<IommuState>` (`endpoint_bdf -> domain_id`,
     and per-domain `BTreeMap<u64, IommuMapping>` with contiguous-range checks).
   - Every VirtIO device in `vmm-io` (`VirtioBlk`, `VirtioNet`, etc.) already
     performs 100% of its ring & buffer DMA through `Arc<dyn GuestMemAccess>`
     (`vmm-io/src/host.rs`). When `iommu = true`, each endpoint receives an
     `Arc<EndpointDmaView>` tagged with its PCI `endpoint_bdf` ( while
     `virtio-iommu` itself keeps raw `GuestMemAccess` so its own `requestq` is
     never recursively translated).
   - **Hardening `SplitQueue` Against Malicious L2 Ring Pointers**:
     Replace `.expect(...)` calls on `self.memory.read` / `write` in
     `vmm-io/src/virtio/queue/split.rs` with `io::Result` propagation so an
     unmapped/malicious `avail_gpa`, `used_gpa`, or `Desc.addr` cleanly aborts
     queue processing (and posts a `VIRTIO_IOMMU_FAULT_R_MAPPING` event on
     `eventq`) instead of panicking L0 `vmm-io`.

### 5.3 L1 Ring-0 `IommuProvider` & `VirtioIommuDriver` (`tests/kernel/src/vmm/`)

1. **`IommuProvider` Trait (`tests/kernel/src/vmm/iommu.rs`)**:
   ```rust
   pub trait IommuProvider: Send + Sync {
       fn alloc_domain(&self) -> HvResult<u32>;
       fn free_domain(&self, domain: u32);
       fn attach_endpoint(&self, domain: u32, bdf: u16) -> HvResult<()>;
       fn detach_to_blocked(&self, bdf: u16) -> HvResult<()>;
       fn map_dma(&self, domain: u32, iova: u64, hpa: u64, size: u64, prot: MemProt) -> HvResult<()>;
       fn unmap_dma(&self, domain: u32, iova: u64, size: u64) -> HvResult<()>;
   }
   ```
   This internal kernel interface cleanly decouples `MotorHvCore` from the
   specific IOMMU hardware (`VirtioIommuDriver` in nested VMs today; hardware
   AMD-Vi / Intel VT-d on bare metal later).
2. **`VirtioIommuDriver` (`tests/kernel/src/vmm/virtio_iommu.rs`)**:
   - Runs entirely in Ring 0 (`~220` lines, synchronous polled `requestq`
     protected by a `SpinLock`, using 2 pre-allocated 4 KiB frameless DMA pages
     for the `requestq` split ring + request/response scratch buffer; `ATTACH`,
     `DETACH`, `MAP`, `UNMAP` only run on cold control-plane paths: boot, VM
     create, BAR/RAM setup, and VM teardown).
   - Probes PCI Bus `0` during kernel init (before PID 2 starts) for vendor
     `0x1af4`, device `0x1057` (`virtio-iommu`):
     - Reads `domain_range` from device config, sets `bypass = 0` if
       `F_BYPASS_CONFIG` is negotiated, allocates `BLOCKING_DOMAIN` and
       `L1_SYSTEM_DOMAIN`:
       - Attaches every BDF in `pci_passthrough` to `BLOCKING_DOMAIN`.
       - Maps L1's PVH `mem_map` RAM segments into `L1_SYSTEM_DOMAIN` and
         attaches all remaining Bus-0 PCI endpoints (except `00:00.0` host
         bridge and the `virtio-iommu` BDF itself) to `L1_SYSTEM_DOMAIN`.
   - Tested identically against **both** `wasm-vmm` (`iommu = true`) and
     `cloud-hypervisor-static` (`--platform iommu_segments=0`, `iommu=virtio`).

---

## 6. Motor OS L1 Integration Details (`tests/`)

### 6.1 Hiding `virtio-iommu` & Passthrough BDFs from Stock `sys-io` (Topology A)

In `../motor-dev/motor-os/src/sys/lib/virtio-async/src/pci.rs`, `sys-io` scans
PCI Bus `0` via `out 0xcf8, eax` / `in eax, 0xcfc` (enabled by `RFLAGS.IOPL = 3`
in `tests/kernel/src/arch/x64/syscall.rs` line 244; all post-probe VirtIO BAR
accesses in `sys-io` use MMIO via `SysMem::mmio_map`).

To hide Ring-0-owned BDFs (`virtio-iommu` + `pci_passthrough=00:03.0,...`) from
unmodified `sys-io`:
1. Parse `pci_passthrough=00:03.0[,00:02.0]` in `tests/kernel/src/config.rs`.
2. Whenever `VirtioIommuDriver` or `pci_passthrough` claims any BDF, withhold
   `IOPL = 3` (`IOPL = 0`) on `CAP_IO_MANAGER` threads and emulate `in`/`out` on
   ports `0xcf8..=0xcff` inside `general_protection_fault`
   (`tests/kernel/src/arch/x64/irq.rs`):
   - `out 0xcf8, eax` updates a per-process virtual `pci_cfg_addr` latch.
   - `in`/`out 0xcfc..=0xcff` checks `bdf = (pci_cfg_addr >> 8) & 0xffff`:
     - If `bdf` is owned by Ring 0 (`virtio-iommu` or `passthrough_bdfs`), reads
       return `0xffff_ffff` and writes are ignored.
     - Otherwise, Ring 0 executes the real `0xcf8`/`0xcfc` access under a global
       `PCI_CFG_LOCK` spinlock and advances `RIP`.
3. Stock `sys-io` mounts `00:02.0` (`virtio-blk`), skips `00:01.0` and `00:03.0`
   cleanly, and boots `rush` with zero NICs while `00:03.0` remains untouched
   for `MotorHvCore::pci_attach`.

### 6.2 Ring-0 Physical PCI Backend & Zero-Hop MSI-X Routing (`tests/kernel/src/vmm/pci_host.rs`)

1. **Attach & BAR Discovery (`pci_attach`, `pci_bar_info`)**:
   - Verifies an `IommuProvider` is present (failing closed with
     `HvError::Unsupported` otherwise) and that `host_bdf` is in
     `passthrough_bdfs` (or `initrd-only` mode with no `sys-io`) and unclaimed.
   - Attaches `host_bdf` to `VmInstance`'s `vm_domain` via `iommu.attach_endpoint`
     (replaying any already-mapped Guest RAM slots into `vm_domain`).
   - Resets the function (§6.3), sizes `BAR0..BAR5` under `PCI_CFG_LOCK` at
     their L0-assigned host physical addresses, wraps MMIO BARs as
     `MemBacking::PciBarMmio { phys_base, size }` (`UC` NPT attributes), and
     maps the physical MSI-X table into kernel virtual space (`mm::mmio::map`).
2. **Ring-0 MSI-X -> Guest vLAPIC Fast Path (`tests/kernel/src/arch/x64/irq.rs`)**:
   - Coordinates custom IDT vector allocation (`64..191`) via a shared bitmap
     between `wait_handles` (`sys-io`) and `vmm::pci_host`.
   - Programs physical `MsixTableEntry[entry_idx]` to target L1 BSP
     (`0xfee0_0000 | (bsp_apic_id << 12)`, `data = host_vec`) and registers
     `(Weak<VmInstance>, guest_addr, guest_data)` in `VMM_IRQ_ROUTES[host_vec - 64]`.
   - `irq_handler_inner` dispatches active `VMM_IRQ_ROUTES` entries directly to
     `hv.inject_msi_from_isr(guest_addr, guest_data)` + local APIC `EOI` in Ring
     0 (**0 Ring-3 context switches, 0 Wasm calls**).

### 6.3 Function Reset & Teardown Safety

On `pci_attach`, `pci_reset`, and `VmInstance::drop` (including if the Ring-3
VMM process exits or is killed):
1. Clear physical `PCI_COMMAND.BUS_MASTER` (`bit 2`) first to stop in-flight DMA.
2. Mask physical `MsixMsgCtrl` + all MSI-X entries and release L1 IDT vectors.
3. Move `host_bdf` back to `BLOCKING_DOMAIN` (`detach_to_blocked`) and free
   `vm_domain` **before** Guest RAM frames are unpinned/freed.
4. Reset device state via PCIe `FLR` (if advertised) and, for VirtIO PCI
   (`0x1af4`), write `CommonCfg.device_status = 0` and poll until `0` so L0
   (`wasm-vmm` or `cloud-hypervisor-static`) cleanly resets all virtqueues.

### 6.4 `initrd-only` L1 Packaging for `virtio-blk` Passthrough (Topology B)

When `00:02.0` (`virtio-blk`) is passed through to L2, L1 boots diskless without
`sys-io` (since `sys-io` requires a root filesystem to spawn `sys-init`). When
all PCI devices are passed through to L2 (`num_virtio_devs == 0`), both `COM1`
(`16450` UART) and `PassthroughPciDev` live 100% inside `vmm-core.wasm`, so L1
needs **zero Ring-3 Wasmtime or `vmm-io.wasm`**:

- **Lean PID-2 `vmm-init` + `vmm-core-motor.cwasm` (`InitrdBundle`)**:
  - Extending `tests/test-init` (or a small `tests/motor-vmm-init` PID-2 binary)
    reads an appended `InitrdBundle` trailer containing `vm.toml` (using the
    same `pci = ["00:02.0", "00:03.0"]` format), `vmm-core-motor.cwasm`, L2's
    `bzImage` or `kloader`, and optional L2 `initramfs`.
  - PID 2 allocates Guest RAM + `BridgeShm`, populates `ShmBootInfo` +
    `pci_devs`, starts Ring-0 `vmm-core-motor.cwasm` via `"vmm:create"`, and
    bridges bidirectional interactive `COM1` (`serial_console` `SysObj` / port
    `0x3f8` <-> `CORE_MSG_SERIAL_TX` / `IO_MSG_SERIAL_RX` with `Ctrl-b x`
    escape).
  - Because `InitrdBundle` is appended after compilation, shell scripts
    (`vm_scripts/run-passthrough-blk-*.sh`) repackage L2 kernels, cmdlines, and
    BDF lists in milliseconds without recompiling Rust.

---

## 7. Dual-L0 Verification: `wasm-vmm` vs. `cloud-hypervisor-static` (`virtio-iommu`)

Running every nested test and script against **both** our Linux Ring-3
`wasm-vmm` and `cloud-hypervisor-static` (`v54.1`) in L0 validates our Ring-0
`VirtioIommuDriver` and `PassthroughPciDev` against an independent production
`virtio-iommu` + nested-KVM implementation.

### 7.1 `cloud-hypervisor-static` L0 Invocation Profile

When L0 is `cloud-hypervisor-static`:
```bash
cloud-hypervisor-static \
  --cpus "boot=${L1_SMP},nested=on" \
  --memory "size=${L1_MEM},thp=on" \
  --platform "iommu_segments=0" \
  --console off --serial tty \
  --kernel "$KLOADER" \
  --initramfs "$INITRD" \
  --cmdline "$L1_CMDLINE" \
  --rng "src=/dev/urandom,iommu=virtio,pci_device_id=4" \
  [ --disk "path=$DISK_IMG,image_type=$FMT,iommu=virtio,pci_device_id=2" ] \
  [ --net  "tap=$TAP_IF,mac=a4:a1:c2:00:00:01,iommu=virtio,pci_device_id=3" ]
```
- `--cpus "boot=...,nested=on"` enables nested SVM/VMX for L1 Motor OS Ring 0.
- `--platform "iommu_segments=0"` + `iommu=virtio` places all PCI segment `0`
  endpoints behind Cloud Hypervisor's `virtio-iommu` (`00:01.0`) + ACPI `VIOT`.
- Explicit `pci_device_id={2,3,4}` matches `wasm-vmm`'s BDF layout (`00:02.0`
  disk, `00:03.0` net, `00:04.0` rng).

### 7.2 Complete Nested Test Matrix in `tests/tests/boot_vms.rs`

Every nested boot test runs in **both** L0 hypervisors (`L0Backend::WasmVmm`
with `iommu = true` and `L0Backend::CloudHypervisor` with `iommu_segments=0` +
`iommu=virtio`):

| Nested Scenario | L0 = Linux `wasm-vmm` (`iommu = true`) | L0 = `cloud-hypervisor-static` (`virtio-iommu`) |
| :--- | :--- | :--- |
| **1. Nested `test-guest` (`L0 -> L1 -> L2`)** | `boot_nested_test_guest_{cwasm,wasm}` | `boot_nested_test_guest_chv` |
| **2. Nested Full Motor OS (`IpDevice`)** | `boot_nested_motor_os_{cwasm,wasm}` | `boot_nested_motor_os_chv_{cwasm,wasm}` |
| **3. Nested Linux `initramfs`** | `boot_nested_linux_initrd_{cwasm,wasm}` | `boot_nested_linux_initrd_chv_{cwasm,wasm}` |
| **4. Nested Full Alpine Linux (`IpDevice`)** | `boot_nested_alpine_{cwasm,wasm}` | `boot_nested_alpine_chv_{cwasm,wasm}` |
| **5. Passthrough `virtio-net` -> L2 Alpine (Topology A)** | `boot_passthrough_net_alpine_{cwasm,wasm}` | `boot_passthrough_net_alpine_chv_{cwasm,wasm}` |
| **6. Passthrough `virtio-blk` (+ `net`) -> L2 Alpine (Topology B)** | `boot_passthrough_blk_alpine_{cwasm,wasm}` | `boot_passthrough_blk_alpine_chv_{cwasm,wasm}` |

*(In `tests/src/lib.rs`, a shared `spawn_l0_chv(...)` helper locates
`cloud-hypervisor-static` via `CHV_BIN` or `PATH` and drives PTY serial + SSH
verification identically to `spawn_l0_wasm_vmm(...)`.)*

### 7.3 `--vmm chv` Support Across All Nested Scripts in `vm_scripts/`

Every nested launcher script accepts `--vmm wasm` (default: our Linux L3
`wasm-vmm` with `iommu = true`) or `--vmm chv` (`cloud-hypervisor-static` with
`nested=on`, `iommu_segments=0`, and `iommu=virtio`):

1. `vm_scripts/run-nested-test-guest.sh [--vmm wasm|chv] ...`
2. `vm_scripts/run-nested-motor-os.sh [--vmm wasm|chv] ...`
3. `vm_scripts/run-nested-linux.sh [--vmm wasm|chv] ...`
4. `vm_scripts/run-passthrough-net-linux.sh [--vmm wasm|chv] ...` *(Topology A: L1 Motor OS has no NIC; L2 Alpine gets L0's `moto-tap` / `puff-tap` directly)*
5. `vm_scripts/run-passthrough-blk-linux.sh [--vmm wasm|chv] ...` *(Topology B: `initrd-only` L1 Motor OS passes L0's `alpine.raw` `virtio-blk` + `puff-tap` `virtio-net` directly to L2 Alpine)*

---

## 8. Cross-Platform Mapping to Linux VFIO & Linux Ring 0 (`Step g`)

Because `PassthroughPciDev` in `vmm-core` talks strictly to `VmmHostCore`, every
host primitive maps 1-to-1 onto Linux userspace VFIO and future Linux Ring 0:

| `VmmHostCore` Primitive | Motor OS Ring 0 (`MotorHvCore`) | Linux Userspace (`KvmCoreHost` + VFIO) | Future Linux Ring 0 (`Step g` Module) |
| :--- | :--- | :--- | :--- |
| `pci_attach(bdf)` | `VirtioIommuDriver::attach_endpoint` + reset | Open `/dev/vfio/<group>`, `VFIO_GROUP_GET_DEVICE_FD` | `vfio_device` / `pci_dev` claim + `iommu_attach_device` |
| `pci_read/write_config` | `0xcf8`/`0xcfc` under `PCI_CFG_LOCK` | `pread`/`pwrite` on `VFIO_PCI_CONFIG_REGION_INDEX` | `pci_user_read/write_config_*` |
| `pci_bar_info` + `gpa_map` (BAR) | `MemBacking::PciBarMmio` -> UC NPT PTEs | `mmap` VFIO BAR region -> `KVM_SET_USER_MEMORY_REGION` | `io_remap_pfn_range` / `tdp_mmu` MMIO SPTEs |
| `gpa_map` (Guest RAM DMA) | `VirtioIommuDriver::map_dma(vm_dom, gpa, hpa)` | `ioctl(VFIO_IOMMU_MAP_DMA)` | `iommu_map()` on `iommu_domain` |
| `pci_configure_msix` | Host IDT `64..191` -> ISR `inject_msi` | `eventfd` + `VFIO_DEVICE_SET_IRQS` + `KVM_IRQFD` | `request_irq` / `irq_bypass_producer` -> APICv / `irqfd` |

---

## 9. Proposed Phased Implementation Plan

1. **Sub-step `(p.1)` — L0 `virtio-iommu` in `wasm-vmm` + L1 Ring-0 `VirtioIommuDriver` + `--vmm chv` on Existing Nested Tests**:
   - Implement `virtio-iommu` (`device_id = 23` + ACPI `VIOT` + `EndpointDmaView`
     + hardened `SplitQueue`) in `vmm-core` and `vmm-io` (`iommu = true`).
   - Implement `IommuProvider` + `VirtioIommuDriver` (`L1_SYSTEM_DOMAIN` +
     `BLOCKING_DOMAIN` + `#GP` `0xcf8` hiding of `00:01.0`) in `tests/kernel`.
   - Enable `iommu = true` on existing nested tests, add the `_chv` test copies
     (`boot_nested_{test_guest,motor_os,linux_initrd,alpine}_chv*`) in
     `tests/tests/boot_vms.rs`, and add `--vmm chv` to
     `run-nested-{test-guest,motor-os,linux}.sh`.

2. **Sub-step `(p.2)` — `VmmHostCore` Passthrough ABI, `PassthroughPciDev` (`vmm-core`), & Ring-0 `pci_host.rs`**:
   - Add `pci_*` methods to `VmmHostCore`, `"vmm"::hv_pci_*` Wasm imports,
     `ShmPciPassthroughSpec` in `BridgeShm`, `MemRange::DevMem`, and
     `PassthroughPciDev` (`vmm-core/src/hw/pci/passthrough.rs`) + unit tests.
   - Implement `tests/kernel/src/vmm/pci_host.rs` (fail-closed IOMMU domain
     attachment, Guest RAM `gpa_map` -> `iommu.map_dma`, UC BAR `MemObjId`,
     VirtIO/FLR reset, and Ring-0 IDT `64..191` -> `inject_msi` fast path).

3. **Sub-step `(p.3)` — Topology A (`virtio-net` Passthrough on Full Motor OS L1, Both `wasm-vmm` & `chv` L0)**:
   - Wire `pci = [...]` in `vmm-io` (`vm.toml`) and `MotorIoHost`.
   - Add `boot_passthrough_net_alpine_{cwasm,wasm}` and
     `boot_passthrough_net_alpine_chv_{cwasm,wasm}` in `tests/tests/boot_vms.rs`
     plus `vm_scripts/run-passthrough-net-linux.sh [--vmm wasm|chv]`, verifying
     L1 has no NIC while L0 SSHes **directly** into L2 over the host TAP.

4. **Sub-step `(p.4)` — Topology B (`virtio-blk` + `virtio-net` Passthrough on `initrd-only` Motor OS L1, Both `wasm-vmm` & `chv` L0)**:
   - Build the reusable `InitrdBundle` packager + lean PID-2 passthrough runner
     with bidirectional interactive `COM1` serial.
   - Add `boot_passthrough_blk_alpine_{cwasm,wasm}` and
     `boot_passthrough_blk_alpine_chv_{cwasm,wasm}` in `tests/tests/boot_vms.rs`
     plus `vm_scripts/run-passthrough-blk-linux.sh [--vmm wasm|chv]`, booting
     full Alpine Linux in L2 directly off L0's `virtio-blk` + `virtio-net`
     under both `wasm-vmm` and `cloud-hypervisor-static`.

