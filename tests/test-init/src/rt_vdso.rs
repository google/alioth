// Self-bootstrapping vDSO loader for `test-init` (modeled on `sys-io/src/rt_vdso.rs`).
//
// `rt.vdso` is referenced read-only from `../motor-dev/motor-os`; see
// https://github.com/moturus/motor-os/blob/main/docs/build.md.

use core::sync::atomic::Ordering;
use elfloader::{
    ElfBinary, ElfLoader, ElfLoaderErr, Flags, LoadableHeaders, Machine, RelocationEntry,
    RelocationType, VAddr,
};

#[repr(C, align(64))]
struct AlignedBytes<B: ?Sized> {
    bytes: B,
}

static VDSO_BIN: &AlignedBytes<[u8]> = &AlignedBytes {
    bytes: *include_bytes!("../../../../motor-dev/motor-os/src/sys/lib/rt.vdso/rt.vdso"),
};

static VDSO_BYTES: &[u8] = &VDSO_BIN.bytes;

pub fn load() {
    let elf_binary = ElfBinary::new(VDSO_BYTES).expect("rt.vdso ELF parsing failed");
    assert_eq!(
        elf_binary.get_arch(),
        Machine::X86_64,
        "rt.vdso is not x86_64"
    );
    assert!(
        elf_binary.interpreter().is_none(),
        "rt.vdso must not have a dynamic interpreter"
    );

    let mut loader = VdsoLoader {
        mapped_regions: [(0, 0, 0); VdsoLoader::MAX_REGIONS],
        num_regions: 0,
    };
    elf_binary
        .load(&mut loader)
        .expect("failed to load rt.vdso segments");
    core::mem::drop(loader); // Unmaps temporary R+W aliases (W^X).

    let vdso_entry_addr = elf_binary.entry_point() + moto_rt::RT_VDSO_START;
    assert_ne!(vdso_entry_addr, 0);

    let vdso_bytes_sz = VDSO_BYTES.len() as u64;
    let num_pages = vdso_bytes_sz.div_ceil(moto_sys::sys_mem::PAGE_SIZE_SMALL);
    let addr = moto_sys::SysMem::map(
        moto_sys::SysHandle::SELF,
        moto_sys::SysMem::F_CUSTOM_USER
            | moto_sys::SysMem::F_READABLE
            | moto_sys::SysMem::F_WRITABLE,
        u64::MAX,
        moto_rt::RT_VDSO_BYTES_ADDR,
        moto_sys::sys_mem::PAGE_SIZE_SMALL,
        num_pages,
    )
    .unwrap();
    assert_eq!(addr, moto_rt::RT_VDSO_BYTES_ADDR);
    unsafe {
        core::ptr::copy_nonoverlapping(
            VDSO_BYTES.as_ptr(),
            moto_rt::RT_VDSO_BYTES_ADDR as usize as *mut u8,
            vdso_bytes_sz as usize,
        );
    }

    let addr = moto_sys::SysMem::map(
        moto_sys::SysHandle::SELF,
        moto_sys::SysMem::F_CUSTOM_USER
            | moto_sys::SysMem::F_READABLE
            | moto_sys::SysMem::F_WRITABLE,
        u64::MAX,
        moto_rt::RT_VDSO_VTABLE_VADDR,
        moto_sys::sys_mem::PAGE_SIZE_SMALL,
        1,
    )
    .unwrap();
    assert_eq!(addr, moto_rt::RT_VDSO_VTABLE_VADDR);

    let vdso_vtable = unsafe {
        (moto_rt::RT_VDSO_VTABLE_VADDR as usize as *const moto_rt::RtVdsoVtable)
            .as_ref()
            .unwrap()
    };
    vdso_vtable
        .vdso_entry
        .store(vdso_entry_addr, Ordering::Relaxed);
    vdso_vtable
        .vdso_bytes_sz
        .store(vdso_bytes_sz, Ordering::Release);

    // Zeroed ProcessData page at MOTO_SYS_CUSTOM_USERSPACE_REGION_START.
    let addr = moto_sys::SysMem::map(
        moto_sys::SysHandle::SELF,
        moto_sys::SysMem::F_CUSTOM_USER
            | moto_sys::SysMem::F_READABLE
            | moto_sys::SysMem::F_WRITABLE,
        u64::MAX,
        moto_rt::MOTO_SYS_CUSTOM_USERSPACE_REGION_START,
        moto_sys::sys_mem::PAGE_SIZE_SMALL,
        1,
    )
    .unwrap();
    assert_eq!(addr, moto_rt::MOTO_SYS_CUSTOM_USERSPACE_REGION_START);

    moto_rt::init();

    if moto_rt::RT_VERSION != std::os::motor::rt_version() {
        let msg = format!(
            "test-init: std expects moto-rt version {}, got {}\n",
            std::os::motor::rt_version(),
            moto_rt::RT_VERSION
        );
        let _ = moto_sys::SysRay::log(&msg);
        moto_sys::SysCpu::exit_process(0xbadc0de);
    }
}

struct VdsoLoader {
    // (unoffset vaddr, local RW alias, num_pages); no heap allocations before moto_rt::init().
    mapped_regions: [(u64, u64, u64); Self::MAX_REGIONS],
    num_regions: usize,
}

impl VdsoLoader {
    const MAX_REGIONS: usize = 16;

    unsafe fn write_via_alias(&self, dst: u64, src: *const u8, sz: u64) {
        let mut region: Option<(u64, u64, u64)> = None;
        for entry in &self.mapped_regions[..self.num_regions] {
            let region_sz = entry.2 << moto_sys::sys_mem::PAGE_SIZE_SMALL_LOG2;
            if entry.0 <= dst && (dst + sz) <= (entry.0 + region_sz) {
                region = Some(*entry);
                break;
            }
        }
        let (region_start, alias_start, _) = region.unwrap();
        unsafe {
            core::ptr::copy_nonoverlapping(
                src,
                (alias_start + (dst - region_start)) as usize as *mut u8,
                sz as usize,
            );
        }
    }
}

impl Drop for VdsoLoader {
    fn drop(&mut self) {
        for (_, alias, _) in &self.mapped_regions[..self.num_regions] {
            moto_sys::SysMem::unmap(moto_sys::SysHandle::SELF, 0, u64::MAX, *alias).unwrap();
        }
    }
}

impl ElfLoader for VdsoLoader {
    fn allocate(&mut self, load_headers: LoadableHeaders) -> Result<(), ElfLoaderErr> {
        use moto_rt::RT_VDSO_START;

        for header in load_headers {
            if header.flags().is_write() && header.flags().is_execute() {
                return Err(ElfLoaderErr::UnsupportedElfFormat);
            }

            let vaddr_start = header.virtual_addr() & !(moto_sys::sys_mem::PAGE_SIZE_SMALL - 1);
            let vaddr_end = moto_sys::align_up(
                header.virtual_addr() + header.mem_size(),
                moto_sys::sys_mem::PAGE_SIZE_SMALL,
            );

            let mut flags = moto_sys::SysMem::F_SHARE_SELF;
            if header.flags().is_read() {
                flags |= moto_sys::SysMem::F_READABLE;
            }
            if header.flags().is_write() {
                flags |= moto_sys::SysMem::F_WRITABLE;
            }
            if header.flags().is_execute() {
                flags |= moto_sys::SysMem::F_EXECUTABLE;
            }

            let num_pages = (vaddr_end - vaddr_start) >> moto_sys::sys_mem::PAGE_SIZE_SMALL_LOG2;
            let (addr, alias) = moto_sys::SysMem::map2(
                moto_sys::SysHandle::SELF,
                flags,
                u64::MAX,
                RT_VDSO_START + vaddr_start,
                moto_sys::sys_mem::PAGE_SIZE_SMALL,
                num_pages,
            )
            .map_err(|_| ElfLoaderErr::OutOfMemory)?;
            assert_eq!(addr, RT_VDSO_START + vaddr_start);
            assert!(self.num_regions < Self::MAX_REGIONS);
            self.mapped_regions[self.num_regions] = (vaddr_start, alias, num_pages);
            self.num_regions += 1;
        }
        Ok(())
    }

    fn load(&mut self, _flags: Flags, base: VAddr, region: &[u8]) -> Result<(), ElfLoaderErr> {
        unsafe {
            self.write_via_alias(base, region.as_ptr(), region.len() as u64);
        }
        Ok(())
    }

    fn relocate(&mut self, entry: RelocationEntry) -> Result<(), ElfLoaderErr> {
        use RelocationType::x86_64;
        use elfloader::arch::x86_64::RelocationTypes::{R_AMD64_NONE, R_AMD64_RELATIVE};

        match entry.rtype {
            x86_64(R_AMD64_RELATIVE) => {
                let addend = entry
                    .addend
                    .ok_or(ElfLoaderErr::UnsupportedRelocationEntry)?;
                let value = moto_rt::RT_VDSO_START + addend;
                unsafe {
                    self.write_via_alias(
                        entry.offset,
                        &raw const value as *const u8,
                        core::mem::size_of::<u64>() as u64,
                    );
                }
                Ok(())
            }
            x86_64(R_AMD64_NONE) => Ok(()),
            _ => panic!("unrecognized relocation entry: {:#?}", entry.rtype),
        }
    }
}
