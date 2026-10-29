// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::host::abi::{
    CoreToIoEntry, EXIT_INTERRUPTED, EXIT_IO, EXIT_MMIO, EXIT_REBOOT, EXIT_SHUTDOWN,
    IoToCoreEntry, RawCpuid, RawDoorbellSpec, RawRegEntry, RawVmExit, ShmBootInfo,
    ShmDeviceMsixRouting, ShmVirtioDeviceSpec, ShmVirtioQueueConfig, encode_vm_entry,
};
use crate::host::{
    DoorbellSpec, HostCaps, HvError, HvResult, IoSpace, MemObjId, MemProt, PayloadKind, RegId,
    RegVal, VcpuId, VmEntry, VmExit, VmmCoreBridge, VmmHostCore,
};

#[link(wasm_import_module = "vmm")]
unsafe extern "C" {
    fn hv_caps() -> u32;
    fn hv_supported_cpuids(dst_ptr: u32, max_entries: u32) -> i32;

    fn vcpu_configure(vcpu: u32, cpuids_ptr: u32, cpuids_len: u32) -> i32;
    fn vcpu_get_regs(vcpu: u32, regs_ptr: u32, regs_len: u32) -> i32;
    fn vcpu_set_regs(vcpu: u32, regs_ptr: u32, regs_len: u32) -> i32;
    fn vcpu_kick(vcpu: u32) -> i32;
    fn vcpu_run(vcpu: u32, entry_kind: u32, entry_data: u64, exit_out_ptr: u32) -> i32;

    fn mem_alloc(size: u64) -> i32;
    fn mem_free(obj: u32) -> i32;
    fn mem_read(obj: u32, offset: u64, dst_ptr: u32, len: u32) -> i32;
    fn mem_write(obj: u32, offset: u64, src_ptr: u32, len: u32) -> i32;
    fn gpa_map(gpa: u64, size: u64, obj: u32, offset: u64, prot: u32) -> i32;
    fn gpa_unmap(gpa: u64, size: u64) -> i32;

    fn inject_msi(addr: u64, data: u32) -> i32;
    fn set_gsi_level(gsi: u32, active: u32) -> i32;
    fn register_doorbell(spec_ptr: u32) -> i32;
    fn unregister_doorbell(space: u32, addr: u64, size: u32) -> i32;
}

#[link(wasm_import_module = "vmm_bridge")]
unsafe extern "C" {
    fn bridge_boot_info(boot_info_out_ptr: u32, devs_out_ptr: u32, max_devs: u32) -> i32;
    fn bridge_read_payload(kind: u32, offset: u64, dst_ptr: u32, len: u32) -> i32;
    fn bridge_configure_queues(dev: u32, queues_ptr: u32, num_queues: u32) -> i32;
    fn bridge_update_irq_route(dev: u32, routing_ptr: u32) -> i32;
    fn bridge_send_cmd(entry_ptr: u32) -> i32;
    fn bridge_recv_cmd(blocking: u32, entry_out_ptr: u32) -> i32;
}

#[inline]
fn check_rc(rc: i32) -> HvResult<u32> {
    if rc < 0 {
        Err(HvError::from_code(rc))
    } else {
        Ok(rc as u32)
    }
}

#[inline]
fn check_unit(rc: i32) -> HvResult<()> {
    check_rc(rc).map(|_| ())
}

#[derive(Debug, Default, Copy, Clone)]
pub struct WasmHost;

impl VmmHostCore for WasmHost {
    fn caps(&self) -> HostCaps {
        HostCaps::from_bits_retain(unsafe { hv_caps() })
    }

    fn supported_cpuids(&self, dst: &mut [RawCpuid]) -> HvResult<usize> {
        let n = check_rc(unsafe {
            hv_supported_cpuids(dst.as_mut_ptr() as u32, dst.len() as u32)
        })?;
        Ok(n as usize)
    }

    fn vcpu_configure(&self, vcpu: VcpuId, cpuids: &[RawCpuid]) -> HvResult<()> {
        check_unit(unsafe {
            vcpu_configure(vcpu, cpuids.as_ptr() as u32, cpuids.len() as u32)
        })
    }

    fn vcpu_get_regs(&self, vcpu: VcpuId, ids: &[RegId], out: &mut [RegVal]) -> HvResult<()> {
        if ids.len() != out.len() {
            return Err(HvError::InvalidParam);
        }
        const CHUNK: usize = 32;
        let mut raw = [RawRegEntry::default(); CHUNK];
        let mut offset = 0;
        while offset < ids.len() {
            let n = (ids.len() - offset).min(CHUNK);
            for i in 0..n {
                raw[i] = RawRegEntry::from_id(ids[offset + i]);
            }
            check_unit(unsafe { vcpu_get_regs(vcpu, raw.as_mut_ptr() as u32, n as u32) })?;
            for i in 0..n {
                out[offset + i] = raw[i].to_val()?;
            }
            offset += n;
        }
        Ok(())
    }

    fn vcpu_set_regs(&self, vcpu: VcpuId, regs: &[(RegId, RegVal)]) -> HvResult<()> {
        const CHUNK: usize = 32;
        let mut raw = [RawRegEntry::default(); CHUNK];
        for chunk in regs.chunks(CHUNK) {
            for (i, &(id, val)) in chunk.iter().enumerate() {
                raw[i] = RawRegEntry::from_pair(id, val);
            }
            check_unit(unsafe { vcpu_set_regs(vcpu, raw.as_ptr() as u32, chunk.len() as u32) })?;
        }
        Ok(())
    }

    fn vcpu_kick(&self, vcpu: VcpuId) -> HvResult<()> {
        check_unit(unsafe { vcpu_kick(vcpu) })
    }

    fn vcpu_run(&self, vcpu: VcpuId, entry: VmEntry) -> HvResult<VmExit> {
        let (entry_kind, entry_data) = encode_vm_entry(entry);
        let mut raw_exit = RawVmExit::default();
        check_unit(unsafe {
            vcpu_run(
                vcpu,
                entry_kind,
                entry_data,
                &mut raw_exit as *mut RawVmExit as u32,
            )
        })?;
        match raw_exit.kind {
            EXIT_IO => Ok(VmExit::Io {
                port: raw_exit.addr_or_port as u16,
                write: if raw_exit.is_write != 0 {
                    Some(raw_exit.data as u32)
                } else {
                    None
                },
                size: raw_exit.size,
            }),
            EXIT_MMIO => Ok(VmExit::Mmio {
                gpa: raw_exit.addr_or_port,
                write: if raw_exit.is_write != 0 {
                    Some(raw_exit.data)
                } else {
                    None
                },
                size: raw_exit.size,
            }),
            EXIT_SHUTDOWN => Ok(VmExit::Shutdown),
            EXIT_REBOOT => Ok(VmExit::Reboot),
            EXIT_INTERRUPTED => Ok(VmExit::Interrupted),
            _ => Err(HvError::HardwareFault),
        }
    }

    fn mem_alloc(&self, size: u64) -> HvResult<MemObjId> {
        check_rc(unsafe { mem_alloc(size) })
    }

    fn mem_free(&self, obj: MemObjId) -> HvResult<()> {
        check_unit(unsafe { mem_free(obj) })
    }

    fn mem_read(&self, obj: MemObjId, offset: u64, dst: &mut [u8]) -> HvResult<()> {
        check_unit(unsafe { mem_read(obj, offset, dst.as_mut_ptr() as u32, dst.len() as u32) })
    }

    fn mem_write(&self, obj: MemObjId, offset: u64, src: &[u8]) -> HvResult<()> {
        check_unit(unsafe { mem_write(obj, offset, src.as_ptr() as u32, src.len() as u32) })
    }

    fn gpa_map(
        &self,
        gpa: u64,
        size: u64,
        obj: MemObjId,
        offset: u64,
        prot: MemProt,
    ) -> HvResult<()> {
        check_unit(unsafe { gpa_map(gpa, size, obj, offset, prot.bits()) })
    }

    fn gpa_unmap(&self, gpa: u64, size: u64) -> HvResult<()> {
        check_unit(unsafe { gpa_unmap(gpa, size) })
    }

    fn inject_msi(&self, addr: u64, data: u32) -> HvResult<()> {
        check_unit(unsafe { inject_msi(addr, data) })
    }

    fn set_gsi_level(&self, gsi: u32, active: bool) -> HvResult<()> {
        check_unit(unsafe { set_gsi_level(gsi, u32::from(active)) })
    }

    fn register_doorbell(&self, spec: DoorbellSpec) -> HvResult<()> {
        let raw = RawDoorbellSpec::from(spec);
        check_unit(unsafe { register_doorbell(&raw as *const RawDoorbellSpec as u32) })
    }

    fn unregister_doorbell(&self, space: IoSpace, addr: u64, size: u8) -> HvResult<()> {
        check_unit(unsafe { unregister_doorbell(space as u32, addr, size as u32) })
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct WasmBridge;

impl VmmCoreBridge for WasmBridge {
    fn boot_info(
        &self,
        out_info: &mut ShmBootInfo,
        out_devs: &mut [ShmVirtioDeviceSpec],
    ) -> HvResult<usize> {
        let n = check_rc(unsafe {
            bridge_boot_info(
                out_info as *mut ShmBootInfo as u32,
                out_devs.as_mut_ptr() as u32,
                out_devs.len() as u32,
            )
        })?;
        Ok(n as usize)
    }

    fn read_payload(&self, kind: PayloadKind, offset: u64, dst: &mut [u8]) -> HvResult<usize> {
        let n = check_rc(unsafe {
            bridge_read_payload(kind as u32, offset, dst.as_mut_ptr() as u32, dst.len() as u32)
        })?;
        Ok(n as usize)
    }

    fn configure_device_queues(
        &self,
        dev: u32,
        queues: &[ShmVirtioQueueConfig],
    ) -> HvResult<()> {
        check_unit(unsafe {
            bridge_configure_queues(dev, queues.as_ptr() as u32, queues.len() as u32)
        })
    }

    fn update_irq_route(&self, dev: u32, routing: &ShmDeviceMsixRouting) -> HvResult<()> {
        check_unit(unsafe {
            bridge_update_irq_route(dev, routing as *const ShmDeviceMsixRouting as u32)
        })
    }

    fn send_io_cmd(&self, entry: &CoreToIoEntry) -> HvResult<()> {
        check_unit(unsafe { bridge_send_cmd(entry as *const CoreToIoEntry as u32) })
    }

    fn recv_io_cmd(&self, blocking: bool, out: &mut IoToCoreEntry) -> HvResult<bool> {
        let rc = check_rc(unsafe {
            bridge_recv_cmd(u32::from(blocking), out as *mut IoToCoreEntry as u32)
        })?;
        Ok(rc != 0)
    }
}

#[used]
static mut DATA_PAD: [u64; 16] = [1; 16];

thread_local! {
    static TLS_PAD: std::cell::Cell<[u64; 16]> = const { std::cell::Cell::new([1; 16]) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __vmm_memcpy(mut dst: *mut u8, mut src: *const u8, mut n: usize) {
    if n == usize::MAX {
        TLS_PAD.with(|c| c.set(unsafe { DATA_PAD }));
    }
    if dst as usize == src as usize || n == 0 {
        return;
    }
    if (dst as usize) < (src as usize) || (dst as usize) >= (src as usize).wrapping_add(n) {
        while core::hint::black_box(n) >= 8 {
            unsafe {
                let v = core::ptr::read_unaligned(src as *const u64);
                core::ptr::write_unaligned(dst as *mut u64, v);
                src = src.add(8);
                dst = dst.add(8);
            }
            n -= 8;
        }
        while core::hint::black_box(n) > 0 {
            unsafe {
                *dst = *src;
                src = src.add(1);
                dst = dst.add(1);
            }
            n -= 1;
        }
    } else {
        unsafe {
            src = src.add(n);
            dst = dst.add(n);
        }
        while core::hint::black_box(n) >= 8 {
            n -= 8;
            unsafe {
                src = src.sub(8);
                dst = dst.sub(8);
                let v = core::ptr::read_unaligned(src as *const u64);
                core::ptr::write_unaligned(dst as *mut u64, v);
            }
        }
        while core::hint::black_box(n) > 0 {
            n -= 1;
            unsafe {
                src = src.sub(1);
                dst = dst.sub(1);
                *dst = *src;
            }
        }
    }
}
