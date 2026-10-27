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

use std::sync::Arc;

use crate::host::abi::{
    ERR_INTERRUPTED, ERR_WOULD_BLOCK, EXEC_TYPE_LINUX, EXEC_TYPE_PVH, EXIT_INTERRUPTED, EXIT_IO,
    EXIT_MMIO, EXIT_REBOOT, EXIT_SHUTDOWN, MAX_QUEUES_PER_DEV, MAX_VIRTIO_DEVS, RawCpuid,
    RawDtRegEntry, RawDtRegVal, RawRegVal, RawSegRegEntry, RawSegRegVal, RawVmExit, ShmBootInfo,
    ShmDeviceMsixRouting, ShmMsiEntry, ShmVirtioDeviceSpec, ShmVirtioQueueConfig, dt_reg_to_u32,
    encode_vm_entry, mem_map_option_to_u32, reg_to_u32, seg_reg_to_u32, sreg_to_u32,
};
use crate::host::{
    CoreBootInfo, Cpuid, DtReg, DtRegVal, Error, Handle, Hypervisor, IntxSender, MemMapOption,
    MemPages, MsiSender, PayloadKind, Reg, Result, SReg, SegReg, SegRegVal, Vcpu, VirtioDeviceSpec,
    VirtioQueueConfig, Vm, VmEntry, VmExit, VmMemory,
};
use crate::loader::ExecType;

#[link(wasm_import_module = "vmm")]
unsafe extern "C" {
    fn vmm_last_error_len() -> u32;
    fn vmm_last_error_read(dst_ptr: u32, dst_len: u32) -> i32;

    fn hv_new() -> i32;
    fn hv_get_supported_cpuids(hv: u32, dst_ptr: u32, max_entries: u32) -> i32;
    fn hv_create_vm(hv: u32) -> i32;
    fn hv_close(hv: u32);

    fn vm_create_vcpu(vm: u32, id: u32) -> i32;
    fn vm_stop_vcpu(vm: u32, id: u32) -> i32;
    fn vm_create_vm_memory(vm: u32) -> i32;
    fn vm_create_intx_sender(vm: u32, pin: u32) -> i32;
    fn vm_create_msi_sender(vm: u32) -> i32;
    fn vm_close(vm: u32);

    fn vcpu_run(vcpu: u32, entry_kind: u32, entry_data: u64, exit_out_ptr: u32) -> i32;
    fn vcpu_get_reg(vcpu: u32, reg: u32, val_out_ptr: u32) -> i32;
    fn vcpu_set_regs(vcpu: u32, vals_ptr: u32, vals_len: u32) -> i32;
    fn vcpu_get_seg_reg(vcpu: u32, reg: u32, val_out_ptr: u32) -> i32;
    fn vcpu_get_dt_reg(vcpu: u32, reg: u32, val_out_ptr: u32) -> i32;
    fn vcpu_get_sreg(vcpu: u32, reg: u32, val_out_ptr: u32) -> i32;
    fn vcpu_set_sregs(
        vcpu: u32,
        sregs_ptr: u32,
        sregs_len: u32,
        seg_regs_ptr: u32,
        seg_regs_len: u32,
        dt_regs_ptr: u32,
        dt_regs_len: u32,
    ) -> i32;
    fn vcpu_set_cpuids(vcpu: u32, cpuids_ptr: u32, cpuids_len: u32) -> i32;
    fn vcpu_dump(vcpu: u32) -> i32;
    fn vcpu_close(vcpu: u32);

    fn vm_memory_mem_map(mem: u32, slot: u32, gpa: u64, size: u64, hva: u64, flags: u32) -> i32;
    fn vm_memory_unmap(mem: u32, slot: u32, gpa: u64, size: u64) -> i32;
    fn vm_memory_max_mem_slots(mem: u32, out_ptr: u32) -> i32;
    fn vm_memory_register_encrypted_range(mem: u32, addr: u64, size: u64) -> i32;
    fn vm_memory_deregister_encrypted_range(mem: u32, addr: u64, size: u64) -> i32;
    fn vm_memory_alloc_anon_mem(
        mem: u32,
        size: u64,
        addr_out_ptr: u32,
        size_out_ptr: u32,
    ) -> i32;
    fn vm_memory_close(mem: u32);

    fn mem_pages_sync(pages: u32) -> i32;
    fn mem_pages_read(pages: u32, offset: u64, dst_ptr: u32, len: u32) -> i32;
    fn mem_pages_write(pages: u32, offset: u64, src_ptr: u32, len: u32) -> i32;
    fn mem_pages_close(pages: u32);

    fn intx_sender_send(sender: u32) -> i32;
    fn intx_sender_close(sender: u32);

    fn msi_sender_send(sender: u32, addr: u64, data: u32) -> i32;
    fn msi_sender_close(sender: u32);

    fn core_get_boot_info(boot_info_out_ptr: u32, devs_out_ptr: u32, max_devs: u32) -> i32;
    fn core_read_payload(kind: u32, offset: u64, dst_ptr: u32, len: u32) -> i32;
    fn core_virtio_start(
        dev: u64,
        driver_features: u64,
        queues_ptr: u32,
        num_queues: u32,
    ) -> i32;
    fn core_virtio_notify(dev: u64, queue_index: u32) -> i32;
    fn core_virtio_reset(dev: u64) -> i32;
    fn core_virtio_update_irq(dev: u64, routing_ptr: u32) -> i32;
    fn core_serial_tx(byte: u32) -> i32;
    fn core_serial_rx(dst_ptr: u32, max_len: u32) -> i32;
    fn core_notify_shutdown() -> i32;
}

fn fetch_last_error() -> String {
    let len = unsafe { vmm_last_error_len() } as usize;
    if len == 0 {
        return "unknown host error".to_string();
    }
    let mut buf = vec![0u8; len];
    unsafe { vmm_last_error_read(buf.as_mut_ptr() as u32, len as u32) };
    String::from_utf8_lossy(&buf).into_owned()
}

fn check_hv(rc: i32) -> Result<u32, Error> {
    if rc < 0 {
        Err(Error::Unexpected {
            msg: fetch_last_error(),
        })
    } else {
        Ok(rc as u32)
    }
}

fn check_hv_unit(rc: i32) -> Result<(), Error> {
    check_hv(rc).map(|_| ())
}

fn check_io(rc: i32) -> std::io::Result<u32> {
    if rc >= 0 {
        Ok(rc as u32)
    } else if rc == ERR_WOULD_BLOCK {
        Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
    } else if rc == ERR_INTERRUPTED {
        Err(std::io::Error::from(std::io::ErrorKind::Interrupted))
    } else {
        Err(std::io::Error::other(fetch_last_error()))
    }
}

fn check_io_unit(rc: i32) -> std::io::Result<()> {
    check_io(rc).map(|_| ())
}

#[derive(Debug)]
pub struct WasmMemPages {
    handle: u32,
    addr: u64,
    size: usize,
}

impl Drop for WasmMemPages {
    fn drop(&mut self) {
        unsafe { mem_pages_close(self.handle) };
    }
}

impl MemPages for WasmMemPages {
    fn addr(&self) -> u64 {
        self.addr
    }

    fn size(&self) -> usize {
        self.size
    }

    fn sync(&self) -> std::io::Result<()> {
        check_io_unit(unsafe { mem_pages_sync(self.handle) })
    }

    fn read(&self, offset: usize, dst: &mut [u8]) -> std::io::Result<()> {
        check_io_unit(unsafe {
            mem_pages_read(
                self.handle,
                offset as u64,
                dst.as_mut_ptr() as u32,
                dst.len() as u32,
            )
        })
    }

    fn write(&self, offset: usize, src: &[u8]) -> std::io::Result<()> {
        check_io_unit(unsafe {
            mem_pages_write(
                self.handle,
                offset as u64,
                src.as_ptr() as u32,
                src.len() as u32,
            )
        })
    }
}

#[derive(Debug)]
pub struct WasmVmMemory {
    handle: u32,
}

impl Drop for WasmVmMemory {
    fn drop(&mut self) {
        unsafe { vm_memory_close(self.handle) };
    }
}

impl VmMemory for WasmVmMemory {
    fn mem_map(
        &self,
        slot: u32,
        gpa: u64,
        size: usize,
        hva: u64,
        option: MemMapOption,
    ) -> Result<(), Error> {
        check_hv_unit(unsafe {
            vm_memory_mem_map(
                self.handle,
                slot,
                gpa,
                size as u64,
                hva,
                mem_map_option_to_u32(option),
            )
        })
    }

    fn unmap(&self, slot: u32, gpa: u64, size: usize) -> Result<(), Error> {
        check_hv_unit(unsafe { vm_memory_unmap(self.handle, slot, gpa, size as u64) })
    }

    fn max_mem_slots(&self) -> Result<u32, Error> {
        let mut out = 0u32;
        check_hv_unit(unsafe { vm_memory_max_mem_slots(self.handle, &mut out as *mut u32 as u32) })?;
        Ok(out)
    }

    fn register_encrypted_range(&self, addr: u64, size: usize) -> Result<()> {
        check_hv_unit(unsafe {
            vm_memory_register_encrypted_range(self.handle, addr, size as u64)
        })
    }

    fn deregister_encrypted_range(&self, addr: u64, size: usize) -> Result<()> {
        check_hv_unit(unsafe {
            vm_memory_deregister_encrypted_range(self.handle, addr, size as u64)
        })
    }

    fn alloc_anon_mem(&self, size: usize) -> std::io::Result<Arc<dyn MemPages>> {
        let mut addr = 0u64;
        let mut actual_size = 0u64;
        let handle = check_io(unsafe {
            vm_memory_alloc_anon_mem(
                self.handle,
                size as u64,
                &mut addr as *mut u64 as u32,
                &mut actual_size as *mut u64 as u32,
            )
        })?;
        Ok(Arc::new(WasmMemPages {
            handle,
            addr,
            size: actual_size as usize,
        }))
    }
}

#[derive(Debug)]
pub struct WasmIntxSender {
    handle: u32,
}

impl Drop for WasmIntxSender {
    fn drop(&mut self) {
        unsafe { intx_sender_close(self.handle) };
    }
}

impl IntxSender for WasmIntxSender {
    fn send(&self) -> Result<(), Error> {
        check_hv_unit(unsafe { intx_sender_send(self.handle) })
    }
}

#[derive(Debug)]
pub struct WasmMsiSender {
    handle: u32,
}

impl Drop for WasmMsiSender {
    fn drop(&mut self) {
        unsafe { msi_sender_close(self.handle) };
    }
}

impl MsiSender for WasmMsiSender {
    fn send(&self, addr: u64, data: u32) -> Result<()> {
        check_hv_unit(unsafe { msi_sender_send(self.handle, addr, data) })
    }
}

#[derive(Debug)]
pub struct WasmVcpu {
    handle: u32,
}

impl Drop for WasmVcpu {
    fn drop(&mut self) {
        unsafe { vcpu_close(self.handle) };
    }
}

impl Vcpu for WasmVcpu {
    fn run(&mut self, entry: VmEntry) -> Result<VmExit, Error> {
        let (entry_kind, entry_data) = encode_vm_entry(entry);
        let mut raw_exit = RawVmExit::default();
        check_hv_unit(unsafe {
            vcpu_run(
                self.handle,
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
                addr: raw_exit.addr_or_port,
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
            _ => Ok(VmExit::Unknown(fetch_last_error())),
        }
    }

    fn get_reg(&self, reg: Reg) -> Result<u64, Error> {
        let mut val = 0u64;
        check_hv_unit(unsafe {
            vcpu_get_reg(self.handle, reg_to_u32(reg), &mut val as *mut u64 as u32)
        })?;
        Ok(val)
    }

    fn set_regs(&mut self, vals: &[(Reg, u64)]) -> Result<(), Error> {
        let raw_vals: Vec<RawRegVal> = vals
            .iter()
            .map(|&(r, val)| RawRegVal {
                reg: reg_to_u32(r),
                _pad: 0,
                val,
            })
            .collect();
        check_hv_unit(unsafe {
            vcpu_set_regs(self.handle, raw_vals.as_ptr() as u32, raw_vals.len() as u32)
        })
    }

    fn get_seg_reg(&self, reg: SegReg) -> Result<SegRegVal, Error> {
        let mut raw = RawSegRegVal::default();
        check_hv_unit(unsafe {
            vcpu_get_seg_reg(
                self.handle,
                seg_reg_to_u32(reg),
                &mut raw as *mut RawSegRegVal as u32,
            )
        })?;
        Ok(raw.into())
    }

    fn get_dt_reg(&self, reg: DtReg) -> Result<DtRegVal, Error> {
        let mut raw = RawDtRegVal::default();
        check_hv_unit(unsafe {
            vcpu_get_dt_reg(
                self.handle,
                dt_reg_to_u32(reg),
                &mut raw as *mut RawDtRegVal as u32,
            )
        })?;
        Ok(raw.into())
    }

    fn get_sreg(&self, reg: SReg) -> Result<u64, Error> {
        let mut val = 0u64;
        check_hv_unit(unsafe {
            vcpu_get_sreg(self.handle, sreg_to_u32(reg), &mut val as *mut u64 as u32)
        })?;
        Ok(val)
    }

    fn set_sregs(
        &mut self,
        sregs: &[(SReg, u64)],
        seg_regs: &[(SegReg, SegRegVal)],
        dt_regs: &[(DtReg, DtRegVal)],
    ) -> Result<(), Error> {
        let raw_sregs: Vec<RawRegVal> = sregs
            .iter()
            .map(|&(r, val)| RawRegVal {
                reg: sreg_to_u32(r),
                _pad: 0,
                val,
            })
            .collect();
        let raw_seg_regs: Vec<RawSegRegEntry> = seg_regs
            .iter()
            .map(|&(r, val)| RawSegRegEntry {
                reg: seg_reg_to_u32(r),
                _pad: 0,
                val: val.into(),
            })
            .collect();
        let raw_dt_regs: Vec<RawDtRegEntry> = dt_regs
            .iter()
            .map(|&(r, val)| RawDtRegEntry {
                reg: dt_reg_to_u32(r),
                _pad: 0,
                val: val.into(),
            })
            .collect();
        check_hv_unit(unsafe {
            vcpu_set_sregs(
                self.handle,
                raw_sregs.as_ptr() as u32,
                raw_sregs.len() as u32,
                raw_seg_regs.as_ptr() as u32,
                raw_seg_regs.len() as u32,
                raw_dt_regs.as_ptr() as u32,
                raw_dt_regs.len() as u32,
            )
        })
    }

    fn set_cpuids(&mut self, cpuids: Vec<Cpuid>) -> Result<(), Error> {
        let raw_cpuids: Vec<RawCpuid> = cpuids.into_iter().map(RawCpuid::from).collect();
        check_hv_unit(unsafe {
            vcpu_set_cpuids(
                self.handle,
                raw_cpuids.as_ptr() as u32,
                raw_cpuids.len() as u32,
            )
        })
    }

    fn dump(&self) -> Result<(), Error> {
        check_hv_unit(unsafe { vcpu_dump(self.handle) })
    }
}

#[derive(Debug)]
pub struct WasmVm {
    handle: u32,
}

impl Drop for WasmVm {
    fn drop(&mut self) {
        unsafe { vm_close(self.handle) };
    }
}

impl Vm for WasmVm {
    fn create_vcpu(&self, id: u32) -> Result<Box<dyn Vcpu>, Error> {
        let handle = check_hv(unsafe { vm_create_vcpu(self.handle, id) })?;
        Ok(Box::new(WasmVcpu { handle }))
    }

    fn stop_vcpu(&self, id: u32) -> Result<(), Error> {
        check_hv_unit(unsafe { vm_stop_vcpu(self.handle, id) })
    }

    fn create_vm_memory(&mut self) -> Result<Box<dyn VmMemory>, Error> {
        let handle = check_hv(unsafe { vm_create_vm_memory(self.handle) })?;
        Ok(Box::new(WasmVmMemory { handle }))
    }

    fn create_intx_sender(&self, pin: u8) -> Result<Box<dyn IntxSender>, Error> {
        let handle = check_hv(unsafe { vm_create_intx_sender(self.handle, pin as u32) })?;
        Ok(Box::new(WasmIntxSender { handle }))
    }

    fn create_msi_sender(&self) -> Result<Box<dyn MsiSender>, Error> {
        let handle = check_hv(unsafe { vm_create_msi_sender(self.handle) })?;
        Ok(Box::new(WasmMsiSender { handle }))
    }
}

#[derive(Debug)]
pub struct WasmHypervisor {
    handle: u32,
}

impl Drop for WasmHypervisor {
    fn drop(&mut self) {
        unsafe { hv_close(self.handle) };
    }
}

impl WasmHypervisor {
    pub fn new() -> Result<Self, String> {
        let handle = check_hv(unsafe { hv_new() }).map_err(|e| e.to_string())?;
        Ok(Self { handle })
    }
}

impl Hypervisor for WasmHypervisor {
    fn create_vm(&self) -> Result<Box<dyn Vm>, Error> {
        let handle = check_hv(unsafe { hv_create_vm(self.handle) })?;
        Ok(Box::new(WasmVm { handle }))
    }

    fn get_supported_cpuids(&self) -> Result<Vec<Cpuid>, Error> {
        let mut raw = vec![RawCpuid::default(); 256];
        let count = check_hv(unsafe {
            hv_get_supported_cpuids(self.handle, raw.as_mut_ptr() as u32, raw.len() as u32)
        })? as usize;
        raw.truncate(count);
        Ok(raw.into_iter().map(Cpuid::from).collect())
    }

    fn core_get_boot_info(&self) -> Result<(CoreBootInfo, Vec<VirtioDeviceSpec>), Error> {
        let mut raw_boot = ShmBootInfo::default();
        let mut raw_devs = vec![ShmVirtioDeviceSpec::default(); MAX_VIRTIO_DEVS];
        let num_devs = check_hv(unsafe {
            core_get_boot_info(
                &mut raw_boot as *mut ShmBootInfo as u32,
                raw_devs.as_mut_ptr() as u32,
                MAX_VIRTIO_DEVS as u32,
            )
        })? as usize;
        raw_devs.truncate(num_devs);

        let exec_type = match raw_boot.exec_type {
            EXEC_TYPE_LINUX => Some(ExecType::Linux),
            EXEC_TYPE_PVH => Some(ExecType::Pvh),
            _ => None,
        };
        let cmd_line_len = (raw_boot.cmd_line_len as usize).min(raw_boot.cmd_line.len());
        let cmd_line = if cmd_line_len > 0 {
            Some(
                String::from_utf8_lossy(&raw_boot.cmd_line[..cmd_line_len])
                    .into_owned(),
            )
        } else {
            None
        };
        let initramfs_size = if raw_boot.initramfs_size > 0 {
            Some(raw_boot.initramfs_size)
        } else {
            None
        };
        let boot_info = CoreBootInfo {
            num_cpus: raw_boot.num_cpus,
            mem_size: raw_boot.mem_size as usize,
            exec_type,
            kernel_size: raw_boot.kernel_size,
            initramfs_size,
            cmd_line,
        };

        let mut specs = Vec::with_capacity(raw_devs.len());
        for raw in raw_devs {
            let name_len = (raw.name_len as usize).min(raw.name.len());
            let name = String::from_utf8_lossy(&raw.name[..name_len]).into_owned();
            let cfg_len = (raw.config_len as usize).min(raw.config_bytes.len());
            let config_bytes = raw.config_bytes[..cfg_len].to_vec();
            specs.push(VirtioDeviceSpec {
                dev: raw.dev,
                name,
                device_id: raw.device_id,
                device_features: raw.device_features,
                num_queues: raw.num_queues,
                config_bytes,
            });
        }
        Ok((boot_info, specs))
    }

    fn core_read_payload(
        &self,
        kind: PayloadKind,
        offset: u64,
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        let n = check_hv(unsafe {
            core_read_payload(
                kind as u32,
                offset,
                dst.as_mut_ptr() as u32,
                dst.len() as u32,
            )
        })? as usize;
        Ok(n)
    }

    fn core_virtio_start(
        &self,
        dev: Handle,
        driver_features: u64,
        queues: &[VirtioQueueConfig],
    ) -> Result<(), Error> {
        let raw_queues: Vec<ShmVirtioQueueConfig> =
            queues.iter().copied().map(ShmVirtioQueueConfig::from).collect();
        check_hv_unit(unsafe {
            core_virtio_start(
                dev,
                driver_features,
                raw_queues.as_ptr() as u32,
                raw_queues.len() as u32,
            )
        })
    }

    fn core_virtio_notify(&self, dev: Handle, queue_index: u16) -> Result<(), Error> {
        check_hv_unit(unsafe { core_virtio_notify(dev, queue_index as u32) })
    }

    fn core_virtio_reset(&self, dev: Handle) -> Result<(), Error> {
        check_hv_unit(unsafe { core_virtio_reset(dev) })
    }

    fn core_virtio_update_irq(
        &self,
        dev: Handle,
        config_msi: Option<(u64, u32)>,
        queue_msis: &[Option<(u64, u32)>],
    ) -> Result<(), Error> {
        let mut routing = ShmDeviceMsixRouting::default();
        if let Some((addr, data)) = config_msi {
            routing.config_msi = ShmMsiEntry {
                addr,
                data,
                enabled: 1,
            };
        }
        for (i, q_msi) in queue_msis.iter().enumerate().take(MAX_QUEUES_PER_DEV) {
            if let Some((addr, data)) = q_msi {
                routing.queue_msis[i] = ShmMsiEntry {
                    addr: *addr,
                    data: *data,
                    enabled: 1,
                };
            }
        }
        check_hv_unit(unsafe {
            core_virtio_update_irq(dev, &routing as *const ShmDeviceMsixRouting as u32)
        })
    }

    fn core_serial_tx(&self, byte: u8) -> Result<(), Error> {
        check_hv_unit(unsafe { core_serial_tx(byte as u32) })
    }

    fn core_serial_rx(&self, dst: &mut [u8]) -> Result<usize, Error> {
        let n = check_hv(unsafe { core_serial_rx(dst.as_mut_ptr() as u32, dst.len() as u32) })?;
        Ok(n as usize)
    }

    fn core_notify_shutdown(&self) -> Result<(), Error> {
        check_hv_unit(unsafe { core_notify_shutdown() })
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
