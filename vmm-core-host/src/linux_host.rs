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

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::{Mutex, RwLock};
use vmm_core::host::{
    CoreBootInfo, Cpuid, DtReg, DtRegVal, Error as HvError, Handle, Hypervisor, IntxSender,
    MemMapOption, MemPages, MsiSender, PayloadKind, Reg, Result as HvResult, SReg, SegReg,
    SegRegVal, Vcpu, VirtioDeviceSpec, VirtioQueueConfig, Vm, VmEntry, VmExit, VmMemory,
};

use crate::kvm::{CoreBridgeFds, Kvm, SharedCoreBridge};
use crate::wasm_host::VmmHostCore;

struct ResourceTable<T: ?Sized> {
    next_id: AtomicU64,
    items: RwLock<HashMap<Handle, Arc<T>>>,
}

impl<T: ?Sized> Default for ResourceTable<T> {
    fn default() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            items: RwLock::new(HashMap::new()),
        }
    }
}

impl<T> ResourceTable<T> {
    fn insert(&self, val: T) -> Handle {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.items.write().insert(id, Arc::new(val));
        id
    }
}

impl<T: ?Sized> ResourceTable<T> {
    fn insert_arc(&self, val: Arc<T>) -> Handle {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.items.write().insert(id, val);
        id
    }

    fn get(&self, id: Handle) -> HvResult<Arc<T>> {
        self.items
            .read()
            .get(&id)
            .cloned()
            .ok_or_else(|| HvError::Unexpected {
                msg: format!("invalid resource handle {id}"),
            })
    }

    fn remove(&self, id: Handle) {
        self.items.write().remove(&id);
    }
}

/// Linux/KVM implementation of [`VmmHostCore`].
pub struct KvmCoreHost {
    bridge: Arc<SharedCoreBridge>,
    hypervisors: ResourceTable<Kvm>,
    vms: ResourceTable<RwLock<Box<dyn Vm>>>,
    vcpus: ResourceTable<Mutex<Box<dyn Vcpu>>>,
    vm_memories: ResourceTable<Box<dyn VmMemory>>,
    mem_pages: ResourceTable<dyn MemPages>,
    intx_senders: ResourceTable<Box<dyn IntxSender>>,
    msi_senders: ResourceTable<Box<dyn MsiSender>>,
}

impl KvmCoreHost {
    pub fn new(fds: CoreBridgeFds) -> std::io::Result<Self> {
        let bridge = SharedCoreBridge::from_fds(fds)?;
        Ok(Self {
            bridge,
            hypervisors: ResourceTable::default(),
            vms: ResourceTable::default(),
            vcpus: ResourceTable::default(),
            vm_memories: ResourceTable::default(),
            mem_pages: ResourceTable::default(),
            intx_senders: ResourceTable::default(),
            msi_senders: ResourceTable::default(),
        })
    }
}

impl VmmHostCore for KvmCoreHost {
    fn hv_new(&self) -> HvResult<Handle> {
        let kvm = Kvm::new(self.bridge.clone())?;
        Ok(self.hypervisors.insert(kvm))
    }

    fn hv_get_supported_cpuids(&self, hv: Handle) -> HvResult<Vec<Cpuid>> {
        self.hypervisors.get(hv)?.get_supported_cpuids()
    }

    fn hv_create_vm(&self, hv: Handle) -> HvResult<Handle> {
        let vm = self.hypervisors.get(hv)?.create_vm()?;
        Ok(self.vms.insert(RwLock::new(vm)))
    }

    fn hv_close(&self, hv: Handle) {
        self.hypervisors.remove(hv);
    }

    fn vm_create_vcpu(&self, vm: Handle, id: u32) -> HvResult<Handle> {
        let vcpu = self.vms.get(vm)?.read().create_vcpu(id)?;
        Ok(self.vcpus.insert(Mutex::new(vcpu)))
    }

    fn vm_stop_vcpu(&self, vm: Handle, id: u32) -> HvResult<()> {
        self.vms.get(vm)?.read().stop_vcpu(id)
    }

    fn vm_create_vm_memory(&self, vm: Handle) -> HvResult<Handle> {
        let mem = self.vms.get(vm)?.write().create_vm_memory()?;
        Ok(self.vm_memories.insert(mem))
    }

    fn vm_create_intx_sender(&self, vm: Handle, pin: u8) -> HvResult<Handle> {
        let sender = self.vms.get(vm)?.read().create_intx_sender(pin)?;
        Ok(self.intx_senders.insert(sender))
    }

    fn vm_create_msi_sender(&self, vm: Handle) -> HvResult<Handle> {
        let sender = self.vms.get(vm)?.read().create_msi_sender()?;
        Ok(self.msi_senders.insert(sender))
    }

    fn vm_close(&self, vm: Handle) {
        self.vms.remove(vm);
    }

    fn vcpu_run(&self, vcpu: Handle, entry: VmEntry) -> HvResult<VmExit> {
        self.vcpus.get(vcpu)?.lock().run(entry)
    }

    fn vcpu_get_reg(&self, vcpu: Handle, reg: Reg) -> HvResult<u64> {
        self.vcpus.get(vcpu)?.lock().get_reg(reg)
    }

    fn vcpu_set_regs(&self, vcpu: Handle, vals: &[(Reg, u64)]) -> HvResult<()> {
        self.vcpus.get(vcpu)?.lock().set_regs(vals)
    }

    fn vcpu_get_seg_reg(&self, vcpu: Handle, reg: SegReg) -> HvResult<SegRegVal> {
        self.vcpus.get(vcpu)?.lock().get_seg_reg(reg)
    }

    fn vcpu_get_dt_reg(&self, vcpu: Handle, reg: DtReg) -> HvResult<DtRegVal> {
        self.vcpus.get(vcpu)?.lock().get_dt_reg(reg)
    }

    fn vcpu_get_sreg(&self, vcpu: Handle, reg: SReg) -> HvResult<u64> {
        self.vcpus.get(vcpu)?.lock().get_sreg(reg)
    }

    fn vcpu_set_sregs(
        &self,
        vcpu: Handle,
        sregs: &[(SReg, u64)],
        seg_regs: &[(SegReg, SegRegVal)],
        dt_regs: &[(DtReg, DtRegVal)],
    ) -> HvResult<()> {
        self.vcpus
            .get(vcpu)?
            .lock()
            .set_sregs(sregs, seg_regs, dt_regs)
    }

    fn vcpu_set_cpuids(&self, vcpu: Handle, cpuids: Vec<Cpuid>) -> HvResult<()> {
        self.vcpus.get(vcpu)?.lock().set_cpuids(cpuids)
    }

    fn vcpu_dump(&self, vcpu: Handle) -> HvResult<()> {
        self.vcpus.get(vcpu)?.lock().dump()
    }

    fn vcpu_close(&self, vcpu: Handle) {
        self.vcpus.remove(vcpu);
    }

    fn vm_memory_mem_map(
        &self,
        mem: Handle,
        slot: u32,
        gpa: u64,
        size: u64,
        hva: u64,
        option: MemMapOption,
    ) -> HvResult<()> {
        self.vm_memories
            .get(mem)?
            .mem_map(slot, gpa, size as usize, hva, option)
    }

    fn vm_memory_unmap(&self, mem: Handle, slot: u32, gpa: u64, size: u64) -> HvResult<()> {
        self.vm_memories.get(mem)?.unmap(slot, gpa, size as usize)
    }

    fn vm_memory_max_mem_slots(&self, mem: Handle) -> HvResult<u32> {
        self.vm_memories.get(mem)?.max_mem_slots()
    }

    fn vm_memory_register_encrypted_range(
        &self,
        mem: Handle,
        addr: u64,
        size: u64,
    ) -> HvResult<()> {
        self.vm_memories
            .get(mem)?
            .register_encrypted_range(addr, size as usize)
    }

    fn vm_memory_deregister_encrypted_range(
        &self,
        mem: Handle,
        addr: u64,
        size: u64,
    ) -> HvResult<()> {
        self.vm_memories
            .get(mem)?
            .deregister_encrypted_range(addr, size as usize)
    }

    fn vm_memory_alloc_anon_mem(&self, mem: Handle, size: u64) -> HvResult<(Handle, u64, u64)> {
        let pages = self.vm_memories.get(mem)?.alloc_anon_mem(size as usize)?;
        let addr = pages.addr();
        let actual_size = pages.size() as u64;
        let handle = self.mem_pages.insert_arc(pages);
        Ok((handle, addr, actual_size))
    }

    fn vm_memory_close(&self, mem: Handle) {
        self.vm_memories.remove(mem);
    }

    fn mem_pages_sync(&self, pages: Handle) -> HvResult<()> {
        self.mem_pages.get(pages)?.sync().map_err(Into::into)
    }

    fn mem_pages_read(&self, pages: Handle, offset: u64, dst: &mut [u8]) -> HvResult<()> {
        self.mem_pages
            .get(pages)?
            .read(offset as usize, dst)
            .map_err(Into::into)
    }

    fn mem_pages_write(&self, pages: Handle, offset: u64, src: &[u8]) -> HvResult<()> {
        self.mem_pages
            .get(pages)?
            .write(offset as usize, src)
            .map_err(Into::into)
    }

    fn mem_pages_close(&self, pages: Handle) {
        self.mem_pages.remove(pages);
    }

    fn intx_sender_send(&self, sender: Handle) -> HvResult<()> {
        self.intx_senders.get(sender)?.send()
    }

    fn intx_sender_close(&self, sender: Handle) {
        self.intx_senders.remove(sender);
    }

    fn msi_sender_send(&self, sender: Handle, addr: u64, data: u32) -> HvResult<()> {
        self.msi_senders.get(sender)?.send(addr, data)
    }

    fn msi_sender_close(&self, sender: Handle) {
        self.msi_senders.remove(sender);
    }

    fn core_get_boot_info(&self) -> HvResult<(CoreBootInfo, Vec<VirtioDeviceSpec>)> {
        self.bridge.core_get_boot_info()
    }

    fn core_read_payload(
        &self,
        kind: PayloadKind,
        offset: u64,
        dst: &mut [u8],
    ) -> HvResult<usize> {
        self.bridge.core_read_payload(kind, offset, dst)
    }

    fn core_virtio_start(
        &self,
        dev: Handle,
        driver_features: u64,
        queues: &[VirtioQueueConfig],
    ) -> HvResult<()> {
        self.bridge.core_virtio_start(dev, driver_features, queues)
    }

    fn core_virtio_notify(&self, dev: Handle, queue_index: u16) -> HvResult<()> {
        self.bridge.core_virtio_notify(dev, queue_index)
    }

    fn core_virtio_reset(&self, dev: Handle) -> HvResult<()> {
        self.bridge.core_virtio_reset(dev)
    }

    fn core_virtio_update_irq(
        &self,
        dev: Handle,
        config_msi: Option<(u64, u32)>,
        queue_msis: &[Option<(u64, u32)>],
    ) -> HvResult<()> {
        self.bridge
            .core_virtio_update_irq(dev, config_msi, queue_msis)
    }

    fn core_serial_tx(&self, byte: u8) -> HvResult<()> {
        self.bridge.core_serial_tx(byte)
    }

    fn core_serial_rx(&self, dst: &mut [u8]) -> HvResult<usize> {
        self.bridge.core_serial_rx(dst)
    }

    fn core_notify_shutdown(&self) -> HvResult<()> {
        self.bridge.core_notify_shutdown()
    }
}
