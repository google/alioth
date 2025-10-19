// Copyright 2025 Google LLC
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

use std::any::Any;
use std::sync::Arc;

use assert_matches::assert_matches;
use rstest::rstest;

use crate::mem::emulated::{Action, Mmio};
use crate::mem::{self, IoRegion, MemRegion, MemRegionType};
use crate::pci::config::{
    BAR_IO, BAR_MEM32, BAR_MEM64, Command, CommonHeader, ConfigHeader, DeviceHeader,
    EmulatedHeader, MoveBarCallback, Status, UpdateCommandCallback, offset_bar,
};
use crate::pci::{Bdf, PciBar};

#[derive(Debug)]
struct TestRange {
    size: u64,
}

impl Mmio for TestRange {
    fn read(&self, _: u64, _: u8) -> mem::Result<u64> {
        Ok(0)
    }

    fn write(&self, _: u64, _: u8, _: u64) -> mem::Result<Action> {
        Ok(Action::None)
    }

    fn size(&self) -> u64 {
        self.size
    }
}

fn fixture_emulated_header() -> EmulatedHeader {
    let header = ConfigHeader::Device(DeviceHeader {
        bars: [
            0xe000_0000 | BAR_MEM32,
            0,
            BAR_MEM64,
            0x0000_0001,
            0,
            0xe000 | BAR_IO,
        ],
        ..Default::default()
    });
    let bars = [
        PciBar::Mem(Arc::new(MemRegion::with_emulated(
            Arc::new(TestRange { size: 1 << 10 }),
            MemRegionType::Hidden,
        ))),
        PciBar::Empty,
        PciBar::Mem(Arc::new(MemRegion::with_emulated(
            Arc::new(TestRange { size: 1 << 30 }),
            MemRegionType::Hidden,
        ))),
        PciBar::Empty,
        PciBar::Empty,
        PciBar::Io(Arc::new(IoRegion::new(Arc::new(TestRange { size: 2 })))),
    ];

    EmulatedHeader::new(header, bars)
}

#[test]
fn test_emulated_header_masks() {
    let header = fixture_emulated_header();
    let data = header.data.read();
    assert_eq!(
        data.bar_masks,
        [0xffff_f000, 0x0, 0xc000_0000, 0xffff_ffff, 0x0, 0xffff_fffc,]
    );
}

#[rstest]
#[case(Command::empty(), Command::empty(), Command::empty())]
#[case(Command::empty(), Command::IO, Command::IO)]
#[case(Command::IO, Command::MEM, Command::IO | Command::MEM)]
#[case(Command::IO | Command::MEM | Command::INTX_DISABLE, Command::MEM,
    Command::IO | Command::INTX_DISABLE)]
fn test_emulated_header_change_command(
    #[case] old: Command,
    #[case] new: Command,
    #[case] changed: Command,
) {
    let header = fixture_emulated_header();
    header.set_command(old);

    let got = header
        .write(
            CommonHeader::OFFSET_COMMAND as u64,
            size_of::<Command>() as u8,
            new.bits() as u64,
        )
        .unwrap();

    if let Action::ChangeLayout { callback } = got {
        let callback = <dyn Any>::downcast_ref::<UpdateCommandCallback>(&*callback).unwrap();
        assert_eq!(callback.changed, changed);
    } else {
        assert_matches!(got, Action::None);
        assert_eq!(changed, Command::empty());
    }

    let val = header
        .read(
            CommonHeader::OFFSET_COMMAND as u64,
            size_of::<Command>() as u8,
        )
        .unwrap();
    assert_eq!(val as u16, new.bits());
}

#[rstest]
#[case(Command::empty(), 5, 0xc000, None)]
#[case(Command::IO, 5, 0xe000, None)]
#[case(Command::IO, 5, 0xf000, Some(0xf001))]
#[case(Command::empty(), 0, 0xffff_ffff, None)]
#[case(Command::MEM, 0, 0xd000_0000, Some(0xd000_0000))]
#[case(Command::MEM, 2, 0x9000_0000, Some(0x1_8000_0004))]
#[case(Command::MEM, 3, 0x0000_0002, Some(0x2_0000_0004))]
#[case(Command::MEM | Command::IO, 1, 0x1000, None)]
fn test_emulated_header_write_bar(
    #[case] command: Command,
    #[case] bar: usize,
    #[case] value: u32,
    #[case] dst: Option<u64>,
) {
    let header = fixture_emulated_header();
    header.set_command(command);
    let bdf = Bdf::new(0, 1, 0);
    header.set_bdf(bdf);

    let old_val = header
        .read(offset_bar(bar) as u64, size_of::<u32>() as u8)
        .unwrap();

    let got = header
        .write(offset_bar(bar) as u64, size_of::<u32>() as u8, value as u64)
        .unwrap();

    if let Action::ChangeLayout { callback } = got {
        let callback = <dyn Any>::downcast_ref::<MoveBarCallback>(&*callback).unwrap();
        assert_eq!(callback.dst, dst.unwrap());
        assert_eq!(callback.bdf, bdf);
        let new_val = header
            .read(offset_bar(bar) as u64, size_of::<u32>() as u8)
            .unwrap();
        assert_eq!(new_val, old_val);
    } else {
        assert_matches!(got, Action::None);
        assert_eq!(dst, None);
    }
}

#[rstest]
#[case(Status::empty(), Status::empty(), Status::empty())]
#[case(Status::PARITY_ERR, Status::PARITY_ERR, Status::empty())]
#[case(Status::PARITY_ERR, Status::empty(), Status::PARITY_ERR)]
#[case(Status::CAP | Status::PARITY_ERR, Status::PARITY_ERR, Status::CAP)]
fn test_emulated_header_write_status(
    #[case] old: Status,
    #[case] new: Status,
    #[case] expected: Status,
) {
    let header = fixture_emulated_header();
    {
        let mut hdr = header.data.write();
        match &mut hdr.header {
            ConfigHeader::Device(header) => header.common.status = old,
        }
    }

    header
        .write(
            CommonHeader::OFFSET_STATUS as u64,
            size_of::<Status>() as u8,
            new.bits() as u64,
        )
        .unwrap();

    let got = header
        .read(
            CommonHeader::OFFSET_STATUS as u64,
            size_of::<Status>() as u8,
        )
        .unwrap() as u16;

    assert_eq!(got, expected.bits())
}
