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

DefinitionBlock ("dsdt.aml", "DSDT", 2, "ALIOTH", "ALIOTHVM", 0x00000001)
{
    Device (_SB.COM1)
    {
        Name (_HID, EisaId ("PNP0501") )
        Name (_UID, One)
        Name (_STA, 0x0F)
        Name (_CRS, ResourceTemplate ()
        {
            IO (Decode16,
                0x03F8,
                0x03F8,
                0x00,
                0x08,
                )
            IRQNoFlags ()
                {4}
        })
    }

    Name (_S5, Package (0x01)
    {
        0x05
    })

    Device (_SB.PCI0)
    {
        Name (_HID, EisaId ("PNP0A08") )
        Name (_CID, EisaId ("PNP0A03") )
        Name (_SEG, Zero)
        Name (_UID, Zero)
        Method (_DSM, 4, NotSerialized)
        {
            // Arg0: UUID of function
            // Arg1: Revision
            // Arg2: function index

            // PCI Firmware Spec 3.1,
            // Sec. 4.6. _DSM Definitions for PCI
            If ((Arg0 == ToUUID ("e5c937d0-3553-4d7a-9117-ea4d19c3434d") ))
            {
                // Function 0, returns the function bit map
                // https://uefi.org/htmlspecs/ACPI_Spec_6_4_html/09_ACPI-Defined_Devices_and_Device-Specific_Objects/ACPIdefined_Devices_and_DeviceSpecificObjects.html#dsm-device-specific-method
                If ((Arg2 == Zero))
                {
                    Return (Buffer (One)
                    {
                        // 0b100001, supports function 0 and function 5
                         0x21
                    })
                }

                // PCI Firmware Spec 3.1,
                // Sec. 4.6.5 _DSM for Preserving PCI Boot Configurations
                If ((Arg2 == 0x05))
                {
                    // OS perserves reserouce assignment
                    Return (Zero)
                }
            }

            Return (Zero)
        }

        Name (_CRS, ResourceTemplate ()
        {
            WordBusNumber (ResourceProducer, MinFixed, MaxFixed, PosDecode,
                0x0000,
                0x0000,
                0x0000,
                0x0000,
                0x0001,
                ,, )
            IO (Decode16,
                0x0CF8,
                0x0CF8,
                0x01,
                0x08,
                )
            DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, Prefetchable, ReadWrite,
                0x00000000,
                0x80000000,
                0x9FFFFFFF,
                0x00000000,
                0x20000000,
                ,, , AddressRangeMemory, TypeStatic)
            DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, NonCacheable, ReadWrite,
                0x00000000,
                0xA0000000,
                0xBFFFFFFF,
                0x00000000,
                0x20000000,
                ,, , AddressRangeMemory, TypeStatic)
            QWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, Prefetchable, ReadWrite,
                0x0000000000000000,
                0x0000000100000000,
                0x00000100FFFFFFFF,
                0x0000000000000000,
                0x0000010000000000,
                ,, , AddressRangeMemory, TypeStatic)
            WordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode, EntireRange,
                0x0000,
                0x1000,
                0xFFFF,
                0x0000,
                0xF000,
                ,, , TypeStatic, DenseTranslation)
        })
    }
}

