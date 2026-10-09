// Copyright 2026 Google LLC
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
    Device (_SB.COM0)
    {
        Name (_HID, "ARMH0011")
        Name (_UID, Zero)
        Name (_STA, 0x0F)
        Name (_CRS, ResourceTemplate ()
        {
            Memory32Fixed (ReadWrite,
                0x2FFFF000,
                0x00001000,
                )
            Interrupt (ResourceConsumer, Edge, ActiveHigh, Exclusive, ,, )
            {
                0x00000021,
            }
        })
    }

    Device (_SB.PCI0)
    {
        Name (_HID, EisaId ("PNP0A08"))
        Name (_CID, EisaId ("PNP0A03"))
        Name (_SEG, Zero)
        Name (_UID, Zero)
        Name (_CCA, One)
        Method (_DSM, 4, NotSerialized)
        {
            // Arg0: UUID of function
            // Arg1: Revision
            // Arg2: function index

            // PCI Firmware Spec 3.1,
            // Sec. 4.6. _DSM Definitions for PCI
            If ((Arg0 == ToUUID ("e5c937d0-3553-4d7a-9117-ea4d19c3434d")))
            {
                // Function 0, returns the function bit map
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
                    // OS preserves resource assignment
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
            DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, Prefetchable, ReadWrite,
                0x00000000,
                0xC0000000,
                0xDFFFFFFF,
                0x00000000,
                0x20000000,
                ,, , AddressRangeMemory, TypeStatic)
            DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed, NonCacheable, ReadWrite,
                0x00000000,
                0xE0000000,
                0xFFFFFFFF,
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
            DWordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode, EntireRange,
                0x00000000,
                0x00000000,
                0x0000FFFF,
                0x0FFF0000,
                0x00010000,
                ,, , TypeTranslation, DenseTranslation)
        })

        Device (RES0)
        {
            Name (_HID, EisaId ("PNP0C02"))
            Name (_CRS, ResourceTemplate ()
            {
                Memory32Fixed (ReadWrite,
                    0x30000000,
                    0x10000000,
                    )
            })
        }
    }
}
