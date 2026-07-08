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
use std::marker::PhantomData;

use assert_matches::assert_matches;
use serde::Deserialize;
use serde_bytes::{ByteArray, ByteBuf};

use crate::{Error, from_arg, from_args};

#[test]
fn test_option() {
    assert_matches!(from_arg::<Option<u32>>(""), Err(Error::ExpectedInteger));
    assert_eq!(from_arg::<Option<u32>>("12").unwrap(), Some(12));

    assert_eq!(from_arg::<Option<&'static str>>("").unwrap(), Some(""));
    assert_eq!(
        from_args::<Option<&'static str>>("id_1", &HashMap::from([("id_1", "")])).unwrap(),
        None
    );
    assert_eq!(from_arg::<Option<&'static str>>("12").unwrap(), Some("12"));
    assert_matches!(
        from_arg::<Option<&'static str>>("id_1"),
        Err(Error::IdNotFound(id)) if id == "id_1"
    );
    assert_eq!(
        from_args::<Option<&'static str>>("id_1", &HashMap::from([("id_1", "id_2")])).unwrap(),
        Some("id_2")
    );

    let map_none = HashMap::from([("id_none", "")]);
    assert_eq!(from_arg::<Vec<Option<u32>>>("").unwrap(), vec![]);
    assert_eq!(
        from_args::<Vec<Option<u32>>>("id_none,", &map_none).unwrap(),
        vec![None]
    );
    assert_eq!(from_arg::<Vec<Option<u32>>>("1,").unwrap(), vec![Some(1)]);
    assert_eq!(
        from_arg::<Vec<Option<u32>>>("1,2,").unwrap(),
        vec![Some(1), Some(2)]
    );
    assert_eq!(
        from_args::<Vec<Option<u32>>>("1,2,id_none,", &map_none).unwrap(),
        vec![Some(1), Some(2), None]
    );
    assert_eq!(
        from_args::<Vec<Option<u32>>>("id_none,2", &map_none).unwrap(),
        vec![None, Some(2)]
    );

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct SimpleStruct {
        val: u32,
        other: u32,
    }
    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct TestOptionStruct {
        opt: Option<SimpleStruct>,
    }
    assert_eq!(
        from_args::<TestOptionStruct>("opt=id_s", &[("id_s", "val=12,other=34")].into()).unwrap(),
        TestOptionStruct {
            opt: Some(SimpleStruct { val: 12, other: 34 })
        }
    );
}

#[test]
fn test_unit() {
    assert!(from_arg::<()>("").is_ok());
    assert_matches!(from_arg::<()>("unit"), Err(Error::ExpectedUnit));

    assert!(from_arg::<PhantomData<u8>>("").is_ok());
    assert_matches!(from_arg::<PhantomData<u8>>("12"), Err(Error::ExpectedUnit));

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Param {
        p: PhantomData<u8>,
    }
    assert_eq!(from_arg::<Param>("p=").unwrap(), Param { p: PhantomData });
    assert_matches!(from_arg::<Param>("p=1,"), Err(Error::ExpectedUnit));
}

#[test]
fn test_numbers() {
    assert_eq!(from_arg::<i8>("0").unwrap(), 0);
    assert_eq!(from_arg::<i8>("1").unwrap(), 1);
    assert_eq!(from_arg::<i8>("127").unwrap(), 127);
    assert_matches!(from_arg::<i8>("128"), Err(Error::Overflow));
    assert_eq!(from_arg::<i8>("-1").unwrap(), -1);
    assert_eq!(from_arg::<i8>("-128").unwrap(), -128);
    assert_matches!(from_arg::<i8>("-129"), Err(Error::Overflow));

    assert_eq!(from_arg::<i16>("1k").unwrap(), 1 << 10);

    assert_eq!(from_arg::<i32>("1g").unwrap(), 1 << 30);
    assert_matches!(from_arg::<i32>("2g"), Err(Error::Overflow));
    assert_matches!(from_arg::<i32>("0xffffffff"), Err(Error::Overflow));

    assert_eq!(from_arg::<i64>("0xffffffff").unwrap(), 0xffffffff);

    assert_matches!(from_arg::<i64>("gg"), Err(Error::ExpectedInteger));

    assert_matches!(from_arg::<f32>("0.125").unwrap(), 0.125);

    assert_matches!(from_arg::<f64>("-0.5").unwrap(), -0.5);
}

#[test]
fn test_char() {
    assert_eq!(from_arg::<char>("=").unwrap(), '=');
    assert_eq!(from_arg::<char>("a").unwrap(), 'a');
    assert_matches!(from_arg::<char>("an"), Err(Error::Message(_)));

    assert_eq!(
        from_args::<HashMap<char, char>>(
            "id_1=a,b=id_2,id_2=id_1",
            &HashMap::from([("id_1", ","), ("id_2", "="),])
        )
        .unwrap(),
        HashMap::from([(',', 'a'), ('b', '='), ('=', ',')])
    );
}

#[test]
fn test_bytes() {
    assert!(from_arg::<ByteArray<6>>("0xea,0xd7,0xa8,0xe8,0xc6,0x2f").is_ok());
    assert_matches!(
        from_arg::<ByteArray<5>>("0xea,0xd7,0xa8,0xe8,0xc6,0x2f"),
        Err(Error::Trailing(t)) if t == "0x2f"
    );
    assert_eq!(
        from_arg::<ByteBuf>("0xea,0xd7,0xa8,0xe8,0xc6,0x2f").unwrap(),
        vec![0xea, 0xd7, 0xa8, 0xe8, 0xc6, 0x2f]
    );

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    struct MacAddr {
        addr: ByteArray<6>,
    }
    assert_eq!(
        from_args::<MacAddr>(
            "addr=id_addr",
            &HashMap::from([("id_addr", "0xea,0xd7,0xa8,0xe8,0xc6,0x2f")])
        )
        .unwrap(),
        MacAddr {
            addr: ByteArray::new([0xea, 0xd7, 0xa8, 0xe8, 0xc6, 0x2f])
        }
    )
}

#[test]
fn test_string() {
    assert_eq!(
        from_arg::<String>("test,s=1,c").unwrap(),
        "test,s=1,c".to_owned()
    );
    assert_eq!(
        from_args::<HashMap<String, String>>(
            "cmd=id_1",
            &HashMap::from([("id_1", "console=ttyS0")])
        )
        .unwrap(),
        HashMap::from([("cmd".to_owned(), "console=ttyS0".to_owned())])
    )
}

#[test]
fn test_seq() {
    assert_eq!(from_arg::<Vec<u32>>("").unwrap(), vec![]);

    assert_eq!(from_arg::<Vec<u32>>("1").unwrap(), vec![1]);

    assert_eq!(from_arg::<Vec<u32>>("1,2,3,4").unwrap(), vec![1, 2, 3, 4]);

    assert_eq!(from_arg::<(u16, bool)>("12,true").unwrap(), (12, true));
    assert_matches!(
        from_arg::<(u16, bool)>("12,true,false"),
        Err(Error::Trailing(t)) if t == "false"
    );

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct TestStruct {
        a: (u16, bool),
    }
    assert_eq!(
        from_args::<TestStruct>("a=id_a", &HashMap::from([("id_a", "12,true")])).unwrap(),
        TestStruct { a: (12, true) }
    );
    assert_matches!(
        from_args::<TestStruct>("a=id_a", &HashMap::from([("id_a", "12,true,true")])),
        Err(Error::Trailing(t)) if t == "true"
    );

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Node {
        #[serde(default)]
        name: String,
        #[serde(default)]
        start: u64,
        size: u64,
    }
    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Numa {
        nodes: Vec<Node>,
    }

    assert_eq!(
        from_args::<Numa>(
            "nodes=id_nodes",
            &HashMap::from([
                ("id_nodes", "id_node1,id_node2"),
                ("id_node1", "name=a,start=0,size=2g"),
                ("id_node2", "name=b,start=4g,size=2g"),
            ])
        )
        .unwrap(),
        Numa {
            nodes: vec![
                Node {
                    name: "a".to_owned(),
                    start: 0,
                    size: 2 << 30
                },
                Node {
                    name: "b".to_owned(),
                    start: 4 << 30,
                    size: 2 << 30
                }
            ]
        }
    );

    assert_eq!(
        from_arg::<Numa>("nodes=size=2g,").unwrap(),
        Numa {
            nodes: vec![Node {
                name: "".to_owned(),
                start: 0,
                size: 2 << 30
            }]
        }
    );

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Info(bool, u32);

    assert_eq!(from_arg::<Info>("true,32").unwrap(), Info(true, 32));
}

#[test]
fn test_map() {
    #[derive(Debug, Deserialize, PartialEq, Eq, Hash)]
    struct MapKey {
        name: String,
        id: u32,
    }
    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct MapVal {
        addr: String,
        info: HashMap<String, String>,
    }

    assert_matches!(
        from_arg::<MapKey>("name=a,id=1,addr=b"),
        Err(Error::Ignored(k)) if k == "addr"
    );
    assert_matches!(
        from_arg::<MapKey>("name=a,addr=b,id=1"),
        Err(Error::Ignored(k)) if k == "addr"
    );
    assert_matches!(from_arg::<MapKey>("name=a,ids=b"), Err(Error::Ignored(k)) if k == "ids");
    assert_matches!(from_arg::<MapKey>("name=a,ids=b,id=1"), Err(Error::Ignored(k)) if k == "ids");

    assert_eq!(
        from_args::<HashMap<MapKey, MapVal>>(
            "id_key1=id_val1,id_key2=id_val2",
            &HashMap::from([
                ("id_key1", "name=gic,id=1"),
                ("id_key2", "name=pci,id=2"),
                ("id_val1", "addr=0xff,info=id_info1"),
                ("id_info1", "compatible=id_gic,msi-controller=,#msi-cells=1"),
                ("id_gic", "arm,gic-v3-its"),
                ("id_val2", "addr=0xcc,info=compatible=pci-host-ecam-generic"),
            ])
        )
        .unwrap(),
        HashMap::from([
            (
                MapKey {
                    name: "gic".to_owned(),
                    id: 1
                },
                MapVal {
                    addr: "0xff".to_owned(),
                    info: HashMap::from([
                        ("compatible".to_owned(), "arm,gic-v3-its".to_owned()),
                        ("msi-controller".to_owned(), "".to_owned()),
                        ("#msi-cells".to_owned(), "1".to_owned())
                    ])
                }
            ),
            (
                MapKey {
                    name: "pci".to_owned(),
                    id: 2
                },
                MapVal {
                    addr: "0xcc".to_owned(),
                    info: HashMap::from([(
                        "compatible".to_owned(),
                        "pci-host-ecam-generic".to_owned()
                    )])
                }
            )
        ])
    );
}

#[test]
fn test_nested_struct() {
    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Param {
        byte: u8,
        word: u16,
        dw: u32,
        long: u64,
        enable_1: bool,
        enable_2: bool,
        enable_3: Option<bool>,
        sub: SubParam,
        addr: Addr,
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct SubParam {
        b: u8,
        w: u16,
        enable: Option<bool>,
        s: String,
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Addr(u32);

    assert_eq!(
        from_args::<Param>(
            "byte=0b10,word=0o7k,dw=0x8m,long=10t,enable_1=on,enable_2=off,sub=id_1,addr=1g",
            &[("id_1", "b=1,w=2,s=s1,enable=on")].into()
        )
        .unwrap(),
        Param {
            byte: 0b10,
            word: 0o7 << 10,
            dw: 0x8 << 20,
            long: 10 << 40,
            enable_1: true,
            enable_2: false,
            enable_3: None,
            sub: SubParam {
                b: 1,
                w: 2,
                enable: Some(true),
                s: "s1".to_owned(),
            },
            addr: Addr(1 << 30)
        }
    );
    assert_matches!(
        from_arg::<SubParam>("b=1,w=2,enable,s=s1"),
        Err(Error::ExpectedMapEq)
    );
    assert_matches!(
        from_arg::<SubParam>("b=1,w=2,s=s1,enable"),
        Err(Error::ExpectedMapEq)
    );
}

#[test]
fn test_bool() {
    assert_matches!(from_arg::<bool>("on"), Ok(true));
    assert_matches!(from_arg::<bool>("off"), Ok(false));
    assert_matches!(from_arg::<bool>("true"), Ok(true));
    assert_matches!(from_arg::<bool>("false"), Ok(false));
    assert_matches!(from_arg::<bool>("on,off"), Err(Error::Trailing(t)) if t == "off");

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct BoolStruct {
        val: bool,
    }
    assert_eq!(
        from_arg::<BoolStruct>("val=on").unwrap(),
        BoolStruct { val: true }
    );
    assert_eq!(
        from_arg::<BoolStruct>("val=off").unwrap(),
        BoolStruct { val: false }
    );
    assert_eq!(
        from_arg::<BoolStruct>("val=true").unwrap(),
        BoolStruct { val: true }
    );
    assert_eq!(
        from_arg::<BoolStruct>("val=false").unwrap(),
        BoolStruct { val: false }
    );
    assert_matches!(from_arg::<BoolStruct>("val=a"), Err(Error::ExpectedBool));

    assert_matches!(
        from_arg::<BoolStruct>("val=on,key=off"),
        Err(Error::Ignored(k)) if k == "key"
    );
}

#[test]
fn test_enum() {
    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct SubStruct {
        a: u32,
        b: bool,
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    enum TestEnum {
        A {
            #[serde(default)]
            val: u32,
        },
        B(u64),
        C(u8, u8),
        D,
        #[serde(alias = "e")]
        E,
        F(SubStruct),
        G(u16, String, bool),
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct TestStruct {
        num: u32,
        e: TestEnum,
    }

    assert_eq!(
        from_args::<TestStruct>("num=3,e=id_a", &[("id_a", "A,val=1")].into()).unwrap(),
        TestStruct {
            num: 3,
            e: TestEnum::A { val: 1 }
        }
    );
    assert_eq!(
        from_arg::<TestStruct>("num=4,e=A").unwrap(),
        TestStruct {
            num: 4,
            e: TestEnum::A { val: 0 },
        }
    );
    assert_eq!(
        from_args::<TestStruct>("num=4,e=id_a", &[("id_a", "A")].into()).unwrap(),
        TestStruct {
            num: 4,
            e: TestEnum::A { val: 0 },
        }
    );
    assert_eq!(
        from_arg::<TestStruct>("num=4,e=D").unwrap(),
        TestStruct {
            num: 4,
            e: TestEnum::D,
        }
    );
    assert_eq!(
        from_args::<TestStruct>("num=4,e=id_d", &[("id_d", "D")].into()).unwrap(),
        TestStruct {
            num: 4,
            e: TestEnum::D,
        }
    );
    assert_eq!(
        from_arg::<TestStruct>("num=3,e=e").unwrap(),
        TestStruct {
            num: 3,
            e: TestEnum::E
        }
    );
    assert_matches!(
        from_arg::<TestStruct>("num=4,e=id_d"),
        Err(Error::IdNotFound(id)) if id == "id_d"
    );
    assert_matches!(
        from_args::<TestStruct>("num=4,e=id_d", &[].into()),
        Err(Error::IdNotFound(id)) if id == "id_d"
    );
    assert_eq!(from_arg::<TestEnum>("B,1").unwrap(), TestEnum::B(1));
    assert_eq!(from_arg::<TestEnum>("D").unwrap(), TestEnum::D);
    assert_eq!(
        from_arg::<TestEnum>("F,a=1,b=on").unwrap(),
        TestEnum::F(SubStruct { a: 1, b: true })
    );
    assert_eq!(
        from_arg::<TestEnum>("G,1,a,true").unwrap(),
        TestEnum::G(1, "a".to_owned(), true)
    );
    assert_matches!(
        from_arg::<TestEnum>("G,1,a,true,false"),
        Err(Error::Trailing(t)) if t == "false"
    );
    assert_matches!(
        from_args::<TestStruct>(
            "num=4,e=id_e",
            &HashMap::from([("id_e", "G,1,a,true,false")])
        ),
        Err(Error::Trailing(t)) if t == "false"
    );
}
