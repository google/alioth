use std::ffi::{c_char, c_int, c_ulong, c_void};

#[repr(C)]
pub struct BlockDescriptor {
    pub reserved: c_ulong,
    pub size: c_ulong,
    pub copy_helper: Option<extern "C" fn(dst: *mut c_void, src: *const c_void)>,
    pub dispose_helper: Option<extern "C" fn(src: *mut c_void)>,
    // pub signature: *const c_char,
}

#[repr(C)]
pub struct BlockLiteral<F> {
    pub isa: *const c_void,
    pub flags: c_int,
    pub reserved: c_int,
    pub invoke: F,
    pub descriptor: *const BlockDescriptor,
}

unsafe extern "C" {
    pub static _NSConcreteGlobalBlock: *const c_void;
    pub static _NSConcreteStackBlock: *const c_void;
}
