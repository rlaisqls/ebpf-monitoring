use std::os::fd::RawFd;
use std::os::raw::c_int;

type ProgramType = u32;
type AttachType = u32;
type TypeID = u32;

pub struct Program {
    fd: *RawFd,
    name: String,
    pinned_path: String,
    typ: ProgramType
}

pub struct RawLink {
    fd: *RawFd,
    pinned_path: String
}

pub struct RawLinkOptions<'a> {
    pub(crate) target_fd: c_int,
    pub(crate) program: *Program,
    pub(crate) attach_type: AttachType,
    btf: TypeID,
    flags: u32,
}