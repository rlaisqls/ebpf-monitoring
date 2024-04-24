#[derive(Debug)]
pub enum ProfilingType {
    Unknown,
    FramePointers,
    Python,
    TypeError,
}

impl ProfilingType {
    pub fn to_u8(&self) -> u8 {
        return match self {
            ProfilingType::Unknown => { 1 }
            ProfilingType::FramePointers => { 2 }
            ProfilingType::Python => { 3 }
            ProfilingType::TypeError => { 4 }
        }
    }
}

// #define OP_REQUEST_UNKNOWN_PROCESS_INFO 1
// #define OP_PID_DEAD 2
// #define OP_REQUEST_EXEC_PROCESS_INFO 3

#[derive(Debug)]
pub enum PidOp {
    RequestUnknownProcessInfo = 1,
    Dead = 2,
    RequestExecProcessInfo = 3,
}

impl PidOp {
    pub fn to_u32(&self) -> u32 {
        return match self {
            PidOp::RequestUnknownProcessInfo => { 1 }
            PidOp::Dead => { 2 }
            PidOp::RequestExecProcessInfo => { 3 }
        }
    }
}