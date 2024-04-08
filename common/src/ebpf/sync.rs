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

#[derive(Debug)]
pub enum PidOp {
    RequestUnknownProcessInfo = 1,
    Dead = 2,
    RequestExecProcessInfo = 3,
}

impl PidOp {
    pub fn to_u8(&self) -> u8 {
        return match self {
            PidOp::RequestUnknownProcessInfo => { 1 }
            PidOp::Dead => { 2 }
            PidOp::RequestExecProcessInfo => { 3 }
        }
    }
}