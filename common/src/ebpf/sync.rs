#[derive(Debug)]
pub enum ProfilingType {
    Unknown = 1,
    FramePointers = 2,
    Python = 3,
    Error = 4,
}

#[derive(Debug)]
pub enum PidOp {
    RequestUnknownProcessInfo = 1,
    Dead = 2,
    RequestExecProcessInfo = 3,
}