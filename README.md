# IWM

A project to implement the [Grafana Pyroscope](https://github.com/grafana/pyroscope) eBPF Agent in Rust.

This project can collect profiling data instead Grafana Agent that using eBPF component only.

The project structure was referenced from the following repository:
- https://github.com/grafana/pyroscope
- https://github.com/grafana/alloy/tree/main

### Architecture

1. **Register target process**: Register the process to be profiled as the target based on the PID.

2. **Detect process execution event and determine**: type Insert eBPF code into the kprobe of the execve and execveat system calls to detect process execution events. Look up the process path to determine if it is a Python or FramePointer type, and store this information in an eBPF map.

3. **Collect stack information when instructions are executed on the CPU**: When the eBPF code is executed by the `PERF_COUNT_SW_CPU_CLOCK` event, execute the appropriate eBPF code based on whether it is a target process and its type. If it is a FramePointer type, collect stack information using bpf_get_stackid and store it in a count map.

4. **Interpret stack information and convert symbols**: Look up `/proc/{PID}/maps` to find the file path mapped to the executed instructions. Obtain the symbol (function name) corresponding to the instruction address from the ELF section of the file, and convert the instruction addresses in the stack information to the corresponding symbols.

5. **Convert data to pprof format and transmit**: Convert the stack information with symbols to the pprof format, and create a pprof message containing profile samples, locations, and function information. Send the generated pprof message to the Pyroscope server.

<img width="839" alt="image" src="https://github.com/rlaisqls/ebpf-monitoring/assets/81006587/5777b413-0b3f-42d4-a4f6-2daaaa4d4f4c">
