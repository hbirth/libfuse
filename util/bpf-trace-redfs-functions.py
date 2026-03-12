#!/usr/bin/env python3
"""
Trace FUSE functions and their latencies

Usage:
    bpf-trace-redfs-functions.py [-d DURATION] [-p PID] [-t THRESHOLD] [-v] [-s] [-f FUNCTIONS]

Examples:
    # Trace redfs functions (default) for 10 seconds
    ./bpf-trace-redfs-functions.py

    # Trace original fuse_ functions
    ./bpf-trace-redfs-functions.py --fuse

    # Trace with custom prefix
    ./bpf-trace-redfs-functions.py --prefix myfs_

    # Trace specific PID for 30 seconds
    ./bpf-trace-redfs-functions.py -p 1234 -d 30

    # Show only calls > 100us with verbose output
    ./bpf-trace-redfs-functions.py -t 100 -v

    # Trace only specific functions (use base names without prefix)
    ./bpf-trace-redfs-functions.py -f uring_commit,uring_commit_fetch

    # Show statistics and kernel stacks for slow calls
    ./bpf-trace-redfs-functions.py -s -K -t 50
"""

from bcc import BPF
from time import sleep, strftime, time
import argparse
import signal
import sys
import subprocess
import tempfile
import os

# Base function names (without _redfs or _fuse prefix)
BASE_FUNCTIONS = [
    'copy_args',
    'uring_copy_to_ring',
    'uring_copy_from_ring',
    'request_find',
    'request_end',
    'uring_cmd',
    'uring_queue_fuse_req',
    'fuse_uring_queue_bq_req',
]

# Parse command line arguments
def parse_args():
    parser = argparse.ArgumentParser(
        description="Trace FUSE/RedFSD uring function latencies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)

    # Prefix options (mutually exclusive)
    prefix_group = parser.add_mutually_exclusive_group()
    prefix_group.add_argument("--prefix", type=str, default="redfs_",
                             help="function prefix to use (default: redfs_)")
    prefix_group.add_argument("--fuse", action="store_true",
                             help="use fuse_ prefix (equivalent to --prefix fuse_)")
    prefix_group.add_argument("--redfs", action="store_true",
                             help="use redfs_ prefix (default)")

    # Tracing options
    parser.add_argument("-d", "--duration", type=int, default=10,
                        help="duration to trace in seconds (default: 10)")
    parser.add_argument("-p", "--pid", type=int, default=0,
                        help="trace this PID only (default: all)")
    parser.add_argument("-t", "--threshold", type=int, default=0,
                        help="only show calls slower than threshold (us, default: 0)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print each function call")
    parser.add_argument("-H", "--histogram", action="store_true", default=True,
                        help="show latency histogram per function (default: on)")
    parser.add_argument("--no-histogram", dest="histogram", action="store_false",
                        help="don't show histogram")
    parser.add_argument("-m", "--milliseconds", action="store_true",
                        help="use milliseconds instead of microseconds")
    parser.add_argument("-s", "--stats", action="store_true",
                        help="show min/max/avg statistics per function")
    parser.add_argument("-K", "--kernel-stack", action="store_true",
                        help="capture kernel stack traces for slow calls")
    parser.add_argument("-c", "--csv", action="store_true",
                        help="output in CSV format")
    parser.add_argument("-f", "--functions", type=str, default="",
                        help=f"comma-separated list of base function names to trace (default: all). "
                             f"Available: {', '.join(BASE_FUNCTIONS)}")
    parser.add_argument("-l", "--list-functions", action="store_true",
                        help="list available base functions and exit")

    # Backend selection
    parser.add_argument("--use-bcc", action="store_true",
                        help="use BCC instead of bpftrace (default is bpftrace)\n" \
                        "        BCC works for exported symbols but not for module-local symbols (marked as 't' in /proc/kallsyms).")

    return parser.parse_args()

def get_prefix(args):
    """Determine the function prefix to use"""
    if args.fuse:
        return "fuse_"
    elif args.redfs:
        return "redfs_"
    else:
        return args.prefix

# BPF program template
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_FUNC_NAME 48

struct data_t {
    u32 pid;
    u32 tid;
    u64 duration_us;
    u64 ts;
    char comm[TASK_COMM_LEN];
    char func[MAX_FUNC_NAME];
    int stack_id;
};

BPF_HASH(start, u64, u64);
BPF_HASH(func_name, u64, u32);
BPF_PERF_OUTPUT(events);
BPF_STACK_TRACE(stacks, 1024);

// Per-function histograms
HISTOGRAM_DECLARATIONS

static inline u64 get_key() {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    return pid_tgid;
}

// Generic entry probe
static __always_inline int trace_entry(struct pt_regs *ctx, u32 func_id) {
    u64 key = get_key();
    u64 ts = bpf_ktime_get_ns();

    FILTER_PID

    start.update(&key, &ts);
    func_name.update(&key, &func_id);
    return 0;
}

// Generic return probe
static __always_inline int trace_return(struct pt_regs *ctx, u32 func_id) {
    u64 key = get_key();
    u64 *tsp;

    tsp = start.lookup(&key);
    if (tsp == 0) {
        return 0;
    }

    u64 delta_ns = bpf_ktime_get_ns() - *tsp;
    u64 delta_us = delta_ns / 1000;

    FILTER_PID

    // Update per-function histogram
    STORE_HISTOGRAM

    // Check threshold and emit event if needed
    if (delta_us >= THRESHOLD) {
        struct data_t data = {};
        data.pid = bpf_get_current_pid_tgid() >> 32;
        data.tid = key;
        data.duration_us = delta_us;
        data.ts = bpf_ktime_get_ns();
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        // Copy function name
        COPY_FUNC_NAME

        STORE_STACK

        events.perf_submit(ctx, &data, sizeof(data));
    }

    start.delete(&key);
    func_name.delete(&key);
    return 0;
}

// Function-specific entry/return probes
FUNCTION_PROBES
"""

def generate_bpf_code(args, functions_to_trace):
    """Generate BPF code with selected functions"""
    bpf_code = bpf_text

    # Generate histogram declarations
    histogram_decls = []
    if args.histogram:
        for i, func in enumerate(functions_to_trace):
            histogram_decls.append(f"BPF_HISTOGRAM(dist_{i});")
    bpf_code = bpf_code.replace("HISTOGRAM_DECLARATIONS", "\n".join(histogram_decls))

    # Generate function-specific probes
    function_probes = []
    for i, func in enumerate(functions_to_trace):
        # Sanitize function name for BPF function names (replace special chars)
        safe_name = func.replace('-', '_').replace('.', '_')
        function_probes.append(f"""
int trace_{safe_name}_entry(struct pt_regs *ctx) {{
    return trace_entry(ctx, {i});
}}

int trace_{safe_name}_return(struct pt_regs *ctx) {{
    return trace_return(ctx, {i});
}}
""")
    bpf_code = bpf_code.replace("FUNCTION_PROBES", "\n".join(function_probes))

    # PID filter
    if args.pid > 0:
        pid_filter = f"u32 pid = bpf_get_current_pid_tgid() >> 32; if (pid != {args.pid}) {{ return 0; }}"
        bpf_code = bpf_code.replace("FILTER_PID", pid_filter)
    else:
        bpf_code = bpf_code.replace("FILTER_PID", "")

    # Threshold
    bpf_code = bpf_code.replace("THRESHOLD", str(args.threshold))

    # Histogram storage
    if args.histogram:
        histogram_store = []
        for i, func in enumerate(functions_to_trace):
            histogram_store.append(f"if (func_id == {i}) {{ dist_{i}.increment(bpf_log2l(delta_us)); }}")
        bpf_code = bpf_code.replace("STORE_HISTOGRAM", "\n    ".join(histogram_store))
    else:
        bpf_code = bpf_code.replace("STORE_HISTOGRAM", "")

    # Function name copy
    func_name_copy = []
    for i, func in enumerate(functions_to_trace):
        # Truncate if needed to fit in buffer
        func_str = func[:47]  # Leave room for null terminator
        func_name_copy.append(f'if (func_id == {i}) {{ __builtin_memcpy(&data.func, "{func_str}", sizeof("{func_str}")); }}')
    bpf_code = bpf_code.replace("COPY_FUNC_NAME", "\n        ".join(func_name_copy))

    # Stack trace
    if args.kernel_stack:
        bpf_code = bpf_code.replace("STORE_STACK",
                                    "data.stack_id = stacks.get_stackid(ctx, BPF_F_REUSE_STACKID);")
    else:
        bpf_code = bpf_code.replace("STORE_STACK", "data.stack_id = -1;")

    return bpf_code

def generate_bpftrace_script(functions, args):
    """Generate a bpftrace script for the given functions"""
    unit = "ms" if args.milliseconds else "us"
    # Convert nanoseconds to microseconds (1000) or milliseconds (1000000)
    divisor = 1000000 if args.milliseconds else 1000

    script = f"""#!/usr/bin/env bpftrace
/*
 * Auto-generated bpftrace script for tracing FUSE/RedFS functions
 * Generated by: {' '.join(sys.argv)}
 */

BEGIN
{{
    printf("Tracing {len(functions)} functions... Hit Ctrl-C to end.\\n");
"""

    if args.verbose:
        script += f"""    printf("%-12s %-35s %-8s %-8s %-16s %s\\n",
           "TIME", "FUNCTION", "PID", "TID", "COMM", "LATENCY({unit})");
"""

    script += "}\n\n"

    # Generate kprobe/kretprobe pairs for each function
    for func in functions:
        safe_name = func.replace('-', '_').replace('.', '_')

        # Entry probe
        script += f"""/* {func} */
kprobe:{func}
{{
    @start_{safe_name}[tid] = nsecs;
}}

"""

        # Return probe
        script += f"""kretprobe:{func}
/@start_{safe_name}[tid]/
{{
    $duration_ns = nsecs - @start_{safe_name}[tid];
    $duration = $duration_ns / {divisor};
"""

        # PID filter if specified
        if args.pid > 0:
            script += f"""
    if (pid != {args.pid}) {{
        delete(@start_{safe_name}[tid]);
        return;
    }}
"""

        # Threshold filter if specified
        if args.threshold > 0:
            script += f"""
    if ($duration < {args.threshold}) {{
        delete(@start_{safe_name}[tid]);
        return;
    }}
"""

        # Output raw sample for internal processing
        script += f"""
    printf("{func},%d\\n", $duration);
"""

        # Verbose output to stderr
        if args.verbose:
            script += f"""
    printf("%-12s %-35s %-8d %-8d %-16s %d\\n",
           strftime("%H:%M:%S", nsecs),
           "{func}",
           pid, tid, comm, $duration) > "/dev/stderr";
"""

        script += f"""
    delete(@start_{safe_name}[tid]);
}}

"""



    return script

def check_function_exists(func_name):
    """Check if a function exists in /proc/kallsyms"""
    try:
        with open('/proc/kallsyms', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    # Format: address type name [module]
                    symbol_name = parts[2]
                    # Check for exact match or CFI prefix match
                    if symbol_name == func_name or symbol_name == f"__pfx_{func_name}":
                        return True
        return False
    except Exception:
        # If we can't read kallsyms, assume function exists
        return True

def run_bpftrace(functions, args):
    """Generate and run a bpftrace script, processing output internally"""
    import time
    import threading
    from collections import defaultdict

    # Filter out functions that don't exist
    valid_functions = []
    for func in functions:
        if check_function_exists(func):
            valid_functions.append(func)
        else:
            print(f"Warning: Function '{func}' not found in /proc/kallsyms, skipping", file=sys.stderr)

    if not valid_functions:
        print("Error: No valid functions to trace", file=sys.stderr)
        return

    if len(valid_functions) < len(functions):
        print(f"Tracing {len(valid_functions)}/{len(functions)} functions\n", file=sys.stderr)

    script = generate_bpftrace_script(valid_functions, args)

    # Create temporary file for the script
    with tempfile.NamedTemporaryFile(mode='w', suffix='.bt', delete=False) as f:
        f.write(script)
        script_path = f.name

    try:
        # Run bpftrace
        cmd = ['bpftrace', script_path]

        print(f"Running bpftrace (script: {script_path})...")

        # Start bpftrace process - let stderr go to console for error messages
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None,
                                text=True, bufsize=1)

        print("Collecting samples... Press Ctrl-C to stop and see results.\n")

        # Collect samples
        samples_by_func = defaultdict(list)
        start_time = time.time()

        try:
            # Read samples from stdout
            for line in proc.stdout:
                line = line.strip()
                if ',' in line:
                    parts = line.split(',')
                    if len(parts) == 2:
                        func_name = parts[0].strip()
                        try:
                            latency = int(parts[1].strip())
                            samples_by_func[func_name].append(latency)
                        except ValueError:
                            pass

                # Check timeout
                if args.duration > 0 and (time.time() - start_time) >= args.duration:
                    break

        except KeyboardInterrupt:
            pass
        except Exception:
            pass
        finally:
            # Terminate bpftrace
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()

        # Print statistics and histograms
        unit = "ms" if args.milliseconds else "us"
        bucket_size = 10  # 10 microseconds or 10 milliseconds

        print("\n\n=== Latency Analysis ===\n")

        for func in valid_functions:
            samples = samples_by_func.get(func, [])
            if not samples:
                print(f"{func}: No samples collected")
                continue

            print(f"\n{func}:")
            print(f"  Count: {len(samples)}")
            print(f"  Min:   {min(samples)} {unit}")
            print(f"  Max:   {max(samples)} {unit}")
            print(f"  Avg:   {sum(samples) // len(samples)} {unit}")
            print(f"  Histogram ({bucket_size} {unit} buckets):")

            # Build histogram
            hist = {}
            for sample in samples:
                bucket = (sample // bucket_size) * bucket_size
                hist[bucket] = hist.get(bucket, 0) + 1

            # Print histogram
            if hist:
                max_count = max(hist.values())
                width = 50
                for bucket in sorted(hist.keys()):
                    count = hist[bucket]
                    bar_len = int((count / max_count) * width)
                    bar = '@' * bar_len
                    print(f"    [{bucket:6d}, {bucket + bucket_size:6d}) {unit:2s} {count:6d} |{bar}")

    finally:
        # Clean up temporary file
        try:
            os.unlink(script_path)
        except:
            pass

def main():
    args = parse_args()

    # List functions if requested
    if args.list_functions:
        print("Available base function names (use without prefix):")
        for func in BASE_FUNCTIONS:
            print(f"  - {func}")
        print(f"\nDefault prefix: redfs_")
        print(f"Use --fuse for fuse_ prefix or --prefix for custom prefix")
        sys.exit(0)

    # Determine prefix
    prefix = get_prefix(args)

    # Determine which functions to trace
    if args.functions:
        base_functions = [f.strip() for f in args.functions.split(',')]
        # Validate function names
        for func in base_functions:
            if func not in BASE_FUNCTIONS:
                print(f"Error: Unknown base function '{func}'", file=sys.stderr)
                print(f"Available base functions: {', '.join(BASE_FUNCTIONS)}", file=sys.stderr)
                sys.exit(1)
    else:
        base_functions = BASE_FUNCTIONS

    # Add prefix to create full function names
    # Special handling: replace 'fuse' in function names with the prefix name (without trailing _)
    prefix_name = prefix.rstrip('_')
    functions_to_trace = []
    for func in base_functions:
        # Replace 'fuse' with the actual prefix name (e.g., 'redfs', 'fuse')
        func_with_prefix = func.replace('fuse', prefix_name)
        full_name = prefix + func_with_prefix
        functions_to_trace.append(full_name)

    print(f"Using prefix: {prefix}")
    print(f"Tracing functions: {', '.join(functions_to_trace)}")

    # Use BCC if requested, otherwise use bpftrace (default)
    if args.use_bcc:
        print("Using backend: BCC")
    else:
        print("Using backend: bpftrace")
        run_bpftrace(functions_to_trace, args)
        return

    # Generate and load BPF program
    bpf_code = generate_bpf_code(args, functions_to_trace)

    try:
        b = BPF(text=bpf_code)

        # Attach probes for each function
        attached_count = 0
        for i, func in enumerate(functions_to_trace):
            safe_name = func.replace('-', '_').replace('.', '_')
            try:
                b.attach_kprobe(event=func, fn_name=f"trace_{safe_name}_entry")
                b.attach_kretprobe(event=func, fn_name=f"trace_{safe_name}_return")
                attached_count += 1
            except Exception as e:
                print(f"Warning: Could not attach to {func}: {e}", file=sys.stderr)
                print(f"Function may not exist in your kernel", file=sys.stderr)

        if attached_count == 0:
            print(f"\nError: Could not attach to any functions with prefix '{prefix}'", file=sys.stderr)
            print(f"Try using --fuse if you're tracing standard FUSE functions", file=sys.stderr)
            print(f"Or use --prefix to specify a different prefix", file=sys.stderr)
            sys.exit(1)

        print(f"Successfully attached to {attached_count}/{len(functions_to_trace)} functions\n")

    except Exception as e:
        print(f"Error loading BPF program: {e}", file=sys.stderr)
        sys.exit(1)

    # Statistics tracking per function
    stats = {}
    for func in functions_to_trace:
        stats[func] = {
            'count': 0,
            'total': 0,
            'min': float('inf'),
            'max': 0
        }

    # Print header
    unit = "ms" if args.milliseconds else "us"
    divisor = 1000 if args.milliseconds else 1

    if args.csv:
        print(f"timestamp,function,pid,tid,comm,duration_{unit}")
    elif args.verbose:
        print(f"Tracing functions... Ctrl-C to end")
        print(f"{'TIME':<12} {'FUNCTION':<35} {'PID':<8} {'TID':<8} {'COMM':<16} {'DURATION':<12}")
    else:
        filter_msg = f" (PID={args.pid})" if args.pid > 0 else ""
        threshold_msg = f" (threshold: >{args.threshold}{unit})" if args.threshold > 0 else ""
        print(f"Tracing functions{filter_msg}{threshold_msg}... Ctrl-C to end")

    # Event callback
    def print_event(cpu, data, size):
        event = b["events"].event(data)
        duration = event.duration_us / divisor
        func_name = event.func.decode('utf-8', 'replace').rstrip('\x00')

        # Update statistics
        if func_name in stats:
            stats[func_name]['count'] += 1
            stats[func_name]['total'] += duration
            stats[func_name]['min'] = min(stats[func_name]['min'], duration)
            stats[func_name]['max'] = max(stats[func_name]['max'], duration)

        if args.csv:
            print(f"{event.ts},{func_name},{event.pid},{event.tid},"
                  f"{event.comm.decode('utf-8', 'replace')},{duration:.2f}")
        elif args.verbose:
            print(f"{strftime('%H:%M:%S'):<12} {func_name:<35} {event.pid:<8} {event.tid:<8} "
                  f"{event.comm.decode('utf-8', 'replace'):<16} {duration:>10.2f} {unit}")

            # Print stack trace if available
            if args.kernel_stack and event.stack_id >= 0:
                stack = b["stacks"].walk(event.stack_id)
                for addr in stack:
                    sym = b.ksym(addr).decode('utf-8', 'replace')
                    print(f"    {sym}")
                print()

    b["events"].open_perf_buffer(print_event)

    # Handle Ctrl-C gracefully
    exiting = False
    def signal_handler(sig, frame):
        nonlocal exiting
        exiting = True

    signal.signal(signal.SIGINT, signal_handler)

    # Trace for specified duration
    start_time = time()
    end_time = start_time + args.duration

    while time() < end_time and not exiting:
        try:
            b.perf_buffer_poll(timeout=1000)
        except KeyboardInterrupt:
            break

    print()

    # Print statistics
    if args.stats:
        print(f"\nStatistics per function:")
        print(f"{'FUNCTION':<35} {'CALLS':<10} {'MIN':<12} {'MAX':<12} {'AVG':<12}")
        print("-" * 81)
        for func in functions_to_trace:
            if stats[func]['count'] > 0:
                avg = stats[func]['total'] / stats[func]['count']
                print(f"{func:<35} {stats[func]['count']:<10} "
                      f"{stats[func]['min']:>10.2f} {unit} "
                      f"{stats[func]['max']:>10.2f} {unit} "
                      f"{avg:>10.2f} {unit}")
            else:
                print(f"{func:<35} {'0':<10} {'-':<12} {'-':<12} {'-':<12}")

    # Print histograms
    if args.histogram:
        print(f"\nLatency distribution per function ({unit}):")
        for i, func in enumerate(functions_to_trace):
            if stats[func]['count'] > 0:
                print(f"\n{func}:")
                b[f"dist_{i}"].print_log2_hist(unit)

if __name__ == "__main__":
    main()
