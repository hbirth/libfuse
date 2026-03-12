#!/bin/bash
# FUSE/REDFS ftrace control script

# Default to redfs tracing
FS_TYPE="${FS_TYPE:-redfs}"

# Parse command line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--type)
            if [[ -z "$2" || "$2" == -* ]]; then
                echo "Error: -t/--type requires an argument (fuse or redfs)"
                exit 1
            fi
            if [[ "$2" != "fuse" && "$2" != "redfs" ]]; then
                echo "Error: Invalid filesystem type '$2'. Must be 'fuse' or 'redfs'"
                exit 1
            fi
            FS_TYPE="$2"
            shift 2
            ;;
        -h|--help)
            # Define usage inline to avoid forward reference
            cat << 'EOF'
Usage: redfs-ftrace.sh [-t|--type <fuse|redfs>] [command]

Options:
  -t, --type TYPE - Filesystem to trace: fuse or redfs (default: redfs)
  -h, --help      - Show this help message

Commands:
  start           - Start tracing
  stop            - Stop tracing
  show            - Show current trace buffer
  clear           - Clear trace buffer
  setup-func      - Setup function tracing
  setup-req       - Setup request tracing (default)
  undo-setup-func - Remove function tracing configuration
  undo-setup-req  - Remove request tracing configuration
  reset           - Reset all tracing settings
  status          - Show current trace configuration

Examples:
  redfs-ftrace.sh                        # Setup redfs request tracing (default)
  redfs-ftrace.sh setup-req              # Setup redfs request tracing
  redfs-ftrace.sh -t fuse setup-req      # Setup fuse request tracing
  redfs-ftrace.sh --type redfs show      # Show redfs trace results

Note: This script requires root privileges to access ftrace.
EOF
            exit 0
            ;;
        *)
            # Not an option, must be the command
            break
            ;;
    esac
done

COMMAND="${1:-setup-req}"

# Check for root privileges (after parsing help option)
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root"
    exit 1
fi

# Setup ftrace directories
if [[ -e /sys/kernel/tracing/trace ]]; then
    TR=/sys/kernel/tracing/
else
    TR=/sys/kernel/debug/tracing/
fi

# Helper functions
clear_trace() {
    echo > $TR/trace
}

enable_tracing() {
    if ! echo 1 > $TR/tracing_on; then
        echo "Error: Failed to enable tracing"
        exit 1
    fi
    echo "Tracing enabled for ${FS_TYPE}"
}

disable_tracing() {
    if ! echo 0 > $TR/tracing_on; then
        echo "Error: Failed to disable tracing"
        exit 1
    fi
    echo "Tracing disabled for ${FS_TYPE}"
}

reset_tracer() {
    echo nop > $TR/current_tracer
    echo > $TR/set_ftrace_filter
    echo > $TR/set_event
}

undo_setup_function() {
    disable_tracing
    # Remove function filters
    echo "!${FS_TYPE}:*" > $TR/set_ftrace_filter 2>/dev/null
    echo "!${FS_TYPE}_*" >> $TR/set_ftrace_filter 2>/dev/null
    echo nop > $TR/current_tracer
    echo "Function tracing configuration removed for ${FS_TYPE}"
}

undo_setup_request() {
    disable_tracing
    # Remove all request events
    echo "!${FS_TYPE}:${FS_TYPE}_request_enqueue" > $TR/set_event 2>/dev/null
    echo "!${FS_TYPE}:${FS_TYPE}_request_bg_enqueue" >> $TR/set_event 2>/dev/null
    echo "!${FS_TYPE}:${FS_TYPE}_request_send" >> $TR/set_event 2>/dev/null
    echo "!${FS_TYPE}:${FS_TYPE}_request_end" >> $TR/set_event 2>/dev/null
    echo "Request tracing configuration removed for ${FS_TYPE}"
}

setup_function_trace() {
    disable_tracing
    clear_trace
    reset_tracer

    # Set function tracer
    if ! grep -q "function" $TR/available_tracers; then
        echo "Error: function tracer not available"
        exit 1
    fi

    echo function > $TR/current_tracer
    echo "${FS_TYPE}:*" > $TR/set_ftrace_filter 2>/dev/null
    echo "${FS_TYPE}_*" >> $TR/set_ftrace_filter 2>/dev/null

    enable_tracing

    echo "Function tracing configured and enabled for ${FS_TYPE}"
}

setup_request_trace() {
    disable_tracing
    clear_trace
    reset_tracer

    # Verify events are available
    if ! grep -q "${FS_TYPE}:${FS_TYPE}_request" $TR/available_events; then
        echo "Error: ${FS_TYPE} tracepoints not available"
        exit 1
    fi

    # Enable all relevant request events
    if ! echo "${FS_TYPE}:${FS_TYPE}_request_enqueue" > $TR/set_event 2>/dev/null || \
       ! echo "${FS_TYPE}:${FS_TYPE}_request_bg_enqueue" >> $TR/set_event 2>/dev/null || \
       ! echo "${FS_TYPE}:${FS_TYPE}_request_send" >> $TR/set_event 2>/dev/null || \
       ! echo "${FS_TYPE}:${FS_TYPE}_request_end" >> $TR/set_event 2>/dev/null; then
        echo "Error: Failed to enable ${FS_TYPE} request events"
        exit 1
    fi

    # Verify events were actually enabled
    if ! grep -q "${FS_TYPE}:${FS_TYPE}_request" $TR/set_event; then
        echo "Error: Failed to verify ${FS_TYPE} events are enabled"
        exit 1
    fi

    enable_tracing

    echo "Request tracing configured and enabled for ${FS_TYPE}"
    echo "Active events:"
    cat $TR/set_event
    echo "Tracing status: $(cat $TR/tracing_on)"
}

usage() {
    echo "Usage: $0 [-t|--type <fuse|redfs>] [command]"
    echo ""
    echo "Options:"
    echo "  -t, --type TYPE - Filesystem to trace: fuse or redfs (default: redfs)"
    echo "  -h, --help      - Show this help message"
    echo ""
    echo "Commands:"
    echo "  start           - Start tracing"
    echo "  stop            - Stop tracing"
    echo "  show            - Show current trace buffer"
    echo "  clear           - Clear trace buffer"
    echo "  setup-func      - Setup function tracing"
    echo "  setup-req       - Setup request tracing (default)"
    echo "  undo-setup-func - Remove function tracing configuration"
    echo "  undo-setup-req  - Remove request tracing configuration"
    echo "  reset           - Reset all tracing settings"
    echo "  status          - Show current trace configuration"
    echo ""
    echo "Examples:"
    echo "  $0                        # Setup redfs request tracing (default)"
    echo "  $0 setup-req              # Setup redfs request tracing"
    echo "  $0 -t fuse setup-req      # Setup fuse request tracing"
    echo "  $0 --type redfs show      # Show redfs trace results"
    exit 1
}

show_status() {
    echo "=== Trace Configuration ==="
    echo "Current Tracer: $(cat $TR/current_tracer)"
    echo "Tracing Status: $(cat $TR/tracing_on)"
    echo
    echo "Active Function Filters:"
    cat $TR/set_ftrace_filter
    echo
    echo "Active Events:"
    cat $TR/set_event
}

case "$COMMAND" in
    "start")
        enable_tracing
        echo "Tracing started for ${FS_TYPE}"
        ;;
    "stop")
        disable_tracing
        echo "Tracing stopped for ${FS_TYPE}"
        ;;
    "show")
        echo "=== ${FS_TYPE} Trace Results ==="
        cat $TR/trace
        ;;
    "clear")
        clear_trace
        echo "Trace buffer cleared"
        ;;
    "setup-func")
        setup_function_trace
        ;;
    "setup-req")
        setup_request_trace
        ;;
    "undo-setup-func")
        undo_setup_function
        ;;
    "undo-setup-req")
        undo_setup_request
        ;;
    "reset")
        disable_tracing
        reset_tracer
        clear_trace
        echo "All tracing settings reset for ${FS_TYPE}"
        ;;
    "status")
        show_status
        ;;
    *)
        usage
        ;;
esac

