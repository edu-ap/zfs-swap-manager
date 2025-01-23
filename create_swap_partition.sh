#!/bin/bash

# Exit on any error and prevent undefined variables
set -euo pipefail
IFS=$'\n\t'

# Default values
DEFAULT_SIZE="28G"
SWAP_SIZE="${2:-$DEFAULT_SIZE}"  # Changed to $2 to accommodate flags
POOL_NAME="rpool"  # Default pool name, can be changed
SWAP_ZVOL="$POOL_NAME/swap"
DRY_RUN=false

# Additional monitoring variables
MONITOR_PID=""
NETHOGS_PID=""
TEST_MODE=false

# State tracking and logging setup
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
STATE_DIR="/var/tmp/swap_setup_${TIMESTAMP}"
LOG_DIR="$STATE_DIR/logs"
RESOURCE_LOG="$LOG_DIR/resources.log"
TRANSACTION_LOG="$LOG_DIR/transactions.log"
FSTAB_BACKUP="$STATE_DIR/fstab.backup"
LOCK_FILE="/var/tmp/swap_setup.lock"
declare -A EXECUTED_STEPS
CURRENT_STATE="INITIAL"  # Initialize current state

# State management and transitions
declare -A STATE_TRANSITIONS=(
    ["INITIAL"]="FSTAB_BACKUP"
    ["FSTAB_BACKUP"]="SERVICES_CHECKED"
    ["SERVICES_CHECKED"]="ZVOL_PREPARED"
    ["ZVOL_PREPARED"]="ZVOL_CREATED"
    ["ZVOL_CREATED"]="SWAP_ENABLED"
    ["SWAP_ENABLED"]="COMPLETED"
)

# Additional monitoring PIDs
STRACE_PID=""
PRESSURE_PID=""
PERF_PID=""
IOSTAT_PID=""
CONTEXT_PID=""

# Monitoring thresholds
MEMORY_PRESSURE_THRESHOLD=80
CONTEXT_SWITCH_THRESHOLD=10000
IO_LATENCY_THRESHOLD=100
SYSCALL_SLOW_THRESHOLD=0.1

# Monitoring directories
TRACE_DIR=""
PROFILE_DIR=""
ERROR_DIR=""

# Required tools for enhanced monitoring
required_tools+=(strace perf iostat vmstat lsof)

# Error handling and logging functions
error_exit() {
    local message="$1"
    log "ERROR: $message"
    cleanup
    exit 1
}

log() {
    local message="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $message"
    if [ -d "$LOG_DIR" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $message" >> "$LOG_DIR/setup.log"
    fi
}

log_transaction() {
    local action="$1"
    local details="$2"
    if [ -d "$LOG_DIR" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $action: $details" >> "$TRANSACTION_LOG"
    fi
}

# State validation function
validate_state_transition() {
    local current="$1"
    local next="$2"
    
    if [ "$DRY_RUN" = true ]; then
        return 0
    fi
    
    # Initial state can transition to any state
    if [ "$current" = "INITIAL" ]; then
        return 0
    fi
    
    # Check if transition is valid
    local valid_next="${STATE_TRANSITIONS[$current]}"
    if [ -z "$valid_next" ]; then
        error_exit "Invalid current state: $current"
    fi
    
    if [ "$valid_next" != "$next" ]; then
        error_exit "Invalid state transition: $current -> $next (expected $valid_next)"
    fi
}

# State management functions
save_state() {
    local new_state="$1"
    local details="$2"
    
    validate_state_transition "$CURRENT_STATE" "$new_state"
    
    # Atomic state file update
    echo "$details" > "${STATE_DIR}/${new_state}.state.tmp"
    sync "${STATE_DIR}/${new_state}.state.tmp"
    mv "${STATE_DIR}/${new_state}.state.tmp" "${STATE_DIR}/${new_state}.state"
    sync "${STATE_DIR}"
    
    CURRENT_STATE="$new_state"
    log "State transition: $CURRENT_STATE -> $new_state"
}

load_state() {
    local state="$1"
    if [ -f "$STATE_DIR/${state}.state" ]; then
        cat "$STATE_DIR/${state}.state"
    fi
}

rollback_to_state() {
    local target_state="$1"
    if [ "$DRY_RUN" = true ] || [ ! -d "$STATE_DIR" ]; then
        return 0
    fi
    
    log "Rolling back to state: $target_state"
    for state in $(ls -r "$STATE_DIR"/*.state 2>/dev/null); do
        local state_name=$(basename "$state" .state)
        if [ "$state_name" = "$target_state" ]; then
            break
        fi
        rollback_state "$state_name"
    done
}

rollback_state() {
    local state="$1"
    case "$state" in
        SWAP_ENABLED)
            swapoff -a || true
            ;;
        FSTAB_MODIFIED)
            if [ -f "$FSTAB_BACKUP" ]; then
                cp "$FSTAB_BACKUP" /etc/fstab
            fi
            ;;
        ZVOL_CREATED)
            local zvol=$(load_state ZVOL_CREATED)
            [ -n "$zvol" ] && zfs destroy "$zvol" || true
            ;;
    esac
    rm -f "$STATE_DIR/${state}.state"
}

# Lock management functions
acquire_lock() {
    local retries=0
    local max_retries=5
    
    while ! ln -s "/proc/$$/exe" "$LOCK_FILE" 2>/dev/null; do
        if [ -L "$LOCK_FILE" ]; then
            local old_pid=$(readlink "$LOCK_FILE" | cut -d/ -f3)
            if ! kill -0 "$old_pid" 2>/dev/null; then
                rm -f "$LOCK_FILE"
                continue
            fi
        fi
        
        retries=$((retries + 1))
        if [ $retries -ge $max_retries ]; then
            error_exit "Could not acquire lock after $max_retries attempts"
        fi
        sleep 1
    done
    
    # Register cleanup on script exit
    trap 'cleanup_lock' EXIT
}

cleanup_lock() {
    rm -f "$LOCK_FILE"
}

# Verification functions
verify_backup() {
    local backup_file="$1"
    if [ ! -f "$backup_file" ]; then
        error_exit "Backup file $backup_file not found"
    fi
    if ! diff "$backup_file" /etc/fstab >/dev/null; then
        local backup_sum=$(sha256sum "$backup_file" | cut -d' ' -f1)
        local current_sum=$(sha256sum /etc/fstab | cut -d' ' -f1)
        log "Backup verification:"
        log "- Backup checksum: $backup_sum"
        log "- Current checksum: $current_sum"
    fi
}

verify_swap_config() {
    if [ "$DRY_RUN" = true ]; then
        log "Would verify swap configuration"
        return 0
    fi
    
    log "Verifying swap configuration..."
    if ! grep -q "^UUID=$SWAP_UUID" /etc/fstab; then
        error_exit "Swap entry not found in fstab"
    fi
    
    if [ ! -e "$ZVOL_DEVICE" ]; then
        error_exit "Swap device not found"
    fi
}

# System health check function
check_system_health() {
    log "Checking system health..."
    
    # Get number of CPU cores and calculate threshold
    local cpu_cores=$(nproc)
    local load_threshold=$(echo "scale=1; $cpu_cores * 0.8" | bc)
    
    # Check system load
    local load=$(uptime | awk -F'load average:' '{ print $2 }' | cut -d, -f1)
    if [ "$(echo "$load > $load_threshold" | bc)" -eq 1 ]; then
        log "System load ($load) is above threshold ($load_threshold for $cpu_cores cores)"
        manage_system_load "$load"
    else
        log "System load ($load/$cpu_cores cores) is within acceptable range"
    fi
    
    # Check available memory
    local mem_available=$(free | awk '/^Mem:/ {print $7}')
    if [ "$mem_available" -lt 1048576 ]; then  # Less than 1GB
        prompt_continue "Low memory available (${mem_available}K)"
    fi
    
    # Check disk space
    local disk_free=$(df -k / | awk 'NR==2 {print $4}')
    if [ "$disk_free" -lt 1048576 ]; then  # Less than 1GB
        prompt_continue "Low disk space available (${disk_free}K)"
    fi
}

# Pool health check function
check_pool_health() {
    log "Checking ZFS pool health..."
    
    # Check if pool exists
    if ! zpool list "$POOL_NAME" >/dev/null 2>&1; then
        error_exit "Pool $POOL_NAME not found"
    fi
    
    # Check pool health
    local pool_health=$(zpool list -H -o health "$POOL_NAME")
    if [ "$pool_health" != "ONLINE" ]; then
        error_exit "Pool $POOL_NAME is not healthy (status: $pool_health)"
    fi
    
    # Check available space
    local available=$(zpool list -H -p -o free "$POOL_NAME")
    local required=$(($(echo "$SWAP_SIZE" | sed 's/[Gg]//' | bc) * 1024 * 1024 * 1024))
    if [ "$available" -lt "$required" ]; then
        error_exit "Insufficient space in pool $POOL_NAME"
    fi
}

# Execute function with dry run support
execute() {
    local cmd="$1"
    local description="$2"
    
    if [ "$DRY_RUN" = true ]; then
        log "Would execute: $description"
        log "Command: $cmd"
    else
        log "Executing: $description"
        eval "$cmd"
    fi
}

# Resource monitoring function
monitor_resources() {
    if [ "$DRY_RUN" = true ]; then
        log "Would start resource monitoring"
        return 0
    fi
    
    log "Starting resource monitoring..."
    
    # Ensure log directory exists
    if [ ! -d "$LOG_DIR" ]; then
        mkdir -p "$LOG_DIR" || error_exit "Failed to create log directory"
    fi
    
    # Create and set permissions for log files
    touch "$RESOURCE_LOG" || error_exit "Failed to create resource log"
    chmod 640 "$RESOURCE_LOG" || error_exit "Failed to set log permissions"
    
    # Start IO monitoring
    (while true; do
        iostat -x 1 2>/dev/null >> "$RESOURCE_LOG" || true
        sleep 5
    done) &
    MONITOR_PID=$!
    
    # Start memory monitoring
    (while true; do
        free -m >> "$RESOURCE_LOG" || true
        vmstat 1 2 >> "$RESOURCE_LOG" || true  # Added vmstat for better memory metrics
        sleep 5
    done) &
}

# Check disk health with improved device detection
check_disk_health() {
    log "Checking disk health..."
    
    # Get root device
    log "Getting root device path..."
    local root_device=$(df -P / | awk 'NR==2 {print $1}')
    log "Root device path: $root_device"
    
    # Get physical device with improved ZFS detection
    log "Extracting physical device path..."
    local device=$(echo "$root_device" | sed 's/[0-9]*$//')
    log "Physical device path: $device"
    
    # Enhanced ZFS pool device detection
    if echo "$device" | grep -q "^/dev/zd"; then
        log "Device appears to be a ZFS zvol, checking pool health instead"
        check_pool_health
        return 0
    fi
    
    if echo "$device" | grep -q "^rpool" || echo "$device" | grep -q "^zroot"; then
        log "Device is a ZFS pool, attempting to find physical devices..."
        local physical_devices=$(zpool status -P "$POOL_NAME" | awk '/\/dev\//{print $1}')
        if [ -n "$physical_devices" ]; then
            for physical_device in $physical_devices; do
                device="$physical_device"
                log "Found physical device: $device"
                check_device_smart "$device"
            done
            return 0
        else
            log "Could not find physical devices for ZFS pool, checking pool health instead"
            check_pool_health
            return 0
        fi
    fi
    
    check_device_smart "$device"
}

# Separate SMART check function
check_device_smart() {
    local device="$1"
    
    # Check if smartctl is available
    if ! command -v smartctl >/dev/null; then
        log "WARNING: smartctl not found, skipping disk health check"
        return 0
    fi
    
    log "Attempting SMART check on device: $device"
    if [ -e "$device" ]; then
        local smart_output
        smart_output=$(smartctl -H "$device" 2>&1)
        local smart_status=$?
        
        log "SMART command output:"
        log "$smart_output"
        log "SMART command exit status: $smart_status"
        
        # Enhanced SMART status checking
        if [ $smart_status -ne 0 ]; then
            log "WARNING: SMART check failed with status $smart_status"
            case $smart_status in
                1)
                    log "SMART error: Command line did not parse"
                    ;;
                2)
                    log "SMART error: Device could not be opened"
                    ;;
                3)
                    log "SMART error: Some SMART command failed"
                    ;;
                4)
                    log "SMART error: SMART status check returned failure"
                    ;;
                *)
                    log "SMART error: Unknown error occurred"
                    ;;
            esac
            prompt_continue "Continue despite disk health warning?"
        else
            # Check for specific SMART attributes
            local reallocated=$(smartctl -A "$device" | awk '/Reallocated_Sector_Ct/{print $10}')
            local pending=$(smartctl -A "$device" | awk '/Current_Pending_Sector/{print $10}')
            
            if [ "${reallocated:-0}" -gt 0 ] || [ "${pending:-0}" -gt 0 ]; then
                log "WARNING: Disk has reallocated or pending sectors"
                prompt_continue "Continue despite potential disk issues?"
            else
                log "SMART check passed successfully"
            fi
        fi
    else
        log "WARNING: Device $device does not exist"
        log "Available block devices:"
        lsblk -o NAME,TYPE,SIZE,MOUNTPOINT | while read line; do
            log "  $line"
        done
        return 0
    fi
}

# Enhanced system load check
check_system_load() {
    log "Checking system load..."
    
    # Get number of CPU cores and calculate threshold
    local cpu_cores=$(nproc)
    local load_threshold=$(echo "scale=1; $cpu_cores * 0.8" | bc)
    
    # Check system load with trend analysis
    local load_1min=$(uptime | awk -F'load average:' '{ print $2 }' | cut -d, -f1)
    local load_5min=$(uptime | awk -F'load average:' '{ print $2 }' | cut -d, -f2)
    local load_15min=$(uptime | awk -F'load average:' '{ print $2 }' | cut -d, -f3)
    
    log "Load averages: 1min: $load_1min, 5min: $load_5min, 15min: $load_15min"
    
    # Check if load is consistently high
    if [ "$(echo "$load_1min > $load_threshold" | bc)" -eq 1 ] && \
       [ "$(echo "$load_5min > $load_threshold" | bc)" -eq 1 ]; then
        log "WARNING: System load has been consistently high"
        log "System load ($load_1min) is above threshold ($load_threshold for $cpu_cores cores)"
        manage_system_load "$load_1min"
    elif [ "$(echo "$load_1min > $load_threshold" | bc)" -eq 1 ]; then
        log "WARNING: High system load might impact performance"
        log "System load ($load_1min/$cpu_cores cores) is above threshold"
        manage_system_load "$load_1min"
    else
        log "System load ($load_1min/$cpu_cores cores) is within acceptable range"
    fi
    
    # Check CPU frequency scaling
    if [ -d "/sys/devices/system/cpu/cpu0/cpufreq" ]; then
        local scaling_governor=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)
        if [ "$scaling_governor" = "powersave" ]; then
            log "WARNING: CPU is in power save mode, this might impact performance"
        fi
    fi
}

# Enhanced directory and file creation
create_directories() {
    log "Creating required directories..."
    
    # Create state directory with proper permissions
    if ! mkdir -p "$STATE_DIR"; then
        error_exit "Failed to create state directory: $STATE_DIR"
    fi
    chmod 750 "$STATE_DIR" || error_exit "Failed to set state directory permissions"
    
    # Create log directory with proper permissions
    if ! mkdir -p "$LOG_DIR"; then
        error_exit "Failed to create log directory: $LOG_DIR"
    fi
    chmod 750 "$LOG_DIR" || error_exit "Failed to set log directory permissions"
    
    # Create and initialize log files
    for logfile in "$LOG_DIR/setup.log" "$TRANSACTION_LOG" "$RESOURCE_LOG"; do
        touch "$logfile" || error_exit "Failed to create log file: $logfile"
        chmod 640 "$logfile" || error_exit "Failed to set log file permissions"
    done
    
    # Create recovery script directory if needed
    if [ ! -d "/var/tmp/swap_setup_base" ]; then
        mkdir -p "/var/tmp/swap_setup_base" || error_exit "Failed to create base directory"
        chmod 750 "/var/tmp/swap_setup_base" || error_exit "Failed to set base directory permissions"
    fi
}

# Define usage function first
usage() {
    cat << EOF
Usage: $0 [OPTIONS] [SIZE]
Create a ZFS-based swap volume with comprehensive safety checks and monitoring.

Options:
    -h, --help              Show this help message
    -d, --dry-run          Show what would be done without making any changes
    -p, --pool NAME        Specify ZFS pool name (default: rpool)
    -t, --test             Run in test mode with minimal impact
    
Size:
    Size of swap volume (default: ${DEFAULT_SIZE})
    Examples: 4G, 8G, 16G

Persistence Features:
    1. Systemd Integration
       - Automatic service creation and enablement
       - Early boot activation
       - Proper dependency management
       - Service status monitoring

    2. Device Management
       - Udev rules for persistent device naming
       - Proper device permissions
       - Automatic device detection
       - ZFS import cache configuration

    3. Boot Integration
       - Initramfs updates for ZFS modules
       - Proper ordering with system services
       - Fallback mechanisms
       - Boot-time validation

Validation Checks:
    1. Service Validation
       - Systemd service status
       - Service enablement state
       - Service dependencies
       - Configuration integrity

    2. Swap Configuration
       - Active swap devices
       - Swap priorities
       - Device paths
       - UUID consistency

    3. ZFS Properties
       - Mountpoint configuration
       - Compression settings
       - Cache settings
       - Sync mode and log bias
       - Snapshot settings

    4. Persistence Verification
       - FSTAB entries
       - Systemd unit files
       - Udev rules
       - ZFS cache
       - Boot configuration

Safety Features:
    1. System Health Monitoring
       - CPU load and temperature monitoring
       - Memory pressure detection and management
       - IO latency tracking
       - Network performance monitoring
       - Process priority management
       - NUMA topology awareness

    2. Resource Management
       - ZFS ARC size optimization
       - IO scheduler tuning
       - Kernel parameter optimization
       - Process and IO priority management
       - Resource limits control

    3. Security Features
       - SELinux/AppArmor context verification
       - Secure Boot detection
       - Process ancestry verification
       - Entropy availability monitoring
       - Mandatory Access Control checks

    4. Monitoring and Debugging
       - System call tracing
       - Performance profiling
       - Filesystem event monitoring
       - Detailed transaction logging
       - Resource usage tracking
       - Network resilience checks

    5. Backup and Recovery
       - Automatic ZFS snapshots
       - Emergency recovery script generation
       - Transaction rollback capabilities
       - State tracking and verification
       - Atomic operations with rollback

    6. Power Management
       - CPU frequency governor optimization
       - Battery status monitoring
       - Thermal throttling detection
       - Power state verification

Test Mode Features:
    - Minimal impact testing with small volumes (128M)
    - Comprehensive device verification
    - Operation simulation
    - Safety checks validation
    - Resource monitoring verification

Dry Run Features:
    - Operation simulation without changes
    - Detailed logging of would-be actions
    - Resource requirement estimation
    - Configuration validation
    - Safety check verification

Examples:
    $0 --dry-run 16G       # Show what would happen with 16GB swap
    $0 -p mypool 8G        # Create 8GB swap in 'mypool'
    $0 --test              # Run in test mode
    $0 -d -p tank 32G      # Dry run with custom pool

Monitoring and Logs:
    All operations are logged to the following locations:
    - Main log: /var/tmp/swap_setup_<timestamp>/logs/setup.log
    - Resource monitoring: /var/tmp/swap_setup_<timestamp>/logs/resources.log
    - Transaction log: /var/tmp/swap_setup_<timestamp>/logs/transactions.log
    - System calls: /var/tmp/swap_setup_<timestamp>/traces/syscalls.log
    - Performance data: /var/tmp/swap_setup_<timestamp>/profile/
    - Error reports: /var/tmp/swap_setup_<timestamp>/errors/

Recovery:
    In case of failure:
    1. Emergency recovery script is created at /tmp/emergency_recovery_<timestamp>.sh
    2. Original system state is preserved in ZFS snapshots
    3. All operations are logged and can be rolled back
    4. Backups of critical files are maintained
    5. Transaction log provides detailed operation history

Requirements:
    - ZFS utilities (zfsutils-linux)
    - System monitoring tools (sysstat, lm-sensors)
    - Performance tools (linux-tools-common)
    - Security tools (apparmor-utils or selinux-utils)
    - Network monitoring (nethogs, iperf3)
    - Debug tools (strace, lsof)
    - Resource monitoring (numactl, bc)

Note:
    The script requires root privileges and will automatically check for all
    required tools and optimal system conditions before proceeding.
    For production systems, it's recommended to run with --dry-run first.
EOF
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -d|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -t|--test)
            TEST_MODE=true
            shift
            ;;
        -p|--pool)
            POOL_NAME="$2"
            SWAP_ZVOL="$POOL_NAME/swap"
            shift 2
            ;;
        *)
            if [[ $1 =~ ^[0-9]+[GgMm]$ ]]; then
                SWAP_SIZE="$1"
                shift
            else
                echo "Error: Unknown argument: $1"
                usage
                exit 1
            fi
            ;;
    esac
done

# Function to prompt for continuation
prompt_continue() {
    local message="$1"
    if [ "$DRY_RUN" = false ]; then
        log "WARNING: $message"
        read -p "Continue? (y/n) " -n 1 -r
        echo
        [[ $REPLY =~ ^[Yy]$ ]] || error_exit "Operation cancelled by user"
    else
        log "Would prompt: $message"
    fi
}

# Pre-flight validation
validate_environment() {
    log "Validating environment..."
    
    # Check for required tools
    local required_tools=(zfs zpool mkswap swapon swapoff blkid sha256sum iostat)
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null; then
            error_exit "Required tool '$tool' not found"
        fi
    done
    
    # Check for pending system updates
    if [ -f /var/run/reboot-required ]; then
        error_exit "System requires a reboot before proceeding"
    fi
    
    # Check disk health
    check_disk_health
    
    log "Environment validation completed"
}

# Performance impact monitoring
monitor_performance_impact() {
    log "Starting performance monitoring..."
    local pid=$$
    (
        while true; do
            local io_stats=$(iostat -x 1 1)
            local mem_stats=$(free -m)
            local load_avg=$(uptime)
            echo "$(date): IO=$io_stats MEM=$mem_stats LOAD=$load_avg" >> "$RESOURCE_LOG"
            if echo "$io_stats" | awk '$NF > 90'; then
                log "WARNING: High IO utilization detected"
            fi
            sleep 5
        done
    ) &
    MONITOR_PID=$!
    trap "kill $MONITOR_PID 2>/dev/null || true" EXIT
}

# Emergency recovery mode
emergency_recovery() {
    log "EMERGENCY RECOVERY MODE ACTIVATED"
    
    # Create emergency recovery script
    cat > "/tmp/emergency_recovery_${TIMESTAMP}.sh" <<EOF
#!/bin/bash
set -euo pipefail

# Disable all swap
swapoff -a || true

# Restore original fstab
if [ -f "$FSTAB_BACKUP" ]; then
    cp "$FSTAB_BACKUP" /etc/fstab
fi

# Remove ZFS volume
zfs destroy "$SWAP_ZVOL" || true

# Clean up state directory
rm -rf "$STATE_DIR"

# Report status
echo "Emergency recovery completed at $(date)"
EOF
    chmod +x "/tmp/emergency_recovery_${TIMESTAMP}.sh"
    
    log "Emergency recovery script created at /tmp/emergency_recovery_${TIMESTAMP}.sh"
}

# Snapshot management
manage_snapshots() {
    local action="$1"
    if [ "$DRY_RUN" = true ]; then
        log "Would $action snapshot"
        return 0
    fi
    
    case "$action" in
        create)
            log "Creating ZFS snapshot..."
            zfs snapshot "$POOL_NAME@swap_setup_${TIMESTAMP}"
            # Removed state saving here
            ;;
        rollback)
            log "Rolling back to snapshot..."
            if zfs list -t snapshot | grep -q "swap_setup_${TIMESTAMP}"; then
                zfs rollback "$POOL_NAME@swap_setup_${TIMESTAMP}"
            fi
            ;;
        cleanup)
            log "Cleaning up snapshot..."
            if zfs list -t snapshot | grep -q "swap_setup_${TIMESTAMP}"; then
                zfs destroy "$POOL_NAME@swap_setup_${TIMESTAMP}"
            fi
            ;;
    esac
}

# Function to manage high system load
manage_system_load() {
    local load="$1"
    local cpu_cores=$(nproc)
    local threshold=$(echo "scale=1; $cpu_cores * 0.8" | bc)
    
    log "System load is high ($load/$cpu_cores cores). Available actions:"
    log "Current threshold: $threshold (80% of total CPU capacity)"
    
    cat << EOF
1. Continue anyway
2. Identify and kill highest CPU consuming processes
3. Reduce IO priority of running processes
4. Wait for load to decrease
5. Adjust threshold (current: ${threshold})
6. Abort operation
EOF
    
    read -p "Select action (1-6): " choice
    case $choice in
        1)
            log "Continuing despite high load"
            ;;
        2)
            log "Top CPU consuming processes:"
            ps aux --sort=-%cpu | head -6
            read -p "Enter PID to kill (or 'n' to cancel): " pid
            if [[ "$pid" =~ ^[0-9]+$ ]]; then
                log "Killing process $pid"
                kill -15 "$pid" || kill -9 "$pid"
                sleep 2
                check_system_health
            fi
            ;;
        3)
            log "Reducing IO priority of high IO processes..."
            for pid in $(ionice -p 1 2>/dev/null; ps -eo pid,class | grep "1" | awk '{print $1}'); do
                ionice -c 3 -p "$pid" 2>/dev/null || true
            done
            log "IO priorities adjusted"
            sleep 2
            check_system_health
            ;;
        4)
            log "Waiting for load to decrease below ${threshold}..."
            while [ "$(echo "$(uptime | awk -F'load average:' '{ print $2 }' | cut -d, -f1) > $threshold" | bc)" -eq 1 ]; do
                local current_load=$(uptime | awk -F'load average:' '{ print $2 }' | cut -d, -f1)
                log "Current load: $current_load/$cpu_cores cores"
                sleep 5
            done
            log "Load has decreased, continuing..."
            ;;
        5)
            read -p "Enter new threshold (as percentage of CPU cores, 1-100): " new_threshold
            if [[ "$new_threshold" =~ ^[0-9]+$ ]] && [ "$new_threshold" -ge 1 ] && [ "$new_threshold" -le 100 ]; then
                threshold=$(echo "scale=1; $cpu_cores * $new_threshold / 100" | bc)
                log "New threshold set to $threshold ($new_threshold% of $cpu_cores cores)"
                check_system_health
            else
                log "Invalid threshold value"
            fi
            ;;
        6)
            error_exit "Operation cancelled due to high system load"
            ;;
        *)
            error_exit "Invalid choice"
            ;;
    esac
}

# Function to manage critical services
manage_critical_service() {
    local service="$1"
    log "Critical service '$service' is running. Available actions:"
    
    cat << EOF
1. Continue anyway
2. Stop the service temporarily
3. Restart service with lower priority
4. Abort operation
EOF
    
    read -p "Select action (1-4): " choice
    case $choice in
        1)
            log "Continuing with service $service running"
            return 1
            ;;
        2)
            log "Service $service will be stopped"
            return 0
            ;;
        3)
            log "Restarting $service with lower priority..."
            systemctl stop "$service"
            sleep 2
            nice -n 19 systemctl start "$service"
            log "Service restarted with lower priority"
            return 1
            ;;
        4)
            error_exit "Operation cancelled due to running service $service"
            ;;
        *)
            error_exit "Invalid choice"
            ;;
    esac
}

# System impact assessment
assess_system_impact() {
    log "Assessing system impact..."
    
    # Check if running in production hours
    local hour=$(date +%H)
    if [ "$hour" -ge 9 ] && [ "$hour" -le 17 ]; then
        prompt_continue "Running during production hours. Continue?"
    fi
    
    # Check system load
    local load=$(uptime | awk -F'load average:' '{ print $2 }' | cut -d, -f1)
    if [ "$(echo "$load > 2.0" | bc)" -eq 1 ]; then
        manage_system_load "$load"
    fi
    
    # Check for critical services
    local services_to_stop=()
    local critical_services=(mysql apache2 nginx docker postgresql mongodb redis-server)
    for service in "${critical_services[@]}"; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            if manage_critical_service "$service"; then
                services_to_stop+=("$service")
            fi
        fi
    done
    
    # Stop all selected services at once
    if [ ${#services_to_stop[@]} -gt 0 ]; then
        log "Stopping selected services..."
        mkdir -p "$STATE_DIR"
        for service in "${services_to_stop[@]}"; do
            log "Stopping service $service..."
            systemctl stop "$service"
            echo "$service" >> "$STATE_DIR/services_to_restart"
        done
    fi
    
    # Always mark services as checked
    save_state "SERVICES_CHECKED" "${services_to_stop[*]:-no_services_stopped}"
    
    # Check memory availability
    local mem_available=$(free -m | awk '/^Mem:/ {print $7}')
    if [ "$mem_available" -lt 1024 ]; then
        error_exit "Insufficient memory available (< 1GB)"
    fi
    
    log "System impact assessment completed"
}

# Network impact monitoring
monitor_network_impact() {
    if command -v nethogs >/dev/null; then
        nethogs -t >> "$RESOURCE_LOG" &
        NETHOGS_PID=$!
        trap "kill $NETHOGS_PID 2>/dev/null || true" EXIT
    fi
}

# Configuration validation
validate_configuration() {
    log "Validating configuration..."
    
    # Validate swap size against system RAM
    local total_ram=$(free -g | awk '/^Mem:/ {print $2}')
    local swap_size_gb=$(echo "$SWAP_SIZE" | sed 's/[Gg]//')
    
    if [ "$swap_size_gb" -gt $((total_ram * 2)) ]; then
        prompt_continue "Swap size > 2x RAM. This might impact performance. Continue?"
    fi
    
    # Validate ZFS dataset properties
    local dataset_props=$(zfs get all "$POOL_NAME")
    if echo "$dataset_props" | grep -q "compression=on"; then
        prompt_continue "ZFS compression is enabled. This might impact swap performance. Continue?"
    fi
    
    log "Configuration validation completed"
}

# Test mode
test_mode() {
    log "Running in test mode..."
    
    # Create small test volume
    local TEST_SIZE="128M"  # Reduced size for testing
    local TEST_ZVOL="${SWAP_ZVOL}_test"
    local success=true
    
    transaction_begin "TEST_MODE"
    
    if [ "$DRY_RUN" = false ]; then
        {
            log "Phase 1: Testing ZFS operations"
            # Check if test volume exists and remove it
            if zfs list "$TEST_ZVOL" >/dev/null 2>&1; then
                log "Removing existing test volume..."
                if grep -q "$TEST_ZVOL" /proc/swaps; then
                    swapoff "/dev/zvol/$TEST_ZVOL" 2>/dev/null || true
                fi
                zfs destroy "$TEST_ZVOL" || { 
                    log "Failed to remove existing test volume"
                    return 1
                }
                sleep 2  # Give ZFS time to clean up
            fi
            
            # Create new test volume
            zfs create -V "$TEST_SIZE" "$TEST_ZVOL" || { 
                success=false
                log "Failed to create test volume"
                return 1
            }
            
            if [ "$success" = true ]; then
                log "Phase 2: Testing device creation"
                local test_device="/dev/zvol/$TEST_ZVOL"
                for i in {1..10}; do
                    if [ -e "$test_device" ]; then
                        break
                    fi
                    sleep 1
                    if [ $i -eq 10 ]; then
                        success=false
                        log "Failed: Device creation timed out"
                        return 1
                    fi
                done
            fi
            
            if [ "$success" = true ]; then
                log "Phase 3: Testing swap operations"
                if ! mkswap "$test_device"; then
                    success=false
                    log "Failed: mkswap operation"
                    return 1
                fi
                
                if [ "$success" = true ]; then
                    if ! swapon "$test_device"; then
                        success=false
                        log "Failed: swapon operation"
                        return 1
                    else
                        swapoff "$test_device"
                    fi
                fi
            fi
            
            # Cleanup test volume
            log "Cleaning up test volume..."
            swapoff "/dev/zvol/$TEST_ZVOL" 2>/dev/null || true
            zfs destroy "$TEST_ZVOL" || log "Warning: Failed to clean up test volume"
            
        } || success=false
        
        if [ "$success" = true ]; then
            log "All tests completed successfully"
            transaction_commit "TEST_MODE"
            return 0
        else
            log "Some tests failed - check logs for details"
            transaction_rollback "TEST_MODE"
            return 1
        fi
    else
        log "Would perform test operations:"
        log "- Create test volume: $TEST_ZVOL ($TEST_SIZE)"
        log "- Test device creation"
        log "- Test swap operations"
        log "- Clean up test volume"
        transaction_commit "TEST_MODE"
        return 0
    fi
}

# Additional system checks and optimizations
check_memory_fragmentation() {
    log "Checking memory fragmentation..."
    if [ -f "/proc/buddyinfo" ]; then
        local fragmentation=$(cat /proc/buddyinfo | awk '{sum += $14} END {print sum}')
        if [ "$fragmentation" -lt 100 ]; then
            log "WARNING: High memory fragmentation detected"
            log "Consider running 'echo 1 > /proc/sys/vm/compact_memory' before proceeding"
            prompt_continue "Continue despite memory fragmentation?"
        fi
    else
        log "Unable to check memory fragmentation - /proc/buddyinfo not available"
    fi
}

manage_zfs_arc() {
    log "Checking ZFS ARC size..."
    if [ -f "/sys/module/zfs/parameters/zfs_arc_max" ]; then
        local arc_max=$(cat /sys/module/zfs/parameters/zfs_arc_max)
        local mem_total=$(free -b | awk '/^Mem:/{print $2}')
        
        if [ "$arc_max" -gt "$((mem_total / 4))" ]; then
            log "WARNING: ZFS ARC might be using too much memory"
            prompt_continue "Would you like to temporarily reduce ARC size?"
            if [ "$DRY_RUN" = false ]; then
                echo "$((mem_total / 4))" > /sys/module/zfs/parameters/zfs_arc_max
                save_state "ARC_MODIFIED" "$arc_max"
            else
                log "Would set ZFS ARC max to $((mem_total / 4)) bytes"
            fi
        fi
    else
        log "ZFS ARC parameters not available"
    fi
}

optimize_io_scheduler() {
    log "Optimizing IO scheduler..."
    local device_path=$(df -P / | awk 'NR==2 {print $1}' | sed 's/[0-9]*$//')
    local scheduler_file="/sys/block/${device_path##*/}/queue/scheduler"
    
    if [ -f "$scheduler_file" ]; then
        local original_scheduler=$(cat "$scheduler_file" | grep -o '\[.*\]' | tr -d '[]')
        if [ "$DRY_RUN" = false ]; then
            echo "deadline" > "$scheduler_file"
            save_state "SCHEDULER_MODIFIED" "$original_scheduler"
            log "Set IO scheduler to deadline for better swap performance"
        else
            log "Would set IO scheduler from $original_scheduler to deadline"
        fi
    else
        log "IO scheduler configuration not available"
    fi
}

tune_kernel_parameters() {
    log "Tuning kernel parameters for swap..."
    local params=(
        "vm.swappiness=10"
        "vm.vfs_cache_pressure=50"
        "vm.page-cluster=0"
    )
    
    if [ "$DRY_RUN" = false ]; then
        # Save current values
        local current_values=""
        for param in "${params[@]}"; do
            local key="${param%=*}"
            local current=$(sysctl -n "$key")
            current_values+="$key=$current;"
        done
        save_state "SYSCTL_MODIFIED" "$current_values"
        
        # Set new values
        for param in "${params[@]}"; do
            sysctl -w "$param" || log "Failed to set $param"
        done
    else
        log "Would set kernel parameters:"
        printf '%s\n' "${params[@]}" | sed 's/^/  /'
    fi
}

check_network_performance() {
    log "Checking network performance..."
    if command -v iperf3 >/dev/null; then
        if [ "$DRY_RUN" = false ]; then
            # Start iperf3 server in background
            iperf3 -s -D >/dev/null 2>&1
            sleep 1
            
            # Run test
            local net_load=$(iperf3 -c localhost -t 1 -J 2>/dev/null | jq '.end.sum_received.bits_per_second' 2>/dev/null)
            
            # Kill iperf3 server
            pkill -f "iperf3 -s" >/dev/null 2>&1
            
            if [ -n "$net_load" ] && [ "$net_load" -lt 1000000000 ]; then  # Less than 1Gbps
                log "WARNING: Network performance might be degraded"
                prompt_continue "Continue with potentially degraded network performance?"
            fi
        else
            log "Would check network performance using iperf3"
        fi
    else
        log "iperf3 not available - skipping network performance check"
    fi
}

monitor_temperature() {
    if command -v sensors >/dev/null; then
        log "Monitoring system temperature..."
        if [ "$DRY_RUN" = false ]; then
            local temp=$(sensors | awk '/^Core 0/ {print $3}' | tr -d '+°C')
            if [ -n "$temp" ] && [ "$(echo "$temp > 80" | bc)" -eq 1 ]; then
                log "WARNING: High CPU temperature detected: ${temp}°C"
                prompt_continue "Continue despite high temperature?"
            fi
        else
            log "Would monitor CPU temperature using lm-sensors"
        fi
    else
        log "lm-sensors not available - skipping temperature monitoring"
    fi
}

check_numa_topology() {
    if [ -d "/sys/devices/system/node/node1" ]; then
        log "NUMA system detected, checking memory distribution..."
        if command -v numastat >/dev/null; then
            if [ "$DRY_RUN" = false ]; then
                local numa_balance=$(numastat -m | awk '/Numa_Hit/ {print $2/$3}')
                if [ -n "$numa_balance" ] && [ "$(echo "$numa_balance < 0.8" | bc)" -eq 1 ]; then
                    log "WARNING: Unbalanced NUMA memory distribution"
                    prompt_continue "Consider enabling automatic NUMA balancing?"
                    if [[ $REPLY =~ ^[Yy]$ ]]; then
                        echo 1 > /proc/sys/kernel/numa_balancing
                        save_state "NUMA_MODIFIED" "enabled"
                    fi
                fi
            else
                log "Would check NUMA memory distribution"
            fi
        else
            log "numastat not available - skipping NUMA check"
        fi
    else
        log "Non-NUMA system detected"
    fi
}

enhance_emergency_recovery() {
    if [ "$DRY_RUN" = false ]; then
        # Add to emergency recovery script
        cat >> "/tmp/emergency_recovery_${TIMESTAMP}.sh" <<EOF

# Restore kernel parameters
echo "Restoring kernel parameters..."
if [ -f "$STATE_DIR/SYSCTL_MODIFIED.state" ]; then
    while IFS=';' read -r param; do
        [ -n "\$param" ] && sysctl -w "\$param"
    done < "$STATE_DIR/SYSCTL_MODIFIED.state"
fi

# Restore ZFS ARC size
if [ -f "$STATE_DIR/ARC_MODIFIED.state" ]; then
    echo "Restoring ZFS ARC size..."
    arc_size=\$(cat "$STATE_DIR/ARC_MODIFIED.state")
    echo "\$arc_size" > /sys/module/zfs/parameters/zfs_arc_max
fi

# Restore IO scheduler
if [ -f "$STATE_DIR/SCHEDULER_MODIFIED.state" ]; then
    echo "Restoring IO scheduler..."
    device_path=\$(df -P / | awk 'NR==2 {print \$1}' | sed 's/[0-9]*\$//')
    original_scheduler=\$(cat "$STATE_DIR/SCHEDULER_MODIFIED.state")
    echo "\$original_scheduler" > "/sys/block/\${device_path##*/}/queue/scheduler"
fi

# Restore NUMA settings
if [ -f "$STATE_DIR/NUMA_MODIFIED.state" ]; then
    echo "Restoring NUMA settings..."
    echo 0 > /proc/sys/kernel/numa_balancing
fi

# Clean up any remaining lock files
rm -f /var/tmp/swap_setup.lock*

# Verify system state
echo "Verifying system state..."
free -h
zpool status
EOF
    else
        log "Would enhance emergency recovery script with additional restore operations"
    fi
}

# Enhanced cleanup function
cleanup() {
    log "Starting cleanup..."
    
    if [ "$DRY_RUN" = true ]; then
        log "Would perform cleanup:"
        log "- Remove lock file"
        log "- Kill monitoring processes"
        log "- Clean up temporary files"
        log "- Restore system state if needed"
        return 0
    fi
    
    # Kill monitoring processes with verification
    for pid_var in MONITOR_PID NETHOGS_PID STRACE_PID PRESSURE_PID PERF_PID IOSTAT_PID CONTEXT_PID; do
        if [ -n "${!pid_var}" ]; then
            if kill -0 "${!pid_var}" 2>/dev/null; then
                kill "${!pid_var}" 2>/dev/null || true
                # Verify process was killed
                for i in {1..5}; do
                    if ! kill -0 "${!pid_var}" 2>/dev/null; then
                        break
                    fi
                    sleep 1
                done
            fi
        fi
    done
    
    # Cleanup test mode artifacts if any
    if [ "$TEST_MODE" = true ]; then
        local test_zvol="${SWAP_ZVOL}_test"
        if zfs list "$test_zvol" >/dev/null 2>&1; then
            swapoff "/dev/zvol/$test_zvol" 2>/dev/null || true
            zfs destroy "$test_zvol" 2>/dev/null || true
        fi
    fi
    
    # Perform rollback
    rollback_to_state "INITIAL"
    
    # Force cleanup of any busy volumes
    if zfs list "$SWAP_ZVOL" >/dev/null 2>&1; then
        log "Cleaning up swap volume..."
        swapoff "/dev/zvol/$SWAP_ZVOL" 2>/dev/null || true
        sleep 2
        
        # Try normal destroy first
        if ! zfs destroy "$SWAP_ZVOL" 2>/dev/null; then
            log "Volume busy, attempting forced cleanup..."
            # Force unmount if mounted
            zfs unmount -f "$SWAP_ZVOL" 2>/dev/null || true
            sleep 1
            # Force destroy
            zfs destroy -f "$SWAP_ZVOL" 2>/dev/null || log "WARNING: Could not destroy volume"
        fi
    fi
    
    # Clean up snapshots
    manage_snapshots cleanup
    
    # Remove lock file
    cleanup_lock
    
    # Restore stopped services
    if [ -f "$STATE_DIR/services_to_restart" ]; then
        log "Restoring stopped services..."
        while read service; do
            log "Starting service $service"
            systemctl start "$service" || log "Failed to restart service $service"
        done < "$STATE_DIR/services_to_restart"
    fi
    
    # Kill monitoring processes
    for pid in "$STRACE_PID" "$PRESSURE_PID" "$PERF_PID" "$IOSTAT_PID" "$CONTEXT_PID"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    
    log "Cleanup completed"
}

# Function to manage quotas
manage_quotas() {
    log "Managing filesystem quotas..."
    
    # Calculate required space with buffer
    local required_bytes=$(($(echo "$SWAP_SIZE" | sed 's/[Gg]//' | bc) * 1024 * 1024 * 1024))
    local buffer_bytes=$((required_bytes / 10))  # 10% buffer
    local total_required=$((required_bytes + buffer_bytes))
    
    # Check dataset quota
    local current_quota=$(zfs get -Hp -o value quota "$POOL_NAME")
    if [ "$current_quota" != "none" ] && [ "$current_quota" -ne 0 ] && [ "$current_quota" -lt "$total_required" ]; then
        error_exit "Dataset quota ($current_quota bytes) is less than required space ($total_required bytes)"
    fi
    
    # Check dataset reservation
    local current_reservation=$(zfs get -Hp -o value reservation "$POOL_NAME")
    if [ "$current_reservation" != "none" ] && [ "$current_reservation" -ne 0 ]; then
        local available_after_reservation=$(($(zfs get -Hp -o value available "$POOL_NAME") - current_reservation))
        if [ "$available_after_reservation" -lt "$total_required" ]; then
            error_exit "Insufficient space after reservation"
        fi
    fi
    
    # Check available space
    local available_space=$(zfs get -Hp -o value available "$POOL_NAME")
    if [ "$available_space" -lt "$total_required" ]; then
        error_exit "Insufficient available space ($available_space bytes) for required allocation ($total_required bytes)"
    fi
    
    # Set temporary quota for safety if in non-dry-run mode
    if [ "$DRY_RUN" = false ]; then
        if zfs create -p "$POOL_NAME/swap" 2>/dev/null; then
            zfs set quota="$total_required" "$POOL_NAME/swap" || true
        fi
    fi
}

# Process priority management
manage_process_priority() {
    log "Managing process priorities..."
    
    # Set script to high priority
    if [ "$DRY_RUN" = false ]; then
        # Set high priority for the script
        renice -n -10 -p $$ || true
        
        # Set IO priority
        ionice -c 2 -n 0 -p $$ || true
    fi
    
    # Identify and manage competing processes
    local high_io_procs=$(ionice -P 1 2>/dev/null | grep "realtime\|best-effort" || true)
    if [ -n "$high_io_procs" ]; then
        log "WARNING: Found processes with high IO priority:"
        echo "$high_io_procs" | while read -r pid class level; do
            local cmd=$(ps -p "$pid" -o comm=)
            log "PID: $pid, Command: $cmd, IO Class: $class, Level: $level"
        done
        prompt_continue "Adjust competing process priorities?"
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "$high_io_procs" | while read -r pid class level; do
                ionice -c 3 -p "$pid" 2>/dev/null || true
                log "Adjusted IO priority for PID $pid"
            done
        fi
    fi
}

# Resource limits management
manage_resource_limits() {
    log "Managing resource limits..."
    
    # Check current limits
    local current_limits=$(ulimit -a)
    log "Current resource limits:"
    log "$current_limits"
    
    if [ "$DRY_RUN" = false ]; then
        # Set appropriate limits for swap operation
        ulimit -n 65535  # file descriptors
        ulimit -l unlimited  # max locked memory
        ulimit -v unlimited  # virtual memory
        
        # Verify limits were set
        local new_limits=$(ulimit -a)
        log "New resource limits:"
        log "$new_limits"
    fi
}

# Network resilience
manage_network_resilience() {
    log "Managing network resilience..."
    
    # Check if we're in a network namespace
    if [ "$(readlink /proc/1/ns/net)" != "$(readlink /proc/$$/ns/net)" ]; then
        log "WARNING: Running in a network namespace"
        prompt_continue "Continue in network namespace?"
    fi
    
    # Check network interface status
    local interfaces=$(ip -br link show | awk '{print $1}')
    local has_active=false
    
    for iface in $interfaces; do
        if [ "$iface" != "lo" ]; then
            local state=$(ip -br link show "$iface" | awk '{print $2}')
            if [ "$state" = "UP" ]; then
                has_active=true
                local drops=$(ip -s link show "$iface" | awk '/RX:/{getline; print $3}')
                local errors=$(ip -s link show "$iface" | awk '/RX:/{getline; print $4}')
                
                if [ "$drops" -gt 1000 ] || [ "$errors" -gt 100 ]; then
                    log "WARNING: Interface $iface has high error count (drops: $drops, errors: $errors)"
                    prompt_continue "Continue despite network issues?"
                fi
            fi
        fi
    done
    
    if ! $has_active && [ "$DRY_RUN" = false ]; then
        log "WARNING: No active network interfaces found"
        prompt_continue "Continue without network connectivity?"
    fi
    
    # Check network load
    if command -v iftop >/dev/null; then
        log "Checking network load..."
        local net_load=$(iftop -t -s 1 2>/dev/null | awk '/Total send rate:/{print $4}')
        if [ -n "$net_load" ] && [ "${net_load%[A-Za-z]*}" -gt 100 ]; then
            log "WARNING: High network load detected ($net_load)"
            prompt_continue "Continue with high network load?"
        fi
    fi
}

# System call tracing for debugging
setup_syscall_tracing() {
    if [ "$DRY_RUN" = true ]; then
        log "Would setup system call tracing"
        return 0
    fi
    
    log "Setting up system call tracing..."
    if command -v strace >/dev/null; then
        local trace_file="$TRACE_DIR/syscalls.log"
        strace -f -tt -T -o "$trace_file" -p $$ &
        STRACE_PID=$!
        save_state "STRACE_STARTED" "$STRACE_PID"
        
        # Setup analysis trap
        trap 'analyze_syscall_trace "$trace_file"' EXIT
    else
        log "strace not available - skipping system call tracing"
    fi
}

analyze_syscall_trace() {
    local trace_file="$1"
    if [ -f "$trace_file" ]; then
        log "Analyzing system call trace..."
        
        # Analyze slow system calls
        log "Top 10 slowest system calls:"
        awk -v threshold="$SYSCALL_SLOW_THRESHOLD" '
        {
            if ($NF ~ /<[0-9.]+>/) {
                time = substr($NF, 2, length($NF)-2)
                syscall = $2
                if (time > threshold) {
                    printf "%-20s %s seconds\n", syscall, time
                }
            }
        }' "$trace_file" | sort -nrk2 | head -10
        
        # Check for failed system calls
        log "Failed system calls:"
        grep "= -1 E" "$trace_file" | awk '{print $2, $NF}' | sort | uniq -c
    fi
}

# Memory pressure handling
setup_memory_pressure_monitoring() {
    if [ "$DRY_RUN" = true ]; then
        log "Would setup memory pressure monitoring"
        return 0
    fi
    
    log "Setting up memory pressure monitoring..."
    
    if [ -f "/proc/pressure/memory" ]; then
        # Use PSI if available
        (while true; do
            local pressure=$(cat /proc/pressure/memory)
            echo "$(date): Memory Pressure: $pressure" >> "$PROFILE_DIR/memory_pressure.log"
            
            local avg10=$(echo "$pressure" | grep "avg10=" | cut -d= -f2 | cut -d' ' -f1)
            if [ "$(echo "$avg10 > $MEMORY_PRESSURE_THRESHOLD" | bc)" -eq 1 ]; then
                handle_high_memory_pressure "$avg10"
            fi
            sleep 5
        done) &
        PRESSURE_PID=$!
        save_state "PRESSURE_MONITOR" "$PRESSURE_PID"
    else
        # Fallback to traditional monitoring
        (while true; do
            local mem_info=$(free -m)
            echo "$(date): Memory Info: $mem_info" >> "$PROFILE_DIR/memory_usage.log"
            
            local mem_used_percent=$(echo "$mem_info" | awk '/^Mem:/ {printf "%.0f", ($3/$2)*100}')
            if [ "$mem_used_percent" -gt "$MEMORY_PRESSURE_THRESHOLD" ]; then
                handle_high_memory_pressure "$mem_used_percent"
            fi
            sleep 5
        done) &
        PRESSURE_PID=$!
        save_state "PRESSURE_MONITOR" "$PRESSURE_PID"
    fi
}

handle_high_memory_pressure() {
    local pressure="$1"
    log "High memory pressure detected: $pressure"
    
    # Get memory hogs
    local top_procs=$(ps -eo pid,pmem,comm --sort=-pmem | head -6)
    log "Top memory consumers:"
    log "$top_procs"
    
    # Memory relief options
    cat << EOF
Memory pressure is high. Available actions:
1. Drop caches
2. Compact memory
3. Adjust ZFS ARC size
4. Kill highest memory consumer
5. Continue anyway
6. Abort operation
EOF
    
    read -p "Select action (1-6): " choice
    case $choice in
        1)
            log "Dropping caches..."
            sync
            echo 3 > /proc/sys/vm/drop_caches
            ;;
        2)
            log "Compacting memory..."
            echo 1 > /proc/sys/vm/compact_memory
            ;;
        3)
            log "Adjusting ZFS ARC size..."
            local mem_total=$(free -b | awk '/^Mem:/{print $2}')
            echo "$((mem_total / 4))" > /sys/module/zfs/parameters/zfs_arc_max
            ;;
        4)
            local top_pid=$(ps -eo pid,pmem --sort=-pmem | awk 'NR==2 {print $1}')
            log "Killing process $top_pid..."
            kill -15 "$top_pid"
            sleep 2
            kill -9 "$top_pid" 2>/dev/null || true
            ;;
        5)
            log "Continuing despite high memory pressure"
            ;;
        6)
            error_exit "Operation aborted due to high memory pressure"
            ;;
    esac
}

# Performance profiling
setup_performance_profiling() {
    if [ "$DRY_RUN" = true ]; then
        log "Would setup performance profiling"
        return 0
    fi
    
    log "Setting up performance profiling..."
    
    # Start perf recording if available
    if command -v perf >/dev/null; then
        log "Starting performance monitoring with perf..."
        perf record -a -g -o "$PROFILE_DIR/perf.data" &
        PERF_PID=$!
        save_state "PERF_MONITOR" "$PERF_PID"
        
        # Setup perf data analysis on exit
        trap 'analyze_perf_data "$PROFILE_DIR/perf.data"' EXIT
    fi
    
    # Start IO latency monitoring
    if command -v iostat >/dev/null; then
        (while true; do
            local io_stats=$(iostat -x 1 1)
            echo "$(date): $io_stats" >> "$PROFILE_DIR/io_latency.log"
            
            # Check for high IO latency
            local max_latency=$(echo "$io_stats" | awk 'NR>3 {if($10>max) max=$10} END {print max}')
            if [ "$(echo "$max_latency > $IO_LATENCY_THRESHOLD" | bc)" -eq 1 ]; then
                log "WARNING: High IO latency detected: ${max_latency}ms"
            fi
            sleep 5
        done) &
        IOSTAT_PID=$!
        save_state "IOSTAT_MONITOR" "$IOSTAT_PID"
    fi
    
    # Monitor context switches
    (while true; do
        local ctxt_rate=$(grep "^ctxt" /proc/stat | awk '{print $2}')
        echo "$(date): Context switches: $ctxt_rate" >> "$PROFILE_DIR/context_switches.log"
        
        if [ "$ctxt_rate" -gt "$CONTEXT_SWITCH_THRESHOLD" ]; then
            log "WARNING: High context switch rate: $ctxt_rate"
        fi
        sleep 5
    done) &
    CONTEXT_PID=$!
    save_state "CONTEXT_MONITOR" "$CONTEXT_PID"
}

analyze_perf_data() {
    local perf_data="$1"
    if [ -f "$perf_data" ]; then
        log "Analyzing performance data..."
        
        # Generate performance report
        perf report -i "$perf_data" --stdio > "${perf_data%.data}_report.txt" 2>/dev/null || true
        
        # Generate flame graph if tools available
        if command -v stackcollapse-perf.pl >/dev/null && command -v flamegraph.pl >/dev/null; then
            perf script -i "$perf_data" | \
                stackcollapse-perf.pl | \
                flamegraph.pl > "${perf_data%.data}_flamegraph.svg" 2>/dev/null || true
        fi
        
        # Analyze hotspots
        log "Top 10 CPU hotspots:"
        perf report -i "$perf_data" --stdio --sort=cpu | head -15
    fi
}

# Enhanced error reporting
setup_enhanced_error_reporting() {
    if [ "$DRY_RUN" = true ]; then
        log "Would setup enhanced error reporting"
        return 0
    fi
    
    log "Setting up enhanced error reporting..."
    
    # Override error_exit function
    error_exit() {
        local error_msg="$1"
        local error_time=$(date +%Y%m%d_%H%M%S)
        local report_file="$ERROR_DIR/error_report_${error_time}.log"
        
        {
            echo "=== Error Report ==="
            echo "Timestamp: $(date)"
            echo "Error Message: $error_msg"
            echo
            echo "=== System State ==="
            echo "Uptime: $(uptime)"
            echo "Load Average: $(cat /proc/loadavg)"
            echo
            echo "=== Memory State ==="
            free -h
            echo
            echo "=== Disk State ==="
            df -h
            echo
            echo "=== ZFS Pool State ==="
            zpool status "$POOL_NAME" 2>/dev/null || echo "No pool info available"
            echo
            echo "=== Recent Logs ==="
            tail -n 50 "$LOG_DIR/setup.log" 2>/dev/null || echo "No recent logs available"
            echo
            echo "=== Process Tree ==="
            ps auxf
            echo
            echo "=== System Messages ==="
            tail -n 50 /var/log/syslog 2>/dev/null || tail -n 50 /var/log/messages 2>/dev/null || echo "No system logs available"
            echo
            echo "=== Performance Data ==="
            if [ -f "$PROFILE_DIR/perf.data" ]; then
                perf report -i "$PROFILE_DIR/perf.data" --stdio 2>/dev/null || echo "No perf data available"
            fi
        } > "$report_file"
        
        log "ERROR: $error_msg"
        log "Detailed error report saved to: $report_file"
        
        cleanup
        exit 1
    }
}

# Initialize monitoring directories
initialize_monitoring_dirs() {
    log "Initializing monitoring directories..."
    
    TRACE_DIR="$LOG_DIR/traces"
    PROFILE_DIR="$LOG_DIR/profile"
    ERROR_DIR="$LOG_DIR/errors"
    
    for dir in "$TRACE_DIR" "$PROFILE_DIR" "$ERROR_DIR"; do
        mkdir -p "$dir" || error_exit "Failed to create directory: $dir"
        chmod 750 "$dir" || error_exit "Failed to set permissions on: $dir"
    done
}

# Kernel module verification
verify_kernel_modules() {
    log "Verifying kernel module states..."
    
    # Check ZFS module parameters
    local zfs_params="/sys/module/zfs/parameters"
    if [ -d "$zfs_params" ]; then
        local params=(
            "zfs_txg_timeout"
            "zfs_vdev_cache_size"
            "zfs_prefetch_disable"
            "zfs_arc_max"
            "zfs_arc_min"
            "zfs_dirty_data_max"
        )
        
        log "Current ZFS module parameters:"
        for param in "${params[@]}"; do
            if [ -f "$zfs_params/$param" ]; then
                local value=$(cat "$zfs_params/$param")
                log "- $param = $value"
                save_state "ZFS_PARAM_${param}" "$value"
            fi
        done
    fi
    
    # Verify module dependencies
    local modules=(zfs zunicode zavl zcommon znvpair spl)
    for module in "${modules[@]}"; do
        if ! lsmod | grep -q "^$module"; then
            error_exit "Required module $module is not loaded"
        fi
        # Get module details
        local module_info=$(modinfo "$module" 2>/dev/null)
        log "Module $module info:"
        log "$module_info" | grep -E "^(version|filename|description):"
    done
    
    # Check module parameters
    if [ -f "/proc/spl/kstat/zfs/arcstats" ]; then
        log "ZFS ARC statistics:"
        local arc_stats=$(cat /proc/spl/kstat/zfs/arcstats)
        log "$arc_stats" | grep -E "^(hits|misses|size|c_max|c_min)"
    fi
}

# Enhanced filesystem event monitoring
monitor_fs_events() {
    if [ "$DRY_RUN" = true ]; then
        log "Would setup filesystem event monitoring"
        return 0
    fi
    
    if command -v inotifywait >/dev/null; then
        log "Setting up filesystem event monitoring..."
        
        # Create events log
        local events_log="$LOG_DIR/fs_events.log"
        touch "$events_log" || error_exit "Failed to create events log"
        chmod 640 "$events_log" || error_exit "Failed to set events log permissions"
        
        # Monitor critical paths
        (inotifywait -m -r /dev/zvol "$STATE_DIR" /etc/fstab 2>/dev/null | while read -r directory events filename; do
            echo "$(date): $directory $events $filename" >> "$events_log"
            
            # Alert on critical file modifications
            case "$directory" in
                "/etc/fstab")
                    log "WARNING: fstab modification detected: $events"
                    if [ "$events" = "MODIFY" ]; then
                        verify_backup "/etc/fstab"
                    fi
                    ;;
                "/dev/zvol/"*)
                    if [[ "$filename" == *"$SWAP_ZVOL"* ]]; then
                        log "WARNING: Swap device event detected: $events"
                        if [ "$events" = "DELETE" ]; then
                            error_exit "Swap device was deleted"
                        fi
                    fi
                    ;;
                "$STATE_DIR"*)
                    log "State directory event: $events on $filename"
                    if [ "$events" = "DELETE" ]; then
                        log "WARNING: State file deletion detected"
                    fi
                    ;;
            esac
        done) &
        
        local INOTIFY_PID=$!
        save_state "INOTIFY_MONITOR" "$INOTIFY_PID"
        
        # Add to cleanup
        trap "kill $INOTIFY_PID 2>/dev/null || true" EXIT
    else
        log "inotifywait not available - skipping filesystem event monitoring"
    fi
}

# Process ancestry verification
verify_process_ancestry() {
    log "Verifying process ancestry..."
    
    # Get process tree in a safer way
    local pid=$$
    local ancestry=""
    local suspicious=false
    
    while [ "$pid" != "1" ] && [ -n "$pid" ]; do
        # Read process info directly from proc to avoid ps issues
        if [ -r "/proc/$pid/status" ]; then
            local cmd=$(tr -d '\0' < "/proc/$pid/comm")
            local ppid=$(awk '/PPid:/{print $2}' "/proc/$pid/status")
            local uid=$(awk '/Uid:/{print $2}' "/proc/$pid/status")
            
            # Get username from uid
            local user=""
            if [ -r "/etc/passwd" ]; then
                user=$(awk -F: "\$3 == $uid {print \$1}" /etc/passwd)
            fi
            
            # Get process start time
            local start=""
            if [ -r "/proc/$pid/stat" ]; then
                start=$(date -d "@$(stat -c %Y "/proc/$pid/stat")" '+%Y-%m-%d %H:%M:%S')
            fi
            
            ancestry="$cmd (User: ${user:-$uid}, Started: ${start:-unknown}) -> $ancestry"
            
            # Check for suspicious parent processes
            case "$cmd" in
                *cron*|*at*|*batch*|systemd-run*)
                    suspicious=true
                    log "WARNING: Suspicious parent process detected: $cmd"
                    ;;
            esac
            
            pid="$ppid"
        else
            break
        fi
    done
    
    log "Process ancestry: $ancestry"
    
    if [ "$suspicious" = true ]; then
        if [ "$DRY_RUN" = true ]; then
            log "Would prompt: Script appears to be running from scheduler or suspicious parent. Continue?"
        else
            prompt_continue "Script appears to be running from scheduler or suspicious parent. Continue?"
        fi
    fi
    
    # Save process information
    if [ "$DRY_RUN" = false ]; then
        save_state "PROCESS_ANCESTRY" "$ancestry"
    fi
}

# Enhanced security context verification
verify_security_context() {
    log "Verifying security context..."
    
    # Check SELinux context if available
    if command -v getenforce >/dev/null; then
        local selinux_state=$(getenforce)
        log "SELinux state: $selinux_state"
        if [ "$selinux_state" = "Enforcing" ]; then
            local context=$(ls -Z "$ZVOL_DEVICE" 2>/dev/null)
            log "SELinux context: $context"
            
            # Verify context is appropriate
            if ! echo "$context" | grep -q "system_u:object_r:fixed_disk_device_t"; then
                log "WARNING: Unexpected SELinux context for swap device"
                prompt_continue "Continue with non-standard SELinux context?"
            fi
        fi
    fi
    
    # Check AppArmor if available
    if command -v aa-status >/dev/null; then
        if aa-status --enabled 2>/dev/null; then
            log "AppArmor is enabled"
            local profile=$(aa-status | grep "$ZVOL_DEVICE" || true)
            if [ -n "$profile" ]; then
                log "AppArmor profile: $profile"
                save_state "APPARMOR_PROFILE" "$profile"
            fi
        fi
    fi
    
    # Check for secure boot
    if [ -d "/sys/firmware/efi/efivars" ]; then
        if bootctl status 2>/dev/null | grep -q "Secure Boot: enabled"; then
            log "WARNING: Secure Boot is enabled"
            prompt_continue "Continue with Secure Boot enabled?"
        fi
        
        # Check for custom keys
        if [ -d "/etc/secureboot/keys" ]; then
            log "Custom Secure Boot keys detected"
        fi
    fi
    
    # Check for mandatory access control
    if [ -f "/proc/self/attr/current" ]; then
        local mac_context=$(cat /proc/self/attr/current)
        log "Mandatory Access Control context: $mac_context"
    fi
}

# Entropy availability check
check_entropy_availability() {
    log "Checking entropy availability..."
    
    local available_entropy=$(cat /proc/sys/kernel/random/entropy_avail)
    local poolsize=$(cat /proc/sys/kernel/random/poolsize)
    
    log "Available entropy: $available_entropy / $poolsize"
    save_state "ENTROPY_LEVEL" "$available_entropy"
    
    if [ "$available_entropy" -lt 1000 ]; then
        log "WARNING: Low entropy available ($available_entropy bytes)"
        
        # Check available entropy sources
        if [ -c "/dev/hwrng" ]; then
            log "Hardware RNG device available"
        fi
        
        if command -v rngd >/dev/null; then
            local rngd_status=$(systemctl is-active rngd 2>/dev/null || echo "inactive")
            if [ "$rngd_status" != "active" ]; then
                prompt_continue "Start rngd to increase entropy?"
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    systemctl start rngd
                    sleep 2
                    available_entropy=$(cat /proc/sys/kernel/random/entropy_avail)
                    log "New entropy level: $available_entropy"
                fi
            fi
        fi
        
        # Check for other entropy sources
        if [ -c "/dev/urandom" ]; then
            log "Checking urandom driver status..."
            local urandom_driver=$(cat /proc/sys/kernel/random/urandom_min_reseed_secs)
            log "urandom minimum reseed seconds: $urandom_driver"
        fi
    fi
}

# Power management state verification
verify_power_management() {
    log "Checking power management state..."
    
    # Check CPU power management
    if [ -d "/sys/devices/system/cpu/cpu0/cpufreq" ]; then
        local governor=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)
        local policy=$(cat /sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference 2>/dev/null || echo "N/A")
        local freq_min=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq)
        local freq_max=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq)
        
        log "CPU Power Management:"
        log "- Governor: $governor"
        log "- Energy Policy: $policy"
        log "- Frequency Range: $freq_min - $freq_max"
        
        save_state "CPU_GOVERNOR" "$governor"
        
        if [ "$governor" != "performance" ]; then
            if [ "$DRY_RUN" = true ]; then
                log "Would prompt: CPU not in performance mode. Continue?"
            else
                prompt_continue "CPU not in performance mode. Continue?"
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    echo "performance" > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
                    save_state "GOVERNOR_MODIFIED" "$governor"
                fi
            fi
        fi
    fi
    
    # Check for battery operation on laptops
    if [ -d "/sys/class/power_supply" ]; then
        local on_battery=false
        local battery_level=""
        
        for battery in /sys/class/power_supply/BAT*; do
            if [ -f "$battery/status" ] && [ -f "$battery/capacity" ]; then
                local status=$(cat "$battery/status")
                local capacity=$(cat "$battery/capacity")
                
                log "Battery status: $status ($capacity%)"
                
                if [ "$status" = "Discharging" ]; then
                    on_battery=true
                    battery_level="$capacity"
                fi
            fi
        done
        
        if [ "$on_battery" = true ]; then
            log "WARNING: System is running on battery power (${battery_level}%)"
            if [ "${battery_level}" -lt 50 ]; then
                error_exit "Battery level too low for safe operation"
            elif [ "$DRY_RUN" = true ]; then
                log "Would prompt: Continue on battery power?"
            else
                prompt_continue "Continue on battery power?"
            fi
        fi
    fi
    
    # Check thermal throttling
    if [ -f "/sys/class/thermal/thermal_zone0/temp" ]; then
        local temp=$(($(cat /sys/class/thermal/thermal_zone0/temp) / 1000))
        log "CPU temperature: ${temp}°C"
        
        if [ "$temp" -gt 80 ]; then
            log "WARNING: High CPU temperature detected"
            if [ "$DRY_RUN" = true ]; then
                log "Would prompt: Continue despite high temperature?"
            else
                prompt_continue "Continue despite high temperature?"
            fi
        fi
    fi
}

# Transaction management functions
transaction_begin() {
    local transaction_name="$1"
    if [ "$DRY_RUN" = true ]; then
        log "Would begin transaction: $transaction_name"
        return 0
    fi
    
    log "Beginning transaction: $transaction_name"
    echo "$transaction_name" > "$STATE_DIR/current_transaction"
    log_transaction "BEGIN" "$transaction_name"
}

transaction_commit() {
    local transaction_name="$1"
    if [ "$DRY_RUN" = true ]; then
        log "Would commit transaction: $transaction_name"
        return 0
    fi
    
    if [ ! -f "$STATE_DIR/current_transaction" ]; then
        error_exit "No active transaction to commit"
    fi
    
    local current_transaction=$(cat "$STATE_DIR/current_transaction")
    if [ "$current_transaction" != "$transaction_name" ]; then
        error_exit "Transaction mismatch: expected $transaction_name, found $current_transaction"
    fi
    
    log "Committing transaction: $transaction_name"
    rm -f "$STATE_DIR/current_transaction"
    log_transaction "COMMIT" "$transaction_name"
}

transaction_rollback() {
    local transaction_name="$1"
    if [ "$DRY_RUN" = true ]; then
        log "Would rollback transaction: $transaction_name"
        return 0
    fi
    
    if [ ! -f "$STATE_DIR/current_transaction" ]; then
        log "No active transaction to rollback"
        return 0
    fi
    
    local current_transaction=$(cat "$STATE_DIR/current_transaction")
    log "Rolling back transaction: $current_transaction"
    
    case "$current_transaction" in
        "TEST_MODE")
            # Clean up test volume
            local test_zvol="${SWAP_ZVOL}_test"
            swapoff "/dev/zvol/$test_zvol" 2>/dev/null || true
            zfs destroy "$test_zvol" 2>/dev/null || true
            ;;
        "QUOTA_MODIFY")
            # Restore original quota
            if [ -f "$STATE_DIR/QUOTA_MODIFIED.state" ]; then
                local original_quota=$(cat "$STATE_DIR/QUOTA_MODIFIED.state")
                zfs set quota="$original_quota" "$POOL_NAME/swap" || true
            fi
            ;;
        "PRIORITY_MODIFY")
            # Restore original process priority
            if [ -f "$STATE_DIR/PRIORITY_MODIFIED.state" ]; then
                local original_priority=$(cat "$STATE_DIR/PRIORITY_MODIFIED.state")
                renice -n "$original_priority" -p $$ || true
            fi
            ;;
        "LIMITS_MODIFY")
            # Restore original resource limits
            if [ -f "$STATE_DIR/LIMITS_MODIFIED.state" ]; then
                while IFS= read -r limit; do
                    ulimit $limit || true
                done < "$STATE_DIR/LIMITS_MODIFIED.state"
            fi
            ;;
        *)
            log "No specific rollback actions for transaction: $current_transaction"
            ;;
    esac
    
    rm -f "$STATE_DIR/current_transaction"
    log_transaction "ROLLBACK" "$current_transaction"
}

# Backup verification function
verify_backups() {
    log "Verifying backup integrity..."
    
    if [ "$DRY_RUN" = true ]; then
        log "Would verify backup files"
        return 0
    fi
    
    # Verify fstab backup
    if [ -f "$FSTAB_BACKUP" ]; then
        log "Verifying fstab backup..."
        
        # Check file permissions
        local perms=$(stat -c "%a" "$FSTAB_BACKUP")
        if [ "$perms" != "644" ]; then
            log "WARNING: Incorrect permissions on fstab backup: $perms (should be 644)"
            chmod 644 "$FSTAB_BACKUP" || error_exit "Failed to set correct permissions on fstab backup"
        fi
        
        # Verify content integrity
        local backup_sum=$(sha256sum "$FSTAB_BACKUP" | cut -d' ' -f1)
        local current_sum=$(sha256sum /etc/fstab | cut -d' ' -f1)
        
        if [ "$backup_sum" = "$current_sum" ]; then
            log "fstab backup verified successfully"
        else
            log "WARNING: fstab backup differs from current file"
            log "Backup checksum: $backup_sum"
            log "Current checksum: $current_sum"
            
            # Check for critical entries
            if ! grep -q "^UUID=" "$FSTAB_BACKUP"; then
                error_exit "Backup verification failed: No UUID entries found in backup"
            fi
        fi
    else
        error_exit "fstab backup not found"
    fi
    
    # Verify ZFS snapshots
    if zfs list -t snapshot | grep -q "swap_setup_${TIMESTAMP}"; then
        log "Verifying ZFS snapshot..."
        if ! zfs get -H -o value creation "rpool@swap_setup_${TIMESTAMP}" >/dev/null 2>&1; then
            error_exit "Snapshot verification failed"
        fi
    fi
    
    # Verify state files
    log "Verifying state files..."
    for state_file in "$STATE_DIR"/*.state; do
        if [ -f "$state_file" ]; then
            if ! [ -r "$state_file" ]; then
                error_exit "State file not readable: $state_file"
            fi
            
            # Verify file format (should contain valid data)
            if ! [ -s "$state_file" ]; then
                error_exit "Empty state file found: $state_file"
            fi
        fi
    done
    
    log "Backup verification completed"
}

# Check if swap zvol already exists
check_existing_swap() {
    log "Checking for existing swap volume..."
    if zfs list "$SWAP_ZVOL" >/dev/null 2>&1; then
        log "WARNING: Swap volume $SWAP_ZVOL already exists"
        if [ "$DRY_RUN" = false ]; then
            read -p "Would you like to remove it and create a new one? (y/n) " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                # First, check what's using the device
                log "Checking what's using the swap device..."
                lsof "/dev/zvol/$SWAP_ZVOL" 2>/dev/null || true
                fuser -v "/dev/zvol/$SWAP_ZVOL" 2>/dev/null || true
                
                # Disable all swap everywhere
                log "Disabling all swap..."
                swapoff -a || true
                
                # Remove from /etc/fstab to prevent auto-mount
                log "Removing swap entries from fstab..."
                sed -i '/\sswap\s/d' /etc/fstab
                sync
                
                # Stop any ZFS swap services
                log "Stopping ZFS swap services..."
                systemctl stop zfs-swap.service 2>/dev/null || true
                systemctl disable zfs-swap.service 2>/dev/null || true
                
                # Force unmount the dataset if mounted
                log "Forcing unmount of swap volume..."
                zfs unmount -f "$SWAP_ZVOL" 2>/dev/null || true
                
                # Kill any processes still using the device
                log "Checking for processes using the device..."
                if fuser -m "/dev/zvol/$SWAP_ZVOL" 2>/dev/null; then
                    log "WARNING: Processes are still using the swap volume. Terminating..."
                    fuser -k -9 "/dev/zvol/$SWAP_ZVOL" 2>/dev/null || true
                    sleep 2
                fi
                
                # Export and import the pool to clear any busy states
                log "Attempting to clear busy state..."
                zpool export -f "$POOL_NAME" 2>/dev/null || true
                sleep 2
                zpool import "$POOL_NAME" 2>/dev/null || true
                sleep 2
                
                # Try normal destroy first
                log "Attempting to destroy swap volume..."
                if ! zfs destroy "$SWAP_ZVOL" 2>/dev/null; then
                    log "Normal destroy failed, trying forced destroy..."
                    if ! zfs destroy -f "$SWAP_ZVOL" 2>/dev/null; then
                        log "Forced destroy failed, trying recursive forced destroy..."
                        if ! zfs destroy -r -f "$SWAP_ZVOL"; then
                            # If all else fails, try to use zfs hold and release
                            log "All standard methods failed. Attempting to release holds..."
                            zfs holds "$SWAP_ZVOL" | while read -r ds tag rest; do
                                [ "$ds" = "$SWAP_ZVOL" ] && zfs release "$tag" "$SWAP_ZVOL"
                            done
                            sleep 1
                            if ! zfs destroy -r -f "$SWAP_ZVOL"; then
                                error_exit "Failed to remove swap volume after all attempts. Manual intervention required."
                            fi
                        fi
                    fi
                fi
                
                # Wait for cleanup and verify
                sync
                sleep 2
                if zfs list "$SWAP_ZVOL" >/dev/null 2>&1; then
                    error_exit "Failed to remove swap volume - it still exists after removal attempts"
                fi
                
                log "Successfully removed existing swap volume"
                return 0
            else
                error_exit "Operation cancelled by user"
            fi
        else
            log "Would prompt to remove existing swap volume"
            return 0
        fi
    fi
    return 0
}

# Function to ensure swap persistence
ensure_swap_persistence() {
    log "Ensuring swap persistence across reboots..."
    
    if [ "$DRY_RUN" = false ]; then
        # 1. Configure ZFS dataset properties
        log "Configuring ZFS dataset properties..."
        zfs set sync=always "$SWAP_ZVOL"
        zfs set primarycache=metadata "$SWAP_ZVOL"
        zfs set secondarycache=none "$SWAP_ZVOL"
        zfs set compression=off "$SWAP_ZVOL"
        zfs set logbias=throughput "$SWAP_ZVOL"
        zfs set mountpoint=none "$SWAP_ZVOL"
        zfs set com.sun:auto-snapshot=false "$SWAP_ZVOL"
        
        # 2. Create systemd service for early swap activation
        local service_file="/etc/systemd/system/zfs-swap.service"
        log "Creating systemd service at $service_file..."
        cat > "$service_file" << EOF
[Unit]
Description=ZFS swap volume activation
DefaultDependencies=no
Before=swap.target
After=zfs-import.target local-fs.target
Requires=zfs-import.target
ConditionPathExists=/dev/zvol/$SWAP_ZVOL

[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutSec=0
ExecStartPre=-/sbin/swapoff -a
ExecStart=/sbin/mkswap /dev/zvol/$SWAP_ZVOL
ExecStart=/sbin/swapon -p 100 /dev/zvol/$SWAP_ZVOL
ExecStop=/sbin/swapoff /dev/zvol/$SWAP_ZVOL

[Install]
WantedBy=swap.target
Also=zfs-import.service
EOF
        chmod 644 "$service_file"
        
        # 3. Create udev rule for persistent device naming
        local udev_file="/etc/udev/rules.d/90-zfs-swap.rules"
        log "Creating udev rule at $udev_file..."
        cat > "$udev_file" << EOF
ACTION=="add|change", KERNEL=="zd*", DRIVER=="zd", ATTR{name}=="$SWAP_ZVOL", SYMLINK+="zvol/$SWAP_ZVOL", TAG+="systemd"
EOF
        chmod 644 "$udev_file"
        
        # 4. Update initramfs to include ZFS modules
        log "Updating initramfs..."
        update-initramfs -u
        
        # 5. Configure ZFS import cache
        log "Updating ZFS cache..."
        zpool set cachefile=/etc/zfs/zpool.cache "$POOL_NAME"
        
        # 6. Update /etc/fstab with priority and options
        log "Updating fstab entry..."
        local uuid=$(blkid -s UUID -o value "/dev/zvol/$SWAP_ZVOL")
        if [ -n "$uuid" ]; then
            # Remove any existing swap entries
            sed -i '/\sswap\s/d' /etc/fstab
            # Add new swap entry with high priority and optimal options
            echo "UUID=$uuid none swap sw,pri=100,discard 0 0" >> /etc/fstab
        fi
        
        # 7. Enable and start the service
        log "Enabling systemd service..."
        systemctl daemon-reload
        systemctl enable zfs-swap.service
        
        # 8. Test the configuration
        log "Testing swap configuration..."
        if ! systemctl start zfs-swap.service; then
            error_exit "Failed to start swap service"
        fi
        
        # 9. Verify swap is active
        if ! swapon --show | grep -q "$SWAP_ZVOL"; then
            error_exit "Swap device not active after service start"
        fi
        
        # 10. Create a backup of the configuration
        local backup_dir="/etc/zfs/swap-backup"
        mkdir -p "$backup_dir"
        cp "$service_file" "$backup_dir/"
        cp "$udev_file" "$backup_dir/"
        cp /etc/fstab "$backup_dir/fstab.backup"
        
        log "Swap persistence configuration completed successfully"
        
        # Final validation checks
        log "Performing final validation checks..."
        
        # Check systemd service status
        log "=== Systemd Service Status ==="
        systemctl status zfs-swap.service
        
        # Check current swap status
        log "=== Current Swap Status ==="
        swapon --show
        
        # Check fstab entry
        log "=== FSTAB Entry ==="
        grep swap /etc/fstab
        
        # Check ZFS properties
        log "=== ZFS Properties ==="
        zfs get all "$SWAP_ZVOL" | grep -E "mountpoint|compression|primarycache|secondarycache|sync|logbias|com.sun:auto-snapshot"
        
        # Check systemd service configuration
        log "=== Systemd Service Configuration ==="
        systemctl is-enabled zfs-swap.service
        
        # Verify swap is active and working
        if ! swapon --show | grep -q "$SWAP_ZVOL"; then
            error_exit "Final validation failed: Swap is not active"
        fi
        
        # Verify systemd service is properly enabled
        if ! systemctl is-enabled zfs-swap.service >/dev/null 2>&1; then
            error_exit "Final validation failed: zfs-swap service is not enabled"
        fi
        
        log "All validation checks passed successfully"
        log "Swap device will be automatically activated on boot"
        
    else
        log "Would configure swap persistence:"
        log "- Set ZFS dataset properties"
        log "- Create systemd service"
        log "- Create udev rule"
        log "- Update initramfs"
        log "- Configure ZFS cache"
        log "- Update fstab"
        log "- Enable service"
        log "- Test configuration"
        log "- Run validation checks"
    fi
}

# Update main function to include new checks
main() {
    # Acquire lock first
    acquire_lock
    
    # Create required directories and initialize logging first
    create_directories
    initialize_monitoring_dirs
    
    # Start transaction logging
    transaction_begin "SETUP_START"
    
    if [ "$DRY_RUN" = true ]; then
        log "=== DRY RUN MODE ==="
        log "The following operations would be performed:"
        log "- Swap size: $SWAP_SIZE"
        log "- ZFS pool: $POOL_NAME"
        log "- Swap zvol: $SWAP_ZVOL"
        log "No changes will be made to your system"
    fi
    
    # Initialize state (after directories are created)
    save_state "INITIAL" "Starting setup"
    
    # Run test mode if requested
    if [ "$TEST_MODE" = true ]; then
        log "Running in test mode..."
        if ! test_mode; then
            error_exit "Test mode failed"
        fi
        if [ "$DRY_RUN" = false ]; then
            log "Test mode completed successfully"
            cleanup
            exit 0
        else
            log "Would exit after successful test mode"
            exit 0
        fi
    fi
    
    # Start resource monitoring
    monitor_resources
    
    # Backup fstab with verification
    if [ "$DRY_RUN" = false ]; then
        if [ ! -f /etc/fstab ]; then
            error_exit "fstab file not found"
        fi
        cp /etc/fstab "$FSTAB_BACKUP" || error_exit "Failed to backup fstab"
        verify_backup "$FSTAB_BACKUP"
        log "Created and verified fstab backup at $FSTAB_BACKUP"
        save_state "FSTAB_BACKUP" "Created fstab backup"
    else
        log "Would backup fstab to $FSTAB_BACKUP"
    fi
    
    # System checks with enhanced monitoring
    check_system_health
    
    # Check if zfs is available and working
    if ! command -v zfs >/dev/null; then
        error_exit "ZFS utilities not found. Please install zfsutils-linux"
    fi
    
    # Test ZFS functionality
    if ! zfs version >/dev/null 2>&1; then
        error_exit "ZFS module not loaded or not functioning"
    fi
    
    # Check pool health and space with enhanced monitoring
    check_pool_health
    
    # Check if swap zvol already exists with improved handling
    if zfs list "$SWAP_ZVOL" >/dev/null 2>&1; then
        log "WARNING: Swap volume $SWAP_ZVOL already exists"
        if [ "$DRY_RUN" = false ]; then
            read -p "Would you like to remove it and create a new one? (y/n) " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                # Check if it's being used as swap
                if grep -q "$SWAP_ZVOL" /proc/swaps; then
                    execute "swapoff \"/dev/zvol/$SWAP_ZVOL\"" "disable existing swap"
                    sleep 2  # Give system time to sync
                fi
                execute "zfs destroy \"$SWAP_ZVOL\"" "remove existing swap volume"
                log_transaction "DESTROY" "$SWAP_ZVOL"
                sleep 2  # Give ZFS time to clean up
            else
                error_exit "Operation cancelled by user"
            fi
        else
            log "Would prompt to remove existing swap volume"
        fi
    fi
    
    # Run enhanced pre-flight checks
    validate_environment
    validate_configuration
    assess_system_impact
    
    # Start enhanced monitoring
    monitor_performance_impact
    monitor_network_impact
    
    # Add new management functions
    manage_quotas
    manage_process_priority
    manage_resource_limits
    
    # Check for existing swap volume before proceeding
    check_existing_swap
    
    # Create the swap zvol
    if [ "$DRY_RUN" = false ]; then
        log "Creating swap volume of size $SWAP_SIZE"
        
        # Ensure any existing swap is disabled
        log "Disabling any existing swap"
        swapoff -a
        sleep 2
        
        # Remove existing volume if it exists
        if zfs list -t volume "$SWAP_ZVOL" >/dev/null 2>&1; then
            log "Removing existing swap volume"
            zfs destroy "$SWAP_ZVOL" || {
                log "ERROR: Failed to remove existing swap volume"
                return 1
            }
            sleep 2
        fi
        
        # Create the volume with correct properties
        log "Creating ZFS volume with 8K block size"
        zfs create -V "$SWAP_SIZE" \
            -b 8K \
            -o compression=off \
            -o logbias=throughput \
            -o sync=always \
            -o primarycache=metadata \
            -o secondarycache=none \
            -o com.sun:auto-snapshot=false \
            "$SWAP_ZVOL" || {
                log "ERROR: Failed to create swap volume"
                return 1
            }
        
        # Wait for device file to appear
        local device="/dev/zvol/$SWAP_ZVOL"
        local timeout=30
        local count=0
        log "Waiting for device file to appear: $device"
        while [ ! -e "$device" ] && [ $count -lt $timeout ]; do
            sleep 1
            count=$((count + 1))
        done
        
        if [ ! -e "$device" ]; then
            log "ERROR: Device file did not appear after $timeout seconds"
            return 1
        fi
        
        # Format the swap
        log "Formatting swap device"
        mkswap "$device" || {
            log "ERROR: Failed to format swap device"
            return 1
        }
        sleep 2
        
        # Get UUID and update fstab
        local uuid=$(blkid -s UUID -o value "$device")
        if [ -z "$uuid" ]; then
            log "ERROR: Failed to get UUID for swap device"
            return 1
        fi
        
        # Update fstab
        log "Updating /etc/fstab with new swap entry"
        sed -i '/\sswap\s/d' /etc/fstab
        echo "UUID=$uuid none swap sw 0 0" >> /etc/fstab
        
        # Enable swap
        log "Enabling swap"
        swapon "$device" || {
            log "ERROR: Failed to enable swap"
            return 1
        }
        
        log "Swap volume created and enabled successfully"
        return 0
    fi
    
    # Set device path
    ZVOL_DEVICE="/dev/zvol/$SWAP_ZVOL"
    
    if [ "$DRY_RUN" = false ]; then
        # Wait for device to be created
        log "Waiting for zvol device to be ready"
        for i in {1..30}; do  # Increased timeout to 30 seconds
            if [ -e "$ZVOL_DEVICE" ]; then
                break
            fi
            sleep 1
            if [ $i -eq 30 ]; then
                error_exit "Timeout waiting for zvol device"
            fi
        done
        
        # Format the swap volume
        log "Formatting swap volume"
        mkswap "$ZVOL_DEVICE"
        sync
        
        # Get UUID of the swap device
        SWAP_UUID=$(blkid -s UUID -o value "$ZVOL_DEVICE")
        if [ -z "$SWAP_UUID" ]; then
            error_exit "Failed to get UUID of swap device"
        fi
    else
        SWAP_UUID="SIMULATED-UUID"
        log "Would:"
        log "- Wait for device $ZVOL_DEVICE to be ready"
        log "- Format device as swap"
        log "- Get device UUID"
    fi
    
    # Handle existing swap
    if [ "$DRY_RUN" = false ]; then
        log "Disabling existing swap"
        swapoff -a || true
        
        log "Removing existing swap entries from fstab"
        sed -i '/swap/d' /etc/fstab
        EXECUTED_STEPS[fstab_modified]=1
    else
        log "Would:"
        log "- Disable all existing swap"
        log "- Remove existing swap entries from fstab"
    fi
    
    # Add new swap entry to fstab
    if [ "$DRY_RUN" = false ]; then
        log "Adding new swap entry to fstab"
        echo "UUID=$SWAP_UUID none swap discard 0 0" >> /etc/fstab
        log_transaction "FSTAB" "Added UUID=$SWAP_UUID"
    else
        log "Would add to fstab: UUID=$SWAP_UUID none swap discard 0 0"
    fi
    
    # Verify configuration
    verify_swap_config
    
    # Enable the new swap
    if [ "$DRY_RUN" = false ]; then
        log "Enabling swap"
        
        # Ensure clean state
        swapoff -a 2>/dev/null || true
        sleep 2
        
        # Debug info before enabling
        log "Swap device details:"
        ls -l "$ZVOL_DEVICE"
        file "$ZVOL_DEVICE"
        
        # Try enabling with error capture
        if ! swapon -v "$ZVOL_DEVICE" 2> >(tee -a "$LOG_DIR/swapon_error.log"); then
            local error_log=$(cat "$LOG_DIR/swapon_error.log")
            error_exit "Failed to enable swap: $error_log"
        fi
        
        EXECUTED_STEPS[swap_enabled]=1
        
        # Verify swap is working
        if ! swapon --show | grep -q "$ZVOL_DEVICE"; then
            error_exit "Swap device not found in active swap list"
        fi
        
        # Show final status
        log "Swap setup completed successfully"
        log "Swap device: $ZVOL_DEVICE"
        log "UUID: $SWAP_UUID"
        swapon --show
        free -h
    else
        log "Would:"
        log "- Enable swap device"
        log "- Verify swap is working"
        log "- Show swap statistics"
    fi
    
    # Ensure swap persistence
    ensure_swap_persistence
    
    # Add state tracking for critical operations
    if [ "$DRY_RUN" = false ]; then
        save_state "ZVOL_CREATED" "$SWAP_ZVOL"
        save_state "FSTAB_MODIFIED" "Added swap entry"
        save_state "SWAP_ENABLED" "$ZVOL_DEVICE"
        save_state "PERSISTENCE_CONFIGURED" "Setup complete"
    fi
    
    # Cleanup lock file
    cleanup_lock
    
    # Create emergency recovery script
    emergency_recovery
    
    # Clean up snapshot on success
    manage_snapshots cleanup
    
    # Add new checks after system health check
    check_memory_fragmentation
    manage_zfs_arc
    optimize_io_scheduler
    tune_kernel_parameters
    check_network_performance
    monitor_temperature
    check_numa_topology
    
    # Enhance emergency recovery before cleanup
    enhance_emergency_recovery
    
    # Add new verification functions
    verify_backups
    manage_network_resilience
    
    # Add new monitoring and safety features
    setup_syscall_tracing
    setup_memory_pressure_monitoring
    setup_performance_profiling
    
    # Add new security and monitoring checks
    verify_kernel_modules
    monitor_fs_events
    verify_process_ancestry
    verify_security_context
    check_entropy_availability
    verify_power_management
    
    transaction_commit "SETUP_COMPLETE"
    
    if [ "$DRY_RUN" = true ]; then
        log "Dry run completed successfully - no changes were made"
    else
        log "Setup completed successfully!"
    fi
}

# Run main function
main