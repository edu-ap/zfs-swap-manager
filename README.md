# ZFS Swap Manager

A comprehensive tool for creating and managing ZFS-based swap volumes with advanced safety features, monitoring, and recovery capabilities.

## Features

### Core Functionality
- Create ZFS-based swap volumes with optimal properties
- Automatic block size optimization (8K)
- Intelligent ZFS property configuration
- UUID-based swap configuration
- Persistent configuration through systemd and fstab
- Comprehensive validation checks

### Persistence Features
1. **Systemd Integration**
   - Automatic service creation and enablement
   - Early boot activation
   - Proper dependency management
   - Service status monitoring

2. **Device Management**
   - Udev rules for persistent device naming
   - Proper device permissions
   - Automatic device detection
   - ZFS import cache configuration

3. **Boot Integration**
   - Initramfs updates for ZFS modules
   - Proper ordering with system services
   - Fallback mechanisms
   - Boot-time validation

### Safety Features
1. **System Health Monitoring**
   - Real-time CPU load monitoring and management
   - Memory pressure detection and handling
   - IO latency tracking and optimization
   - Network performance monitoring
   - Process priority management
   - NUMA topology awareness

2. **Resource Management**
   - ZFS ARC size optimization
   - IO scheduler tuning
   - Kernel parameter optimization
   - Process and IO priority management
   - Resource limits control

3. **Security Features**
   - SELinux/AppArmor context verification
   - Secure Boot detection
   - Process ancestry verification
   - Entropy availability monitoring
   - Mandatory Access Control checks

4. **Monitoring and Debugging**
   - System call tracing
   - Performance profiling
   - Filesystem event monitoring
   - Detailed transaction logging
   - Resource usage tracking
   - Network resilience checks

5. **Backup and Recovery**
   - Automatic ZFS snapshots
   - Emergency recovery script generation
   - Transaction rollback capabilities
   - State tracking and verification
   - Atomic operations with rollback

6. **Power Management**
   - CPU frequency governor optimization
   - Battery status monitoring
   - Thermal throttling detection
   - Power state verification

## Installation

### Dependencies
```bash
# Core dependencies
sudo apt install zfsutils-linux

# Monitoring tools
sudo apt install sysstat lm-sensors linux-tools-common

# Security tools
sudo apt install apparmor-utils selinux-utils

# Network monitoring
sudo apt install nethogs iperf3

# Debug tools
sudo apt install strace lsof

# Resource monitoring
sudo apt install numactl bc
```

### Installation from Package
```bash
sudo dpkg -i zfs-swap-manager_1.0.0_all.deb
```

### Manual Installation
```bash
sudo cp create_swap_partition.sh /usr/sbin/zfs-swap-manager
sudo chmod 755 /usr/sbin/zfs-swap-manager
sudo cp man/zfs-swap-manager.8 /usr/share/man/man8/
sudo mandb
```

## Usage

### Basic Usage
```bash
sudo zfs-swap-manager 16G  # Create 16GB swap
```

### Advanced Options
```bash
# Dry run - show what would happen
sudo zfs-swap-manager --dry-run 32G

# Use specific pool
sudo zfs-swap-manager -p mypool 8G

# Test mode with minimal impact
sudo zfs-swap-manager --test

# Dry run with custom pool
sudo zfs-swap-manager -d -p tank 32G
```

## Monitoring and Logs

All operations are logged to the following locations:

- Main log: `/var/tmp/swap_setup_<timestamp>/logs/setup.log`
- Resource monitoring: `/var/tmp/swap_setup_<timestamp>/logs/resources.log`
- Transaction log: `/var/tmp/swap_setup_<timestamp>/logs/transactions.log`
- System calls: `/var/tmp/swap_setup_<timestamp>/traces/syscalls.log`
- Performance data: `/var/tmp/swap_setup_<timestamp>/profile/`
- Error reports: `/var/tmp/swap_setup_<timestamp>/errors/`

## Recovery

In case of failure:

1. Emergency recovery script is created at `/tmp/emergency_recovery_<timestamp>.sh`
2. Original system state is preserved in ZFS snapshots
3. All operations are logged and can be rolled back
4. Backups of critical files are maintained
5. Transaction log provides detailed operation history

## Safety Features

### Pre-flight Checks
- System health verification
- Resource availability checks
- Security context validation
- Power management status
- Network resilience verification

### Runtime Protection
- Transaction-based operations
- Automatic rollback on failure
- Resource monitoring and management
- Emergency recovery script generation
- State tracking and verification

### Post-operation Verification
- Systemd service status validation
- Current swap status verification
- FSTAB entry validation
- ZFS property verification
- Service enablement checks
- Device activation verification
- Comprehensive state validation

## Validation Checks

The tool performs extensive validation after setup:

1. **Service Validation**
   - Systemd service status
   - Service enablement state
   - Service dependencies
   - Service configuration

2. **Swap Configuration**
   - Active swap devices
   - Swap priorities
   - Device paths
   - UUID consistency

3. **ZFS Properties**
   - Mountpoint configuration
   - Compression settings
   - Cache settings
   - Sync mode
   - Log bias
   - Snapshot settings

4. **Persistence Verification**
   - FSTAB entries
   - Systemd unit files
   - Udev rules
   - ZFS cache
   - Boot configuration

## Best Practices

1. Always run with `--dry-run` first
2. Use test mode for initial validation
3. Monitor system resources during operation
4. Keep emergency recovery script until stability is confirmed
5. Review logs after operation completion

## Troubleshooting

Common issues and solutions:

1. **High System Load**
   - Script provides interactive load management
   - Options to adjust process priorities
   - Ability to wait for load reduction

2. **Memory Pressure**
   - Automatic memory pressure detection
   - Interactive memory management options
   - ZFS ARC size optimization

3. **Device Creation Issues**
   - Automatic retry with timeout
   - Detailed error reporting
   - Recovery script generation

4. **Network Issues**
   - Network resilience checking
   - Performance impact monitoring
   - Interactive resolution options

## License

MIT License

## Author

Eduardo Aguilar Pelaez <eduardo@aguilar-pelaez.co.uk>

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 