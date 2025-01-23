#!/bin/bash

# Exit on error, undefined variables, and print commands
set -euxo pipefail

# Configuration
PACKAGE_NAME="zfs-swap-manager"
PACKAGE_VERSION="1.0.0"
MAINTAINER_NAME="Eduardo Aguilar Pelaez"
MAINTAINER_EMAIL="eduardo@aguilar-pelaez.co.uk"
FULL_VERSION="${PACKAGE_VERSION}"
BUILD_FOR_DEBIAN=0  # Default to Ubuntu-only builds

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log_error "Required command '$1' not found. Installing..."
        sudo apt-get update && sudo apt-get install -y "$2"
    fi
}

# Check and install required tools
install_dependencies() {
    log_info "Installing required packages..."
    
    # List of required packages with their package names
    declare -A REQUIRED_TOOLS=(
        ["debuild"]="devscripts"
        ["dput"]="dput"
        ["lintian"]="lintian"
        ["pbuilder"]="pbuilder"
        ["sbuild"]="sbuild"
        ["reportbug"]="reportbug"
        ["gpg"]="gnupg"
        ["dch"]="devscripts"
        ["mk-sbuild"]="ubuntu-dev-tools"
        ["ubuntu-bug"]="apport"
    )
    
    # Ensure ubuntu-dev-tools is installed
    if ! dpkg -l | grep -q "ubuntu-dev-tools"; then
        log_info "Installing ubuntu-dev-tools..."
        sudo apt-get update && sudo apt-get install -y ubuntu-dev-tools
    fi
    
    # First, check what's missing
    local missing_packages=()
    for cmd in "${!REQUIRED_TOOLS[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_packages+=("${REQUIRED_TOOLS[$cmd]}")
        fi
    done
    
    # If there are missing packages, install them all at once
    if [ ${#missing_packages[@]} -gt 0 ]; then
        log_info "Installing missing packages: ${missing_packages[*]}"
        
        # Backup and disable third-party repositories
        local sources_dir="/etc/apt/sources.list.d"
        local backup_dir="/tmp/sources.backup.$$"
        
        if [ -d "$sources_dir" ] && [ "$(ls -A $sources_dir)" ]; then
            log_info "Temporarily disabling third-party repositories..."
            mkdir -p "$backup_dir"
            sudo mv "$sources_dir"/* "$backup_dir/" 2>/dev/null || true
        fi
        
        # Update and install using only official repositories
        if ! sudo apt-get update -o Dir::Etc::sourcelist="sources.list" -o Dir::Etc::sourceparts="-" && \
             sudo apt-get install -y "${missing_packages[@]}"; then
            # Restore repositories on failure
            if [ -d "$backup_dir" ] && [ "$(ls -A $backup_dir)" ]; then
                sudo mv "$backup_dir"/* "$sources_dir/"
                rm -rf "$backup_dir"
            fi
            log_error "Failed to install required packages. Please check your network connection and package sources."
            exit 1
        fi
        
        # Restore repositories
        if [ -d "$backup_dir" ] && [ "$(ls -A $backup_dir)" ]; then
            sudo mv "$backup_dir"/* "$sources_dir/"
            rm -rf "$backup_dir"
        fi
    else
        log_info "All required packages are already installed"
    fi
}

# Set up reportbug for Debian
setup_reportbug() {
    log_info "Setting up reportbug for Debian..."
    
    if [ ! -f "$HOME/.reportbugrc" ]; then
        cat > "$HOME/.reportbugrc" << EOF
# Configuration for reportbug
bts debian
email ${MAINTAINER_EMAIL}
realname "${MAINTAINER_NAME}"
# Use HTTPS for communication with BTS
secure yes
# Include package version in subject
subject-include-version yes
# Don't query maintainer
query-maintainer no
# Don't check if the bug is being reassigned to the right package
check-available no
EOF
    fi
}

# Set up build environments
setup_build_environments() {
    log_info "Setting up build environments..."
    
    # Get Ubuntu codename
    UBUNTU_CODENAME=$(lsb_release -cs)
    
    # Set up sbuild for Ubuntu
    if ! id -nG "$USER" | grep -qw "sbuild"; then
        log_info "Adding user to sbuild group..."
        sudo sbuild-adduser "$USER"
        # Copy example sbuildrc if it doesn't exist
        if [ ! -f "$HOME/.sbuildrc" ]; then
            cp /usr/share/doc/sbuild/examples/example.sbuildrc "$HOME/.sbuildrc"
        fi
        log_warn "Please run 'newgrp sbuild' or log out and back in to use sbuild"
        exit 1
    fi
    
    # Install required packages for sbuild
    log_info "Installing required packages for sbuild..."
    sudo apt-get update
    sudo apt-get install -y ubuntu-dev-tools sbuild schroot debootstrap
    
    # Create sbuild environment for Ubuntu
    if ! schroot -l | grep -q "sbuild-${UBUNTU_CODENAME}"; then
        log_info "Creating sbuild environment for Ubuntu ${UBUNTU_CODENAME}..."
        
        # Create .mk-sbuild.rc if it doesn't exist
        if [ ! -f "$HOME/.mk-sbuild.rc" ]; then
            cat > "$HOME/.mk-sbuild.rc" << EOF
SOURCE_CHROOTS_DIR="/srv/chroot"
DEBOOTSTRAP_MIRROR="http://archive.ubuntu.com/ubuntu"
SKIP_UPDATES="no"
SKIP_PROPOSED="yes"
SKIP_SECURITY="no"
EOF
        fi
        
        # Ensure directories exist with correct permissions
        sudo mkdir -p /srv/chroot
        sudo chown root:sbuild /srv/chroot
        sudo chmod 2775 /srv/chroot
        
        # Create the build environment with explicit options
        sudo mk-sbuild --arch=amd64 --name="${UBUNTU_CODENAME}" "${UBUNTU_CODENAME}"
        
        # Update the chroot
        sudo sbuild-update -udcar "${UBUNTU_CODENAME}"
    fi
    
    # Only set up Debian environment if requested and repository is configured
    if [ "$BUILD_FOR_DEBIAN" -eq 1 ]; then
        if [ -f "/etc/apt/sources.list.d/debian.list" ]; then
            log_info "Debian repositories found, setting up pbuilder for Debian..."
            
            # Ensure pbuilder is installed
            if ! dpkg -l | grep -q "pbuilder"; then
                log_info "Installing pbuilder..."
                sudo apt-get update && sudo apt-get install -y pbuilder
            fi
            
            # Set up pbuilder for Debian Sid
            if [ ! -f "$HOME/.pbuilderrc" ]; then
                cat > "$HOME/.pbuilderrc" << EOF
MIRRORSITE=http://deb.debian.org/debian
COMPONENTS="main contrib non-free"
NAME=sid
DISTRIBUTION=sid
DEBOOTSTRAPOPTS=("--variant=buildd" "--keyring=/usr/share/keyrings/debian-archive-keyring.gpg")
EOF
            fi
            
            # Create Debian Sid pbuilder environment if it doesn't exist
            if [ ! -d "/var/cache/pbuilder/base.tgz" ]; then
                log_info "Creating pbuilder environment for Debian Sid..."
                sudo pbuilder create --distribution sid --debootstrapopts --variant=buildd
            fi
        else
            log_warn "Debian repositories not found, cannot set up Debian build environment"
            BUILD_FOR_DEBIAN=0
        fi
    fi
}

# Run Lintian checks
run_lintian_checks() {
    log_info "Running Lintian checks..."
    
    local changes_file="../${PACKAGE_NAME}_${FULL_VERSION}_source.changes"
    
    if [ -f "$changes_file" ]; then
        lintian -I --pedantic "$changes_file" || {
            log_warn "Lintian found issues. Please review them."
            return 1
        }
    else
        log_error "Changes file not found: $changes_file"
        return 1
    fi
}

# Build source package
build_source_package() {
    log_info "Building source package..."
    
    # Update changelog if needed
    if [ ! -f "debian/changelog" ]; then
        dch --create --package "$PACKAGE_NAME" --version "$FULL_VERSION" "Initial release."
    fi
    
    # Build source package
    debuild -S -sa || {
        log_error "Failed to build source package"
        return 1
    }
}

# Test package builds
test_package_builds() {
    log_info "Testing package builds..."
    
    local dsc_file="../${PACKAGE_NAME}_${FULL_VERSION}.dsc"
    
    # Test with sbuild (Ubuntu)
    log_info "Testing build with sbuild (Ubuntu)..."
    sbuild -d "${UBUNTU_CODENAME}" "$dsc_file" || {
        log_error "sbuild build failed"
        return 1
    }
    
    # Only test Debian build if enabled and configured
    if [ "$BUILD_FOR_DEBIAN" -eq 1 ] && [ -f "$HOME/.pbuilderrc" ] && [ -d "/var/cache/pbuilder/base.tgz" ]; then
        log_info "Testing build with pbuilder (Debian Sid)..."
        sudo pbuilder build "$dsc_file" || {
            log_error "pbuilder build failed"
            return 1
        }
    fi
}

# Prepare mentors.debian.net upload
prepare_mentors_upload() {
    log_info "Preparing mentors.debian.net upload..."
    
    # Create dput configuration for mentors if it doesn't exist
    if [ ! -f "$HOME/.dput.cf" ]; then
        cat > "$HOME/.dput.cf" << EOF
[mentors]
fqdn = mentors.debian.net
incoming = /upload
method = https
allow_unsigned_uploads = 0
progress_indicator = 2
# Allow uploads for new packages (not yet in the archive)
allow_dcut = 0
EOF
    fi
    
    log_info "Ready to upload to mentors.debian.net"
    log_info "Use: dput mentors ${PACKAGE_NAME}_${FULL_VERSION}_source.changes"
}

# Create ITP bug report template
create_itp_template() {
    local template_file="itp_bug_template.txt"
    cat > "$template_file" << EOF
Package: wnpp
Severity: wishlist
Owner: ${MAINTAINER_NAME} <${MAINTAINER_EMAIL}>
Subject: ITP: ${PACKAGE_NAME} -- Advanced ZFS swap volume manager with safety features

* Package name    : ${PACKAGE_NAME}
* Version        : ${PACKAGE_VERSION}
* Upstream Author: ${MAINTAINER_NAME} <${MAINTAINER_EMAIL}>
* URL            : https://github.com/edu-ap/zfs-swap-manager
* License        : MIT
* Description    : Advanced ZFS swap volume manager with safety features

  A comprehensive tool for creating and managing ZFS-based swap volumes
  with advanced safety features, monitoring capabilities, and automatic
  recovery mechanisms.
  
  Features:
   * System health monitoring (CPU, memory, IO, network)
   * Resource management (ZFS ARC, IO scheduler, process priorities)
   * Security features (SELinux/AppArmor, process verification)
   * Monitoring and debugging (system calls, performance profiling)
   * Backup and recovery (snapshots, transaction rollback)
   * Power management (CPU governor, thermal monitoring)

  The tool ensures optimal swap configuration with proper ZFS properties
  and maintains system stability during the process through extensive
  safety checks and monitoring.

I intend to package ${PACKAGE_NAME} for Debian. I will maintain it myself.
EOF
    
    log_info "Created ITP bug template at: $template_file"
    log_info "Review the template and submit using: reportbug -B debian --template=$template_file wnpp"
}

# Create Ubuntu needs-packaging bug template
create_ubuntu_bug_template() {
    local template_file="ubuntu_bug_template.txt"
    cat > "$template_file" << EOF
[Impact]
The package provides advanced ZFS swap management capabilities for Ubuntu systems.

[Test Case]
1. Install the package
2. Create a ZFS-based swap volume
3. Verify swap is properly configured
4. Test monitoring and safety features

[Regression Potential]
Low - The package does not modify any existing system configuration without explicit user action.

[Other Info]
Debian ITP: <link to your Debian ITP bug>
Homepage: https://github.com/edu-ap/zfs-swap-manager
EOF
    
    log_info "Created Ubuntu needs-packaging bug template at: $template_file"
    log_info "Review the template and submit using: ubuntu-bug ubuntu"
    log_info "Copy the template content when filing the bug"
}

# Generate original tarball
generate_orig_tarball() {
    log_info "Generating original tarball..."
    
    # Create a clean copy of the source without debian/ directory and VCS files
    local temp_dir=$(mktemp -d)
    cp -r . "$temp_dir/"
    rm -rf "$temp_dir/debian" "$temp_dir/.git" "$temp_dir/.gitignore" 2>/dev/null || true
    
    # Generate the tarball using absolute paths
    ORIG_TARBALL="${PWD}/../${PACKAGE_NAME}_${PACKAGE_VERSION}.orig.tar.gz"
    (cd "$temp_dir" && tar czf "$ORIG_TARBALL" *)
    
    # Cleanup
    rm -rf "$temp_dir"
    
    log_info "Original tarball generated: $ORIG_TARBALL"
}

# Main execution
main() {
    # Parse command line arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --debian)
                BUILD_FOR_DEBIAN=1
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Usage: $0 [--debian]"
                exit 1
                ;;
        esac
    done

    log_info "Starting package submission preparation for ${PACKAGE_NAME} ${FULL_VERSION}"
    if [ "$BUILD_FOR_DEBIAN" -eq 1 ]; then
        log_info "Building for both Ubuntu and Debian"
    else
        log_info "Building for Ubuntu only"
    fi
    
    # Set up the original tarball path
    ORIG_TARBALL="../${PACKAGE_NAME}_${PACKAGE_VERSION}.orig.tar.gz"
    
    # Generate original tarball first
    generate_orig_tarball
    
    # Create temporary work directory and its parent for the orig tarball
    WORK_DIR=$(mktemp -d)
    PARENT_DIR="$(dirname "$WORK_DIR")/orig-tarballs"
    mkdir -p "$PARENT_DIR"
    trap 'rm -rf "$WORK_DIR" "$PARENT_DIR"' EXIT
    
    # Copy source files to work directory
    cp -r . "$WORK_DIR"
    
    # Copy the tarball to the temporary parent directory
    cp "$ORIG_TARBALL" "$PARENT_DIR/"
    
    # Change to work directory
    cd "$WORK_DIR"
    
    # Remove existing symlink if it exists and create a new one
    SYMLINK="../$(basename "$ORIG_TARBALL")"
    rm -f "$SYMLINK"
    ln -s "$PARENT_DIR/$(basename "$ORIG_TARBALL")" "$SYMLINK"
    
    # Run all steps
    install_dependencies || exit 1
    setup_reportbug || exit 1
    setup_build_environments || exit 1
    build_source_package || exit 1
    run_lintian_checks || exit 1
    test_package_builds || exit 1
    prepare_mentors_upload || exit 1
    create_itp_template || exit 1
    create_ubuntu_bug_template || exit 1
    
    log_info "Package submission preparation completed successfully!"
    log_info "Next steps:"
    echo "1. Review and submit Debian ITP bug:"
    echo "   reportbug -B debian --template=itp_bug_template.txt wnpp"
    echo
    echo "2. Upload to mentors.debian.net:"
    echo "   dput mentors ${PACKAGE_NAME}_${FULL_VERSION}_source.changes"
    echo
    echo "3. Post to debian-mentors mailing list"
    echo
    echo "4. File Ubuntu needs-packaging bug:"
    echo "   ubuntu-bug ubuntu"
    echo "   (Use content from ubuntu_bug_template.txt when filing)"
}

# Run main function
main "$@" 