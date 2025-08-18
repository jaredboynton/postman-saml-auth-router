#!/usr/bin/env python3
"""Dynamic hosts file management for Postman SAML Enforcement.

This module provides runtime manipulation of /etc/hosts entries as an
alternative deployment strategy for environments where static entries
are not viable. This approach is used by enterprise security solutions
like CrowdStrike and Microsoft Defender.

Note: This is an advanced feature for specialized deployments.
Most production environments should use static hosts entries.
"""

import os
import logging
import subprocess
from typing import Optional

logger = logging.getLogger('postman-auth')


class HostsManager:
    """Manages dynamic modifications to /etc/hosts file.
    
    This class provides safe methods for adding and removing hosts
    entries dynamically based on authentication flow state.
    """
    
    MANAGED_MARKER = "# Managed by Postman Auth Daemon"
    
    def __init__(self, hosts_file: str = "/etc/hosts"):
        """Initialize hosts manager.
        
        Args:
            hosts_file: Path to hosts file
        """
        self.hosts_file = hosts_file
        self.backup_file = f"{hosts_file}.postman-backup"
        
        # Create backup on first use
        if not os.path.exists(self.backup_file):
            self._create_backup()
    
    def _create_backup(self) -> None:
        """Create backup of hosts file."""
        try:
            subprocess.run(['cp', self.hosts_file, self.backup_file], check=True)
            logger.info(f"Created hosts backup: {self.backup_file}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to backup hosts file: {e}")
    
    def add_entry(self, ip: str, hostname: str) -> bool:
        """Add a hosts entry.
        
        Args:
            ip: IP address to map to
            hostname: Hostname to map
            
        Returns:
            True if successful, False otherwise
        """
        entry = f"{ip} {hostname} {self.MANAGED_MARKER}"
        
        try:
            # Check if entry already exists
            with open(self.hosts_file, 'r') as f:
                if hostname in f.read():
                    logger.debug(f"Entry already exists for {hostname}")
                    return True
            
            # Add entry
            with open(self.hosts_file, 'a') as f:
                f.write(f"\n{entry}")
            
            logger.info(f"Added hosts entry: {hostname} -> {ip}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add hosts entry: {e}")
            return False
    
    def remove_entry(self, hostname: str) -> bool:
        """Remove a hosts entry.
        
        Args:
            hostname: Hostname to remove
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Read all lines
            with open(self.hosts_file, 'r') as f:
                lines = f.readlines()
            
            # Filter out lines with our hostname and marker
            filtered_lines = [
                line for line in lines
                if not (hostname in line and self.MANAGED_MARKER in line)
            ]
            
            # Write back
            with open(self.hosts_file, 'w') as f:
                f.writelines(filtered_lines)
            
            logger.info(f"Removed hosts entry for {hostname}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove hosts entry: {e}")
            return False
    
    def cleanup_all(self) -> None:
        """Remove all managed entries from hosts file."""
        try:
            # Read all lines
            with open(self.hosts_file, 'r') as f:
                lines = f.readlines()
            
            # Filter out lines with our marker
            filtered_lines = [
                line for line in lines
                if self.MANAGED_MARKER not in line
            ]
            
            # Write back
            with open(self.hosts_file, 'w') as f:
                f.writelines(filtered_lines)
            
            logger.info("Cleaned up all managed hosts entries")
        except Exception as e:
            logger.error(f"Failed to cleanup hosts entries: {e}")