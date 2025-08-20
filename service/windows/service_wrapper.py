#!/usr/bin/env python3
"""
Windows Service Wrapper for Postman SAML Enforcer
Handles Windows Service lifecycle and manages the daemon process.
"""

import sys
import os
import time
import logging
import subprocess
import threading
from pathlib import Path

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
except ImportError:
    print("pywin32 package required. Install with: pip install pywin32")
    sys.exit(1)

# Configure logging for Windows Event Log
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('C:\\ProgramData\\Postman\\saml-enforcer-service.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('PostmanSAMLService')


class PostmanSAMLService(win32serviceutil.ServiceFramework):
    """Windows Service wrapper for Postman SAML Enforcer daemon."""
    
    _svc_name_ = "PostmanSAMLEnforcer"
    _svc_display_name_ = "Postman SAML Enforcer"
    _svc_description_ = "Enterprise SAML enforcement daemon for Postman Desktop applications"
    
    def __init__(self, args):
        """Initialize the service."""
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.running = True
        self.daemon_process = None
        self.monitor_thread = None
        
        # Service configuration
        self.service_path = Path("C:/Program Files/Postman SAML Enforcer")
        self.script_path = self.service_path / "src" / "saml_enforcer.py"
        
        logger.info("Postman SAML Enforcer service initialized")
    
    def SvcStop(self):
        """Handle service stop request."""
        logger.info("Service stop requested")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        
        # Signal stop event
        win32event.SetEvent(self.hWaitStop)
        self.running = False
        
        # Stop daemon process
        self._stop_daemon()
        
        # Note: Daemon handles hosts file cleanup automatically via signal handlers
        
        logger.info("Service stopped")
    
    def SvcDoRun(self):
        """Main service execution."""
        logger.info("Starting Postman SAML Enforcer service")
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        
        try:
            # Note: Daemon now handles certificate generation, hosts file management, and health checking internally
            self._start_daemon()
            self._monitor_daemon()
            
        except Exception as e:
            logger.error(f"Service error: {e}")
            servicemanager.LogErrorMsg(f"Service error: {e}")
        
        # Wait for stop signal
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
        logger.info("Service main loop ended")
    
    def _start_daemon(self):
        """Start the Python daemon process."""
        logger.info("Starting daemon process")
        
        try:
            # Start the Python daemon
            self.daemon_process = subprocess.Popen(
                [sys.executable, str(self.script_path)],
                cwd=self.service_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )
            
            # Give daemon time to start
            time.sleep(3)
            
            # Check if process is still running
            if self.daemon_process.poll() is None:
                logger.info(f"Daemon started successfully (PID: {self.daemon_process.pid})")
            else:
                stdout, stderr = self.daemon_process.communicate()
                logger.error(f"Daemon failed to start: {stderr.decode()}")
                raise RuntimeError("Daemon process failed to start")
                
        except Exception as e:
            logger.error(f"Failed to start daemon: {e}")
            raise
    
    def _stop_daemon(self):
        """Stop the daemon process."""
        if self.daemon_process and self.daemon_process.poll() is None:
            logger.info("Stopping daemon process")
            try:
                self.daemon_process.terminate()
                # Wait up to 10 seconds for graceful shutdown
                try:
                    self.daemon_process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    logger.warning("Daemon didn't stop gracefully, forcing kill")
                    self.daemon_process.kill()
                
                logger.info("Daemon process stopped")
            except Exception as e:
                logger.error(f"Error stopping daemon: {e}")
    
    def _monitor_daemon(self):
        """Monitor daemon process and restart if needed."""
        logger.info("Starting daemon monitoring")
        
        self.monitor_thread = threading.Thread(target=self._daemon_monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def _daemon_monitor_loop(self):
        """Monitor loop for daemon process health."""
        restart_count = 0
        max_restarts = 5
        restart_window = 300  # 5 minutes
        last_restart = 0
        
        while self.running:
            try:
                # Check if daemon process is still running
                if self.daemon_process and self.daemon_process.poll() is not None:
                    current_time = time.time()
                    
                    # Reset restart counter if enough time has passed
                    if current_time - last_restart > restart_window:
                        restart_count = 0
                    
                    if restart_count < max_restarts:
                        logger.warning(f"Daemon process died, restarting (attempt {restart_count + 1})")
                        
                        try:
                            self._start_daemon()
                            restart_count += 1
                            last_restart = current_time
                        except Exception as e:
                            logger.error(f"Failed to restart daemon: {e}")
                            restart_count += 1
                    else:
                        logger.error("Maximum restart attempts reached, stopping service")
                        self.SvcStop()
                        break
                
                # Sleep before next check
                time.sleep(10)
                
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
                time.sleep(30)


def main():
    """Main entry point for service management."""
    if len(sys.argv) == 1:
        # Run as service
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(PostmanSAMLService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # Handle command line arguments
        win32serviceutil.HandleCommandLine(PostmanSAMLService)


if __name__ == '__main__':
    main()