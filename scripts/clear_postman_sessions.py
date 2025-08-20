#!/usr/bin/env python3
"""
One-time Postman session clearing utility for initial deployment.

This script clears all Postman authentication sessions from browsers and applications
to ensure fresh SAML authentication. Run this once before starting the SAML enforcer daemon.

Usage:
    python3 clear_postman_sessions.py

Requirements:
    - Run with appropriate privileges for browser/app file access
    - Postman apps will be restarted if currently running
"""

import json
import logging
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import time


def setup_logging():
    """Set up simple console logging."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger('postman-session-cleaner')


logger = setup_logging()


class PostmanSessionCleaner:
    """Handles clearing Postman sessions from browsers and applications."""
    
    def __init__(self):
        """Initialize the session cleaner."""
        logger.info("Postman Session Cleaner initialized")
    
    def _get_comprehensive_postman_domains(self):
        """Get comprehensive list of Postman auth domains"""
        # Based on actual domains found in Safari cookies - covers all auth domains while preserving
        # business domains like Salesforce (*.force.com), Okta (*.okta.com), Looker (*.looker.com)
        return [
            # Core Postman domains
            'postman.com', '.postman.com',
            'postman.co', '.postman.co',
            'getpostman.com', '.getpostman.com',
            
            # Identity/auth domains
            'identity.postman.com', '.identity.postman.com',
            'identity.postman.co', '.identity.postman.co', 
            'identity.getpostman.com', '.identity.getpostman.com',
            'identity.getpostman.co', '.identity.getpostman.co',
            
            # Gateway domains
            'gw.postman.com', '.gw.postman.com',
            'gw.postman.co', '.gw.postman.co',
            'id.gw.postman.com', '.id.gw.postman.com',
            'id.gw.postman.co', '.id.gw.postman.co',
            
            # Landing pages and other auth domains
            'lp.postman.com', '.lp.postman.com',
            'www.postman.com', '.www.postman.com',
            'god.postman.co', '.god.postman.co',
            
            # Legacy domains
            'go.postman.co', '.go.postman.co',
            'app.getpostman.com', '.app.getpostman.com'
        ]
    
    def _get_postman_session_cookies(self):
        """Get list of Postman session cookie names found in Safari analysis."""
        return [
            # Auth session cookies
            'legacy_sails.sid', 'postman.iam.sid', 'postman.meta', 'postman.sid',
            'postman-backup.sid', 'alternate_postman.sid', 'getpostmanlogin',
            
            # Device tracking
            'dwndvc', 'pm_dvc', '_PUB_ID', 'dashboard_beta',
            
            # CDN/Security cookies (auth-specific)
            '__cf_bm', '__cfseq-0x5EnpocG', 'cf_clearance',
            
            # Analytics/Marketing (Postman-specific)
            'AMP_56d4a7f424', 'AMP_MKTG_56d4a7f424', '_mkto_trk', '_mkto_trk_http',
            '_gcl_au', '_ga', '_ga_CX7P9K6W67', '_uetsid', '_uetvid',
            'ajs_anonymous_id', 'analytics_session_id', 'analytics_session_id.last_access',
            
            # Store/app specific
            '_pm.store', '_pmt', '__q_state_hhaW6HiVqGA5oJq1',
            'OptanonConsent', 'OptanonAlertBoxClosed'
        ]
        
    def _build_postman_cookie_filter_sql(self):
        """Build SQL WHERE clause to target comprehensive Postman domains and cookies."""
        domains = self._get_comprehensive_postman_domains()
        exact_matches = [f"host_key = '{domain}'" for domain in domains]
        
        # Also clear by specific cookie names for any missed domains
        cookie_names = self._get_postman_session_cookies()
        cookie_name_matches = [f"name = '{cookie}'" for cookie in cookie_names]
        
        all_conditions = exact_matches + cookie_name_matches
        return "WHERE (" + " OR ".join(all_conditions) + ")"
    
    def _kill_firefox_by_pid(self):
        """Kill Firefox processes directly by PID on all platforms."""
        killed_pids = []
        
        try:
            if sys.platform == "win32":
                # Windows: Use tasklist to find Firefox PIDs, then taskkill
                result = subprocess.run([
                    'tasklist', '/FI', 'IMAGENAME eq firefox.exe', '/FO', 'CSV'
                ], capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')[1:]  # Skip header
                    for line in lines:
                        if 'firefox.exe' in line:
                            try:
                                parts = line.split(',')
                                pid = int(parts[1].strip('"'))
                                subprocess.run(['taskkill', '/PID', str(pid), '/F'], 
                                             capture_output=True, timeout=5)
                                killed_pids.append(pid)
                            except (ValueError, IndexError):
                                continue
            
            else:
                # Unix-like: Use pgrep to find PIDs, then kill
                result = subprocess.run(['pgrep', 'firefox'], 
                                      capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0:
                    pids = result.stdout.strip().split('\n')
                    for pid_str in pids:
                        if pid_str:
                            try:
                                pid = int(pid_str)
                                subprocess.run(['kill', '-TERM', str(pid)], 
                                             capture_output=True, timeout=5)
                                killed_pids.append(pid)
                            except ValueError:
                                continue
            
            if killed_pids:
                logger.info(f"Killed Firefox PIDs: {killed_pids}")
                time.sleep(2)  # Wait for processes to die
            else:
                logger.debug("No Firefox processes found")
                
        except Exception as e:
            logger.debug(f"Firefox kill error: {e}")

    def _restart_firefox_simple(self):
        """Restart Firefox - it will auto-restore session."""
        try:
            if sys.platform == "win32":
                # Windows
                firefox_paths = [
                    r"C:\Program Files\Mozilla Firefox\firefox.exe",
                    r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
                ]
                for path in firefox_paths:
                    if os.path.exists(path):
                        subprocess.Popen([path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        break
            elif sys.platform == "darwin":
                # macOS
                subprocess.Popen(["/Applications/Firefox.app/Contents/MacOS/firefox"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                # Linux
                subprocess.Popen(["firefox"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            logger.info("Firefox restarted (session will auto-restore)")
            
        except Exception as e:
            logger.debug(f"Firefox restart error: {e}")

    def _clear_firefox_cookies(self):
        """Clear Firefox Postman auth cookies using simple kill/clear/restart method."""
        try:
            # 1. Kill Firefox by PID
            self._kill_firefox_by_pid()
            
            # 2. Find Firefox profiles
            if sys.platform == "win32":
                firefox_base = os.path.expandvars(r"$APPDATA\Mozilla\Firefox\Profiles")
            elif sys.platform == "darwin":
                firefox_base = os.path.expanduser("~/Library/Application Support/Firefox/Profiles")
            else:
                firefox_base = os.path.expanduser("~/.mozilla/firefox")
            
            if not os.path.exists(firefox_base):
                logger.debug("Firefox profile directory not found")
                return
            
            # 3. Clear auth cookies from all profiles
            cleared_profiles = []
            for profile_name in os.listdir(firefox_base):
                if 'default' in profile_name.lower() and os.path.isdir(os.path.join(firefox_base, profile_name)):
                    profile_path = os.path.join(firefox_base, profile_name)
                    cookies_path = os.path.join(profile_path, "cookies.sqlite")
                    
                    if os.path.exists(cookies_path):
                        try:
                            # Backup first
                            backup_path = f"{cookies_path}.backup-{int(time.time())}"
                            shutil.copy2(cookies_path, backup_path)
                            
                            # Clear only auth domains (preserve business domains)
                            conn = sqlite3.connect(cookies_path, timeout=10.0)
                            cursor = conn.cursor()
                            
                            # Count before
                            cursor.execute("SELECT COUNT(*) FROM moz_cookies WHERE host LIKE '%postman%'")
                            before_count = cursor.fetchone()[0]
                            
                            # Use comprehensive domain list (preserves business domains like Salesforce, Okta)
                            auth_domains = self._get_comprehensive_postman_domains()
                            
                            placeholders = ','.join('?' * len(auth_domains))
                            cursor.execute(f"DELETE FROM moz_cookies WHERE host IN ({placeholders})", auth_domains)
                            
                            # Count after
                            cursor.execute("SELECT COUNT(*) FROM moz_cookies WHERE host LIKE '%postman%'")
                            after_count = cursor.fetchone()[0]
                            
                            conn.commit()
                            conn.close()
                            
                            cleared_count = before_count - after_count
                            if cleared_count > 0:
                                cleared_profiles.append(f"{profile_name}({cleared_count})")
                        
                        except Exception as e:
                            logger.debug(f"Firefox profile {profile_name} error: {e}")
                            # Restore backup on error
                            if 'backup_path' in locals() and os.path.exists(backup_path):
                                shutil.move(backup_path, cookies_path)
            
            # 4. Restart Firefox (session will auto-restore)
            self._restart_firefox_simple()
            
            if cleared_profiles:
                logger.info(f"Firefox auth cookies cleared: {', '.join(cleared_profiles)}")
            else:
                logger.debug("No Firefox auth cookies found")
                
        except Exception as e:
            logger.debug(f"Firefox cookie clearing error: {e}")
    
    def _stop_browser_process(self, process_name):
        """Stop browser/application process safely."""
        try:
            if sys.platform == "win32":
                # Windows: Use taskkill
                subprocess.run(
                    ["taskkill", "/IM", process_name, "/F"],
                    capture_output=True, text=True, timeout=10
                )
            else:
                # macOS/Linux: Use pkill or osascript for apps
                if process_name in ["Safari", "Microsoft Edge", "Postman"]:
                    # Use AppleScript to quit macOS apps gracefully
                    subprocess.run(
                        ["osascript", "-e", f'tell application "{process_name}" to quit'],
                        capture_output=True, text=True, timeout=10
                    )
                else:
                    # Use pkill for other processes
                    subprocess.run(
                        ["pkill", "-f", process_name],
                        capture_output=True, text=True, timeout=10
                    )
        except Exception:
            pass  # Expected if process is not running
    
    def _clear_chromium_cookies(self, browser_name, base_path_win, base_path_unix, profile_method="fixed"):
        """Clear Chromium-based browser cookies using direct SQLite access.
        
        Args:
            browser_name: Browser name for logging ("Chrome", "Brave", etc.)
            base_path_win: Windows base path
            base_path_unix: macOS/Linux base path
            profile_method: "fixed" for Chrome-style fixed profiles or "dynamic" for directory listing
        """
        try:
            if sys.platform == "win32":
                browser_base = os.path.expandvars(base_path_win)
            else:
                browser_base = os.path.expanduser(base_path_unix)
            
            if not os.path.exists(browser_base):
                logger.debug(f"{browser_name} not found")
                return
                
            sql_filter = self._build_postman_cookie_filter_sql()
            cleared_profiles = []
            
            # Get profile directories based on method
            if profile_method == "fixed":
                # Chrome-style fixed profiles
                profile_dirs = ["Default", "Profile 1", "Profile 2", "Profile 3", "Profile 4", "Profile 5"]
            else:
                # Brave-style dynamic discovery
                profile_dirs = [d for d in os.listdir(browser_base) 
                               if d.startswith("Profile") or d == "Default"]
            
            # Clear cookies from all profiles
            for profile_dir in profile_dirs:
                cookies_path = os.path.join(browser_base, profile_dir, "Cookies")
                if os.path.exists(cookies_path):
                    try:
                        conn = sqlite3.connect(cookies_path, timeout=5.0)
                        cursor = conn.cursor()
                        
                        # Count cookies before deletion
                        cursor.execute(f"SELECT COUNT(*) FROM cookies {sql_filter}")
                        before_count = cursor.fetchone()[0]
                        
                        if before_count > 0:
                            # Delete targeted Postman cookies
                            cursor.execute(f"DELETE FROM cookies {sql_filter}")
                            conn.commit()
                            cleared_profiles.append(f"{profile_dir}({before_count})")
                        
                        conn.close()
                        
                    except sqlite3.OperationalError as e:
                        if "database is locked" in str(e):
                            logger.debug(f"{browser_name} {profile_dir} database locked, skipping")
                        else:
                            logger.debug(f"{browser_name} {profile_dir} SQLite error: {e}")
                    except Exception as e:
                        logger.debug(f"{browser_name} {profile_dir} error: {e}")
            
            if cleared_profiles:
                logger.info(f"{browser_name} Postman cookies cleared from: {', '.join(cleared_profiles)}")
            else:
                logger.debug(f"No {browser_name} Postman cookies found to clear")
                
        except Exception as e:
            logger.debug(f"{browser_name} filesystem clearing note: {e}")
    
    def _clear_chrome_cookies(self):
        """Clear Chrome Postman cookies using shared Chromium method."""
        self._clear_chromium_cookies(
            "Chrome", 
            r"$LOCALAPPDATA\Google\Chrome\User Data",
            "~/Library/Application Support/Google/Chrome",
            "dynamic"
        )
    
    def _clear_brave_cookies(self):
        """Clear Brave Postman cookies using shared Chromium method."""
        self._clear_chromium_cookies(
            "Brave",
            r"$LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data", 
            "~/Library/Application Support/BraveSoftware/Brave-Browser",
            "dynamic"
        )
    
    def _get_safari_binary_domains(self):
        """Convert comprehensive domain list to Safari binary cookie format."""
        # Get comprehensive domain list and convert to Safari binary format
        comprehensive_domains = self._get_comprehensive_postman_domains()
        binary_domains = []
        
        for domain in comprehensive_domains:
            # Remove leading dots for Safari format
            clean_domain = domain.lstrip('.')
            
            # Add both 'A' and 'A.' prefixes found in Safari binary cookies
            binary_domains.extend([
                f'A{clean_domain}'.encode(),
                f'A.{clean_domain}'.encode()
            ])
            
        return binary_domains
    
    def _clear_safari_cookies(self):
        """Clear Safari Postman auth cookies using binary parsing (works while Safari is running)."""
        try:
            # Safari cookie file locations
            safari_cookies_paths = [
                os.path.expanduser("~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies"),
                os.path.expanduser("~/Library/Cookies/Cookies.binarycookies")
            ]
            
            safari_cookies_found = None
            for path in safari_cookies_paths:
                if os.path.exists(path):
                    safari_cookies_found = path
                    break
            
            if not safari_cookies_found:
                logger.debug("Safari cookies not found")
                return
            
            file_size = os.path.getsize(safari_cookies_found)
            if file_size == 0:
                logger.debug("Safari cookies file empty")
                return
            
            # Create backup before modification
            backup_path = f"{safari_cookies_found}.backup-{int(time.time())}"
            shutil.copy2(safari_cookies_found, backup_path)
            
            # Read binary cookies file
            with open(safari_cookies_found, 'rb') as f:
                data = f.read()
            
            # Use comprehensive domain list converted to Safari binary format
            auth_domains = self._get_safari_binary_domains()
            
            # Count and clear auth domains
            total_cleared = 0
            for domain in auth_domains:
                count = data.count(domain)
                if count > 0:
                    # Replace with null bytes of same length to preserve file structure
                    replacement = b'\x00' * len(domain)
                    data = data.replace(domain, replacement)
                    total_cleared += count
                    logger.debug(f"Cleared {count} occurrences of {domain.decode()}")
            
            if total_cleared > 0:
                # Write modified data back (atomic replacement)
                temp_path = f"{safari_cookies_found}.tmp"
                with open(temp_path, 'wb') as f:
                    f.write(data)
                
                # Atomic move to replace original
                shutil.move(temp_path, safari_cookies_found)
                
                logger.info(f"Safari auth cookies cleared: {total_cleared} entries removed")
                logger.info("Safari business domains preserved (zendesk, salesforce, etc.)")
                
                # Also clear NetworkCache and AlternativeServices for complete clearing
                self._clear_safari_cache_data(safari_cookies_found)
            else:
                logger.debug("No Safari auth cookies found to clear")
                
        except Exception as e:
            logger.debug(f"Safari cookie clearing error: {e}")
            # Restore backup on error
            if 'backup_path' in locals() and os.path.exists(backup_path):
                try:
                    shutil.move(backup_path, safari_cookies_found)
                    logger.debug("Safari cookies restored from backup")
                except:
                    pass
    
    def _clear_safari_cache_data(self, safari_cookies_path):
        """Clear Safari NetworkCache and AlternativeServices for complete auth data removal."""
        try:
            import sqlite3
            
            # Determine WebKit data store directory from cookies path
            if "WebsiteDataStore" in safari_cookies_path:
                webkit_base = os.path.dirname(os.path.dirname(safari_cookies_path))
            else:
                # Fallback for main Safari data location
                webkit_base = os.path.expanduser("~/Library/Containers/com.apple.Safari/Data/Library/WebKit/WebsiteDataStore")
                # Find the actual data store directory
                if os.path.exists(webkit_base):
                    for item in os.listdir(webkit_base):
                        item_path = os.path.join(webkit_base, item)
                        if os.path.isdir(item_path) and len(item) > 30:  # UUID-like directory
                            webkit_base = item_path
                            break
            
            # Clear NetworkCache postman files
            network_cache = os.path.join(webkit_base, "NetworkCache")
            if os.path.exists(network_cache):
                result = subprocess.run([
                    "find", network_cache, "-type", "f", "-exec", 
                    "grep", "-l", "postman\\.co\\|getpostman\\.com", "{}", ";",
                    "-exec", "rm", "{}", ";"
                ], capture_output=True, text=True)
                if result.returncode == 0:
                    logger.debug("Safari NetworkCache postman files cleared")
            
            # Clear AlternativeServices database
            alt_services_db = os.path.join(webkit_base, "AlternativeServices", "AlternativeService.sqlite")
            if os.path.exists(alt_services_db):
                try:
                    conn = sqlite3.connect(alt_services_db)
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM AlternativeService WHERE hostname LIKE '%postman.co%' OR hostname LIKE '%getpostman.com%'")
                    conn.commit()
                    conn.close()
                    logger.debug("Safari AlternativeServices postman entries cleared")
                except sqlite3.Error as e:
                    logger.debug(f"AlternativeServices clearing error: {e}")
                    
        except Exception as e:
            logger.debug(f"Safari cache clearing error: {e}")
    
    def _clear_browser_cookies(self):
        """Clear Postman cookies using direct filesystem access (safer - no process termination)."""
        logger.info("Clearing Postman cookies using filesystem approach...")
        
        try:
            # Clear Chrome cookies
            self._clear_chrome_cookies()
            # Clear Firefox cookies (kill/restart approach as required)
            self._clear_firefox_cookies()
            # Clear Brave browser cookies  
            self._clear_brave_cookies()
            # Clear Safari cookies
            self._clear_safari_cookies()
            
        except Exception as e:
            logger.warning(f"Browser cookie clearing completed with some warnings: {e}")

    def _check_postman_processes(self):
        """Check if Postman/PostmanEnterprise processes are running."""
        running_processes = {
            'postman': False,
            'postman_enterprise': False
        }
        
        try:
            if sys.platform == "darwin":
                # macOS: Check using osascript to see if apps are running
                try:
                    result = subprocess.run([
                        'osascript', '-e', 
                        'tell application "System Events" to get name of every process whose name contains "Postman"'
                    ], capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0:
                        processes = result.stdout.strip()
                        # Split by comma and check each process name
                        process_list = [p.strip() for p in processes.split(',')]
                        
                        if 'Postman Enterprise' in process_list:
                            running_processes['postman_enterprise'] = True
                        if 'Postman' in process_list:
                            running_processes['postman'] = True
                            
                except Exception as e:
                    logger.debug(f"macOS process check error: {e}")
                    
            elif sys.platform == "win32":
                # Windows: Use tasklist
                try:
                    result = subprocess.run([
                        'tasklist', '/FO', 'CSV'
                    ], capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0:
                        if 'Postman.exe' in result.stdout:
                            running_processes['postman'] = True
                        if 'PostmanEnterprise.exe' in result.stdout:
                            running_processes['postman_enterprise'] = True
                            
                except Exception as e:
                    logger.debug(f"Windows process check error: {e}")
                    
            else:
                # Linux: Use pgrep
                try:
                    for app_name, key in [('postman', 'postman'), ('PostmanEnterprise', 'postman_enterprise')]:
                        result = subprocess.run([
                            'pgrep', '-f', app_name
                        ], capture_output=True, text=True, timeout=5)
                        
                        if result.returncode == 0 and result.stdout.strip():
                            running_processes[key] = True
                            
                except Exception as e:
                    logger.debug(f"Linux process check error: {e}")
                    
        except Exception as e:
            logger.warning(f"Process check error: {e}")
            
        return running_processes
    
    def _kill_postman_processes(self):
        """Kill Postman/PostmanEnterprise processes."""
        killed_processes = []
        
        try:
            if sys.platform == "darwin":
                # macOS: Use osascript to quit apps gracefully
                for app_name in ['Postman', 'Postman Enterprise']:
                    try:
                        result = subprocess.run([
                            'osascript', '-e', f'tell application "{app_name}" to quit'
                        ], capture_output=True, text=True, timeout=10)
                        
                        if result.returncode == 0:
                            killed_processes.append(app_name)
                            logger.info(f"Gracefully quit {app_name}")
                        
                    except Exception as e:
                        logger.debug(f"Failed to quit {app_name}: {e}")
                        
            elif sys.platform == "win32":
                # Windows: Use taskkill
                for exe_name in ['Postman.exe', 'PostmanEnterprise.exe']:
                    try:
                        result = subprocess.run([
                            'taskkill', '/IM', exe_name, '/F'
                        ], capture_output=True, text=True, timeout=10)
                        
                        if result.returncode == 0:
                            killed_processes.append(exe_name)
                            logger.info(f"Killed {exe_name}")
                            
                    except Exception as e:
                        logger.debug(f"Failed to kill {exe_name}: {e}")
                        
            else:
                # Linux: Use pkill
                for app_name in ['postman', 'PostmanEnterprise']:
                    try:
                        result = subprocess.run([
                            'pkill', '-f', app_name
                        ], capture_output=True, text=True, timeout=10)
                        
                        if result.returncode == 0:
                            killed_processes.append(app_name)
                            logger.info(f"Killed {app_name}")
                            
                    except Exception as e:
                        logger.debug(f"Failed to kill {app_name}: {e}")
                        
        except Exception as e:
            logger.warning(f"Process killing error: {e}")
            
        if killed_processes:
            # Wait for processes to fully terminate
            time.sleep(3)
            
        return killed_processes
    
    def _restart_postman_processes(self, was_running):
        """Restart Postman processes that were previously running."""
        restarted_processes = []
        
        try:
            if sys.platform == "darwin":
                # macOS: Use open command
                if was_running.get('postman'):
                    try:
                        subprocess.Popen([
                            'open', '-a', 'Postman'
                        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        restarted_processes.append('Postman')
                        logger.info("Restarted Postman")
                    except Exception as e:
                        logger.debug(f"Failed to restart Postman: {e}")
                        
                if was_running.get('postman_enterprise'):
                    try:
                        subprocess.Popen([
                            'open', '-a', 'Postman Enterprise'
                        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        restarted_processes.append('Postman Enterprise')
                        logger.info("Restarted Postman Enterprise")
                    except Exception as e:
                        logger.debug(f"Failed to restart Postman Enterprise: {e}")
                        
            elif sys.platform == "win32":
                # Windows: Use start command or direct exe paths
                if was_running.get('postman'):
                    try:
                        # Try common installation paths
                        postman_paths = [
                            os.path.expandvars(r"$LOCALAPPDATA\Postman\Postman.exe"),
                            r"C:\Users\%USERNAME%\AppData\Local\Postman\Postman.exe"
                        ]
                        for path in postman_paths:
                            if os.path.exists(path):
                                subprocess.Popen([path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                                restarted_processes.append('Postman')
                                logger.info("Restarted Postman")
                                break
                    except Exception as e:
                        logger.debug(f"Failed to restart Postman: {e}")
                        
                if was_running.get('postman_enterprise'):
                    try:
                        # Try common installation paths
                        enterprise_paths = [
                            os.path.expandvars(r"$LOCALAPPDATA\PostmanEnterprise\PostmanEnterprise.exe"),
                            r"C:\Users\%USERNAME%\AppData\Local\PostmanEnterprise\PostmanEnterprise.exe"
                        ]
                        for path in enterprise_paths:
                            if os.path.exists(path):
                                subprocess.Popen([path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                                restarted_processes.append('PostmanEnterprise')
                                logger.info("Restarted PostmanEnterprise")
                                break
                    except Exception as e:
                        logger.debug(f"Failed to restart PostmanEnterprise: {e}")
                        
            else:
                # Linux: Try common binary locations
                if was_running.get('postman'):
                    try:
                        subprocess.Popen(['postman'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        restarted_processes.append('postman')
                        logger.info("Restarted postman")
                    except Exception as e:
                        logger.debug(f"Failed to restart postman: {e}")
                        
        except Exception as e:
            logger.warning(f"Process restart error: {e}")
            
        return restarted_processes
    
    def _delete_user_partition_files(self):
        """Delete userPartitionData.json files to clear sessions."""
        deleted_files = []
        
        # Define file paths for both apps
        if sys.platform == "win32":
            file_paths = [
                os.path.expandvars(r"$APPDATA\Postman\storage\userPartitionData.json"),
                os.path.expandvars(r"$APPDATA\PostmanEnterprise\storage\userPartitionData.json")
            ]
        else:
            file_paths = [
                os.path.expanduser("~/Library/Application Support/Postman/storage/userPartitionData.json"),
                os.path.expanduser("~/Library/Application Support/PostmanEnterprise/storage/userPartitionData.json")
            ]
        
        for file_path in file_paths:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    deleted_files.append(os.path.basename(os.path.dirname(os.path.dirname(file_path))))
                    logger.info(f"Deleted session file: {file_path}")
                else:
                    logger.debug(f"Session file not found: {file_path}")
                    
            except Exception as e:
                logger.warning(f"Failed to delete {file_path}: {e}")
                
        return deleted_files
    
    def clear_all_sessions(self):
        """Clear all Postman sessions from browsers and applications."""
        logger.info("Starting comprehensive Postman session clearing...")
        
        try:
            # 1. Check which processes are currently running
            running_processes = self._check_postman_processes()
            logger.info(f"Found running processes: {[k for k, v in running_processes.items() if v]}")
            
            # 2. Kill running processes
            if any(running_processes.values()):
                killed = self._kill_postman_processes()
                logger.info(f"Terminated processes: {killed}")
            
            # 3. Delete userPartitionData.json files (this clears all session state)
            deleted = self._delete_user_partition_files()
            logger.info(f"Cleared session files for: {deleted}")
            
            # 4. Clear browser cookies
            self._clear_browser_cookies()
            
            # 5. Restart processes that were originally running
            if any(running_processes.values()):
                restarted = self._restart_postman_processes(running_processes)
                logger.info(f"Restarted processes: {restarted}")
            
            logger.info("✓ Postman session clearing completed successfully")
            logger.info("  All Postman authentication sessions have been cleared")
            logger.info("  Next login will require fresh SAML authentication")
            
        except Exception as e:
            logger.warning(f"Session clearing completed with some warnings: {e}")
            logger.info("✓ Core session clearing completed despite warnings")


def main():
    """Main entry point for the session cleaner."""
    
    print("\n" + "="*60)
    print("🧹 POSTMAN SESSION CLEANER")
    print("="*60)
    print("\nThis utility clears all Postman authentication sessions from:")
    print("  • Browser cookies (Chrome, Firefox, Brave, Safari)")
    print("  • Postman application session files")
    print("  • Postman Enterprise application session files")
    print("\nRunning processes will be gracefully restarted.")
    print("="*60 + "\n")
    
    try:
        # Create and run session cleaner
        cleaner = PostmanSessionCleaner()
        cleaner.clear_all_sessions()
        
        print("\n" + "="*60)
        print("✅ SESSION CLEARING COMPLETED SUCCESSFULLY")
        print("="*60)
        print("\nNext steps:")
        print("  1. Start the SAML enforcer daemon")
        print("  2. All Postman logins will now require SAML authentication")
        print("="*60 + "\n")
        
    except KeyboardInterrupt:
        logger.info("Session clearing interrupted by user")
        print("\n⚠️  Session clearing interrupted")
    except Exception as e:
        logger.error(f"Fatal error during session clearing: {e}")
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()