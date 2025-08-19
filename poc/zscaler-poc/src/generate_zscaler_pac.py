#!/usr/bin/env python3
"""
PAC File Generator for Postman SAML Enforcement

Generates Proxy Auto-Config files that route identity.getpostman.com
through local proxy while allowing direct connections for all other domains.

Proof of concept implementation for enterprise proxy agents.
"""

import json
import os
import sys
from pathlib import Path

def generate_pac_file(proxy_host="127.0.0.1", proxy_port=8444, output_file="postman.pac"):
    """Generate PAC file for Postman SAML enforcement."""
    
    pac_content = f"""// Postman SAML Enforcement PAC File
// Generated automatically - routes identity.getpostman.com through local proxy
// UNTESTED POC - Requires validation before production use

function FindProxyForURL(url, host) {{
    // Convert host to lowercase for case-insensitive matching
    host = host.toLowerCase();
    
    // Route Postman identity domain through local proxy
    if (shExpMatch(host, "identity.getpostman.com")) {{
        return "PROXY {proxy_host}:{proxy_port}";
    }}
    
    // All other traffic goes direct
    return "DIRECT";
}}

// Alternative function names for compatibility
var FindProxyForURLEx = FindProxyForURL;
"""
    
    # Write PAC file
    with open(output_file, 'w') as f:
        f.write(pac_content)
    
    print(f"PAC file generated: {output_file}")
    print(f"Proxy configuration: {proxy_host}:{proxy_port}")
    return output_file

def generate_pac_url_file(pac_file_path, output_file="pac_url.txt"):
    """Generate file URL for PAC file deployment."""
    abs_path = os.path.abspath(pac_file_path)
    file_url = f"file://{abs_path}"
    
    with open(output_file, 'w') as f:
        f.write(file_url)
    
    print(f"PAC file URL: {file_url}")
    print(f"URL saved to: {output_file}")
    return file_url

def load_config(config_file="../config/config.json.template"):
    """Load configuration for proxy settings."""
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        print(f"Config file not found: {config_file}")
        return {}
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in config file: {e}")
        return {}

def main():
    """Main PAC file generation."""
    print("Postman SAML PAC File Generator")
    print("UNTESTED POC - Requires validation before production use")
    print("=" * 60)
    
    # Change to script directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    # Load configuration
    config = load_config()
    proxy_port = config.get('listen_port', 8444)
    proxy_host = "127.0.0.1"
    
    # Generate PAC file
    pac_file = generate_pac_file(
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        output_file="../config/postman.pac"
    )
    
    # Generate PAC URL for deployment
    generate_pac_url_file(
        pac_file_path=f"../config/{os.path.basename(pac_file)}",
        output_file="../config/pac_url.txt"
    )
    
    print("\nNext steps:")
    print("1. Configure system proxy to use generated PAC file")
    print("2. Start PAC proxy daemon")
    print("3. Test with Postman Desktop")
    print("\nWARNING: This is an untested POC implementation")

if __name__ == "__main__":
    main()