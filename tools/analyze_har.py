#!/usr/bin/env python3

import sys
from haralyzer import HarParser
import json

def analyze_har(har_file_path):
    """Analyze HAR file to understand stuck authentication flow."""
    
    with open(har_file_path, 'r') as f:
        har_parser = HarParser(json.loads(f.read()))
    
    print(f"=== HAR Analysis: {har_file_path} ===\n")
    
    # Get all pages
    pages = har_parser.pages
    print(f"Total pages: {len(pages)}")
    
    for page in pages:
        print(f"Page: {page.title}")
        print(f"Started: {page.startedDateTime}")
        print(f"Load time: {page.pageTimings}")
        print()
    
    # Get all entries
    entries = har_parser.har_data['entries']
    print(f"Total requests: {len(entries)}")
    print()
    
    # Analyze each request
    stuck_patterns = []
    redirect_chains = []
    current_chain = []
    
    for i, entry in enumerate(entries):
        request = entry['request']
        response = entry['response']
        
        url = request['url']
        method = request['method']
        status = response['status']
        
        print(f"{i+1:3d}. {method} {url}")
        print(f"     Status: {status} {response.get('statusText', '')}")
        
        if 'timings' in entry:
            timings = entry['timings']
            total_time = entry.get('time', 0)
            print(f"     Time: {total_time:.0f}ms (blocked: {timings.get('blocked', 0):.0f}ms, wait: {timings.get('wait', 0):.0f}ms)")
        
        # Check for errors
        if '_error' in response and response['_error']:
            print(f"     ERROR: {response['_error']}")
            stuck_patterns.append((i+1, url, response['_error']))
        
        # Check for redirects
        if 300 <= status < 400:
            redirect_url = response.get('redirectURL', '')
            if redirect_url:
                print(f"     Redirect to: {redirect_url}")
                current_chain.append((url, redirect_url))
            else:
                if current_chain:
                    redirect_chains.append(current_chain)
                    current_chain = []
        else:
            if current_chain:
                redirect_chains.append(current_chain)
                current_chain = []
        
        # Check for identity.getpostman.com specifically
        if 'identity.getpostman.com' in url:
            if status == 0:
                print(f"     ⚠️  Connection failed to daemon")
            elif '/login' in url and status == 200:
                print(f"     ⚠️  SAML BYPASS: Real login page accessed")
            elif '/sso/' in url:
                print(f"     ✅ SAML redirect working")
        
        print()
    
    # Summary analysis
    print("=== ANALYSIS SUMMARY ===")
    
    if stuck_patterns:
        print(f"\n🚨 STUCK PATTERNS FOUND ({len(stuck_patterns)}):")
        for idx, url, error in stuck_patterns:
            print(f"  {idx}. {url} - {error}")
    
    if redirect_chains:
        print(f"\n🔄 REDIRECT CHAINS ({len(redirect_chains)}):")
        for i, chain in enumerate(redirect_chains):
            print(f"  Chain {i+1}:")
            for from_url, to_url in chain:
                print(f"    {from_url} → {to_url}")
    
    # Check for infinite loops
    urls_seen = {}
    for entry in entries:
        url = entry['request']['url']
        if url in urls_seen:
            urls_seen[url] += 1
        else:
            urls_seen[url] = 1
    
    loops = [(url, count) for url, count in urls_seen.items() if count > 3]
    if loops:
        print(f"\n🔁 POTENTIAL INFINITE LOOPS:")
        for url, count in loops:
            print(f"  {url} - {count} requests")
    
    # Check final state
    if entries:
        last_entry = entries[-1]
        last_url = last_entry['request']['url']
        last_status = last_entry['response']['status']
        print(f"\n📍 FINAL STATE:")
        print(f"  Last URL: {last_url}")
        print(f"  Last Status: {last_status}")
        
        if last_status == 0:
            print("  ❌ Flow ended with connection failure")
        elif last_status in [200, 302]:
            print("  ❓ Flow may be stuck waiting for user interaction")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_har.py <har_file>")
        sys.exit(1)
    
    analyze_har(sys.argv[1])
