#!/usr/bin/env python3
"""
Search for unusual/suspicious activity using LRQ API.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lrq_client import LRQClient, get_time_range

CONSOLE = os.environ.get("S1_CONSOLE", "usea1-purple.sentinelone.net")
JWT = os.environ.get("S1_JWT")

if not JWT:
    print("Set S1_JWT environment variable")
    sys.exit(1)

client = LRQClient(CONSOLE, JWT)
start, end = get_time_range(168)  # Last 7 days

print("="*70)
print("UNUSUAL ACTIVITY HUNT - Last 7 Days")
print("="*70)
print(f"Time range: {start} to {end}\n")

# Hunt 1: Event type distribution
print("[1/6] Event Type Distribution...")
query1 = """
dataSource.name='SentinelOne' dataSource.category='security'
| group ct=count() by event.type
| sort -ct
| limit 30
"""
result = client.execute_query(query1, start, end, timeout=120)
print(f"  Found {len(result['values'])} event types")
if result['values']:
    print("  Top 10:")
    for row in result['values'][:10]:
        print(f"    {row[0]}: {row[1]:,}")

# Hunt 2: Rare processes (potential LOLBins or malware)
print("\n[2/6] Rare Process Executions...")
query2 = """
dataSource.name='SentinelOne' dataSource.category='security' event.type='Process Creation'
| group ct=count() by src.process.name
| filter ct < 10
| sort -ct
| limit 20
"""
result = client.execute_query(query2, start, end, timeout=120)
print(f"  Found {len(result['values'])} rare processes (< 10 executions)")
if result['values']:
    print("  Examples:")
    for row in result['values'][:10]:
        print(f"    {row[0]}: {row[1]} executions")

# Hunt 3: Suspicious command line patterns
print("\n[3/6] Suspicious Command Line Patterns...")
query3 = """
dataSource.name='SentinelOne' dataSource.category='security'
| filter src.process.cmdline matches ".*(whoami|ipconfig|net user|net group|systeminfo|tasklist|reg query).*"
| group ct=count() by src.process.name, endpoint.name
| sort -ct
| limit 20
"""
result = client.execute_query(query3, start, end, timeout=120)
print(f"  Found {len(result['values'])} reconnaissance command patterns")
if result['values']:
    print("  Top findings:")
    for row in result['values'][:10]:
        print(f"    {row[0]} on {row[1]}: {row[2]} times")

# Hunt 4: Network connections to unusual ports
print("\n[4/6] Unusual Network Ports...")
query4 = """
dataSource.name='SentinelOne' dataSource.category='security' event.type='IP Connect'
| filter dst.port.number != 80 AND dst.port.number != 443 AND dst.port.number != 53
| group ct=count() by dst.port.number
| sort -ct
| limit 20
"""
result = client.execute_query(query4, start, end, timeout=120)
print(f"  Found {len(result['values'])} non-standard ports")
if result['values']:
    print("  Top ports:")
    for row in result['values'][:10]:
        print(f"    Port {row[0]}: {row[1]:,} connections")

# Hunt 5: Script execution (PowerShell, WScript, CScript)
print("\n[5/6] Script Execution Activity...")
query5 = """
dataSource.name='SentinelOne' dataSource.category='security'
| filter src.process.name contains ('powershell', 'wscript', 'cscript', 'mshta', 'cmd')
| group ct=count() by src.process.name, endpoint.name
| sort -ct
| limit 20
"""
result = client.execute_query(query5, start, end, timeout=120)
print(f"  Found {len(result['values'])} script execution patterns")
if result['values']:
    print("  Top findings:")
    for row in result['values'][:10]:
        print(f"    {row[0]} on {row[1]}: {row[2]} times")

# Hunt 6: File operations in sensitive directories
print("\n[6/6] Sensitive Directory Activity...")
query6 = """
dataSource.name='SentinelOne' dataSource.category='security' event.type='File Creation'
| filter tgt.file.path matches ".*(Temp|AppData|Downloads|Startup).*\\\\.(exe|dll|ps1|bat|vbs|js)$"
| group ct=count() by tgt.file.path, endpoint.name
| sort -ct
| limit 20
"""
result = client.execute_query(query6, start, end, timeout=120)
print(f"  Found {len(result['values'])} suspicious file creations")
if result['values']:
    print("  Top findings:")
    for row in result['values'][:10]:
        print(f"    {row[0][:60]}... on {row[1]}: {row[2]} times")

print("\n" + "="*70)
print("HUNT COMPLETE")
print("="*70)
