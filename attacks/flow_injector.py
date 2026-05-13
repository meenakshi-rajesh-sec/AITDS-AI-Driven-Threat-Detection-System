#!/usr/bin/env python3
"""Flow injector for direct flow submission to detector"""

import json
import os
import sys

FLOW_FILE = '/tmp/aitds_injected_flows.json'

def inject_flow(flow_dict):
    """Write flow to injection file"""
    try:
        flows = []
        if os.path.exists(FLOW_FILE):
            with open(FLOW_FILE, 'r') as f:
                flows = json.load(f)
        flows.append(flow_dict)
        with open(FLOW_FILE, 'w') as f:
            json.dump(flows, f)
        return True
    except Exception as e:
        print(f"Injection error: {e}")
        return False

if __name__ == "__main__":
    flow = json.loads(sys.stdin.read())
    inject_flow(flow)
