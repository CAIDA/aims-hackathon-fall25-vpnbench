import sys
import os
from datetime import timedelta
from scamper import ScamperCtrl, ScamperFile, ScamperTrace, ScamperPing
import pandas as pd
import pprint
from collections import defaultdict

# Per-traceroute Parameters
n_attempts      = 1
t_timeout       = timedelta(seconds=1)
traceroute_type = 'icmp-paris'

# Define output file
output_fpath = "./foo.warts.gz"
output_file = ScamperFile(output_fpath, "w")

# Inputs
input_fpath = "../data/v4_is_vpn_v6_is_same_org_as_v4_50rows.csv"
df = pd.read_csv(input_fpath)
print(f"Input file rows: {len(df)}")
print(f"Unique (IPv4, IPv6): {len(df.drop_duplicates(subset=['IPv4', 'IPv6']))}")

# Drop Duplicate Pairs
df = df.drop_duplicates(subset=['IPv4', 'IPv6'])
print(f"Target count: {len(df)}")

with ScamperCtrl(mux='/run/ark/mux', outfile=output_file) as ctrl:
    # Vantage Point Selection
    vps = [vp for vp in ctrl.vps() if vp.cc in ('US', 'CA', 'BR', 'IN', 'ES', 'AU')]

    # Select VPs that have BOTH IPv4 and IPv6 connectivity
    vps = [vp for vp in vps if 'network:ipv4' in vp.tags and 'network:ipv6' in vp.tags]

    # Filter Vantage Points
    country_counts = defaultdict(int)
    limited_vps = []
    for vp in vps:
        if country_counts[vp.cc] < 2:
            limited_vps.append(vp)
            country_counts[vp.cc] += 1
    vps = limited_vps
    vps = sorted(vps, key=lambda vp: vp.cc)
    print("Filtered VPs (max 2 per country):")
    for vp in vps:
        print(f"{vp.name} ({vp.cc})")

    # Add Vantage Points
    ctrl.add_vps(vps)

    for inst_index, ctrl_inst in enumerate(ctrl.instances()):
        print(f"Instance {inst_index}")
        for ip_index, (ipv4, ipv6) in enumerate(zip(df['IPv4'], df['IPv6'])):
            ipv4, ipv6 = str(ipv4), str(ipv6)
            id = inst_index * df.shape[0] + ip_index
            print(f"{id:4} {ipv4:15} {ipv6:30}")
            ctrl.do_trace(ipv4, inst=ctrl_inst, method=traceroute_type, attempts=n_attempts, wait_timeout=t_timeout, userid = id)
            ctrl.do_trace(ipv6, inst=ctrl_inst, method=traceroute_type, attempts=n_attempts, wait_timeout=t_timeout, userid = id)

    print("\n--------------------------------\n")

    for obj in ctrl.responses(timeout=timedelta(seconds=100)):
        if not isinstance(obj, ScamperTrace):
            continue

        # Process the traceroute result
        trace = obj
        inst = trace.inst
        inst_name = inst.name
        inst_ipv4 = inst.ipv4
        inst_loc = inst.loc
        inst_cc = inst.cc
        
        userid = trace.userid
        src = trace.src
        dst = trace.dst
        stop = trace.stop_reason_str

        print(f"{inst_name}, {inst_cc}, {inst_ipv4}, {inst_loc}, {userid}, {src}, {dst}, {stop}")

        # Print each hop in the traceroute
        for hop in trace.hops():
            if hop is None:
                print(f"*")
            else:
                if hop.src:
                    hop_num = hop.probe_ttl
                    rtt_ms = hop.rtt.total_seconds() * 1000
                    print(f"{hop_num:2}  {hop.src}  {rtt_ms:.3f} ms")
                else:
                    print(f"{hop_num:2}  *")

output_file.close()