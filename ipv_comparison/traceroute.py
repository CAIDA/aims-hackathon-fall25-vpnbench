import sys
import os
from datetime import timedelta
from scamper import ScamperCtrl, ScamperFile, ScamperTrace, ScamperPing
import pandas as pd
import pprint

script_dir = os.path.dirname(os.path.abspath(__file__))
data_path = os.path.join(script_dir, '..', 'data', 'v4_is_vpn_v6_is_same_org_as_v4_50rows.csv')

WARTS_OUT = "ipv_comparison/foo.warts.gz"
outfile = ScamperFile(WARTS_OUT, "w")
df = pd.read_csv(data_path)

def get_vps(ctrl):
    base_vps = [
        "cld4-us.ark.caida.org",
        "waw-pl.ark.caida.org",
        "dmk2-th.ark.caida.org",
    ]
    return [vp for vp in ctrl.vps() if vp.name in base_vps]

with ScamperCtrl(mux='/run/ark/mux', outfile=outfile) as ctrl:
    # if for some reason these are down, we have bigger problems

    ctrl.add_vps(get_vps(ctrl))

    for inst_index, ctrl_inst in enumerate(ctrl.instances()):
        print(f"Instance {inst_index}")
        for ip_index, (ipv4, ipv6) in enumerate(zip(df['IPv4'], df['IPv6'])):
            ipv4, ipv6 = str(ipv4), str(ipv6)
            id = inst_index * df.shape[0] + ip_index
            print(f"{id:4} {ipv4:15} {ipv6:30}")
            ctrl.do_trace(ipv4, inst=ctrl_inst, method='icmp-paris', attempts=1, wait_timeout=timedelta(seconds=1), userid = id)
            ctrl.do_trace(ipv6, inst=ctrl_inst, method='icmp-paris', attempts=1, wait_timeout=timedelta(seconds=1), userid = id)

    print("\n--------------------------------\n")

    for obj in ctrl.responses(timeout=timedelta(seconds=100)):
        if not isinstance(obj, ScamperTrace):
            continue
        
        # Process the traceroute result
        trace = obj
        src = trace.src
        dst = trace.dst
        
        print(f"traceroute from {src} to {dst}")
        
        # Print each hop in the traceroute
        for hop in trace.hops():
            hop_num = hop.probe_ttl
            if hop.addr:
                print(f"{hop_num:2}  {hop.addr}  {hop.rtt:.3f} ms")
            else:
                print(f"{hop_num:2}  *")

outfile.close()
