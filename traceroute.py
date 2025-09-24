import sys
from datetime import timedelta
from scamper import ScamperCtrl, ScamperFile, ScamperTrace, ScamperPing
import pandas as pd
import pprint

WARTS_OUT = "foo.warts.gz"
outfile = ScamperFile(WARTS_OUT, "w")
df = pd.read_csv('data/v4_is_vpn_v6_is_same_org_as_v4_50rows.csv')

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
            id = inst_index * 10 + ip_index
            print(f"{id:4} {ipv4} {ipv6}")
            ctrl.do_trace(ipv4, inst = ctrl_inst, method='icmp-paris', attempts=1, wait_timeout=timedelta(seconds=1), userid = id)
            ctrl.do_trace(ipv6, inst= ctrl_inst, method='icmp-paris', attempts=1, wait_timeout=timedelta(seconds=1), userid = id)

    for obj in ctrl.responses(timeout=timedelta(seconds=100)):
        if not isinstance(obj, ScamperTrace):
            continue


