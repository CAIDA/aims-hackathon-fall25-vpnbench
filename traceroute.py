import sys
from datetime import timedelta
from scamper import ScamperCtrl, ScamperFile, ScamperTrace
import pandas as pd
import pprint

WARTS_OUT = "foo.warts.gz"
outfile = ScamperFile(WARTS_OUT, "w")
df = pd.read_csv('data/v4_is_vpn_v6_is_same_org_as_v4_50rows.csv')[:10]

with ScamperCtrl(mux='/run/ark/mux', outfile=outfile) as ctrl:
    # print(vps, end='\n')
    vps = [vp for vp in ctrl.vps() if 'network:ipv6' in vp.tags][:3]
    ctrl.add_vps(vps)

    for inst_index, ctrl_inst in enumerate(ctrl.instances()):
        for ip_index, (ipv4, ipv6) in enumerate(zip(df['IPv4'], df['IPv6'])):
            ipv4, ipv6 = str(ipv4), str(ipv6)
            id = inst_index * 10 + ip_index
            print(id, ipv4, ipv6)
            ctrl.do_trace(ipv4, inst = ctrl_inst, method='icmp-paris', attempts=1, wait_timeout=timedelta(seconds=1), userid = id)
            ctrl.do_trace(ipv6, inst= ctrl_inst, method='icmp-paris', attempts=1, wait_timeout=timedelta(seconds=1), userid = id)

    for obj in ctrl.responses(timeout=timedelta(seconds=100)):
        if not isinstance(obj, ScamperTrace):
            continue


