from scamper import ScamperCtrl, ScamperFile, ScamperTrace

with ScamperCtrl(mux='/run/ark/mux') as ctrl:
    vps = [vp for vp in ctrl.vps() if 'network:ipv6' in vp.tags]
    for vp in vps:
        print(vp.name)