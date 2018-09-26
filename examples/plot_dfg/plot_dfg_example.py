#! /usr/bin/env python

import angr
from angrutils import plot_cfg, plot_dfg


def analyze(b, addr, name=None):
    start_state = b.factory.blank_state(addr=addr)
    start_state.stack_push(0x0)
    cfg = b.analyses.CFGFast(fail_fast=True, function_starts=[addr], base_state=start_state, normalize=True)

    plot_cfg(cfg, "%s_cfg" % (name), asminst=True, vexinst=True, debug_info=False, remove_imports=True, remove_path_terminator=True)

    dfg = b.analyses.DFG(cfg=cfg)
    for a,g in dfg.dfgs.iteritems():
        plot_dfg(g, "%s_dfg_%x" % (name, a))
    

if __name__ == "__main__":
    proj = angr.Project("../samples/simple1", load_options={'auto_load_libs':False})
    main = proj.loader.main_object.get_symbol("main")
    analyze(proj, main.rebased_addr, "simple1")
