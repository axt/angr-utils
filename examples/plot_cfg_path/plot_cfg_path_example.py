#! /usr/bin/env python

import angr
import simuvex

from angrutils import plot_cfg
from angrutils.exploration import NormalizedSteps

def analyze(b, addr, name=None):
    start_state = b.factory.blank_state(addr=addr)
    start_state.stack_push(0x0)
    cfg = b.analyses.CFGFast(fail_fast=True, function_starts=[addr], base_state=start_state, normalize=True)

    plot_cfg(cfg, "%s_cfg" % (name), asminst=True, vexinst=False, debug_info=False, remove_imports=False, remove_path_terminator=False)

    start_state = b.factory.blank_state(addr=addr, add_options={simuvex.o.CONSERVATIVE_READ_STRATEGY} | simuvex.o.resilience_options)
    start_state.stack_push(0x0)
    
    simgr = b.factory.simgr(start_state)
    simgr.use_technique(NormalizedSteps(cfg))
    
    def check_loops(state):
        last = state.history.bbl_addrs[-1]
        c = 0
        for p in state.history.bbl_addrs:
            if p ==  last:
               c += 1 
        return c > 1

    def step_func(lsimgr):
        lsimgr.stash(filter_func=check_loops, from_stash='active', to_stash='looping')
        lsimgr.stash(filter_func=lambda state: state.addr == 0, from_stash='active', to_stash='found')
        print lsimgr
        return lsimgr

    simgr.run(step_func=step_func, until=lambda lsimgr: len(lsimgr.active) == 0, n=100)
    print 1
    for stash in simgr.stashes:
        c = 0
        for p in simgr.stashes[stash]:
            plot_cfg(cfg, "%s_cfg_%s_%d" % (name, stash, c), path=p, asminst=True, vexinst=False, debug_info=False, remove_imports=True, remove_path_terminator=True)
            c += 1
    
if __name__ == "__main__":
    proj = angr.Project("../samples/ais3_crackme", load_options={'auto_load_libs':False})
    main = proj.loader.main_object.get_symbol("main")
    analyze(proj, main.rebased_addr, "ais3")

