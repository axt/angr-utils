#! /usr/bin/env python

import angr

from angrutils import plot_cfg, hook0
from angrutils.exploration import NormalizedSteps

def analyze(b, addr, name=None):
    start_state = b.factory.blank_state(addr=addr)
    start_state.stack_push(0x0)
    with hook0(b):
        cfg = b.analyses.CFGEmulated(fail_fast=True, starts=[addr], initial_state=start_state, context_sensitivity_level=5, keep_state=True, call_depth=100, normalize=True)

    plot_cfg(cfg, "%s_cfg" % (name), asminst=True, vexinst=False, debug_info=False, remove_imports=False, remove_path_terminator=False)

    start_state = b.factory.blank_state(addr=addr, add_options={angr.sim_options.CONSERVATIVE_READ_STRATEGY} | angr.sim_options.resilience_options)
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
        print(lsimgr)
        return lsimgr

    simgr.run(step_func=step_func, until=lambda lsimgr: len(lsimgr.active) == 0, n=100)

    for stash in simgr.stashes:
        c = 0
        for state in simgr.stashes[stash]:
            plot_cfg(cfg, "%s_cfg_%s_%d" % (name, stash, c), state=state, asminst=True, vexinst=False, debug_info=False, remove_imports=True, remove_path_terminator=True)
            c += 1

if __name__ == "__main__":
    proj = angr.Project("../samples/ais3_crackme", load_options={'auto_load_libs':False})
    main = proj.loader.main_object.get_symbol("main")
    analyze(proj, main.rebased_addr, "ais3")

