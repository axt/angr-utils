#! /usr/bin/env python

import angr
import simuvex

from angrutils import plot_cfg
from angrutils.exploration import NormalizedSteps

def analyze(b, addr, name=None):
    start_state = b.factory.blank_state(addr=addr)
    start_state.stack_push(0x0)
    cfg = b.analyses.CFGAccurate(fail_fast=True, starts=[addr], initial_state=start_state, context_sensitivity_level=5, keep_state=True, call_depth=100, normalize=True)

    plot_cfg(cfg, "%s_cfg" % (name), asminst=True, vexinst=False, debug_info=False, remove_imports=False, remove_path_terminator=False)

    start_state = b.factory.blank_state(addr=addr, add_options={simuvex.o.CONSERVATIVE_READ_STRATEGY} | simuvex.o.resilience_options)
    start_state.stack_push(0x0)
    
    pg = b.factory.path_group(start_state)
    pg.use_technique(NormalizedSteps(cfg))
    
    unique_states = set()
    def check_loops(path):
        last = path.addr_trace[-1]
        c = 0
        for p in path.addr_trace:
            if p ==  last:
               c += 1 
        return c > 1

    def step_func(lpg):
        lpg.stash(filter_func=check_loops, from_stash='active', to_stash='looping')
        lpg.stash(filter_func=lambda path: path.addr == 0, from_stash='active', to_stash='found')
        print lpg
        return lpg

    pg.step(step_func=step_func, until=lambda lpg: len(lpg.active) == 0, n=100)
    
    for stash in pg.stashes:
        c = 0
        for p in pg.stashes[stash]:
            plot_cfg(cfg, "%s_cfg_%s_%d" % (name, stash, c), path=p, asminst=True, vexinst=False, debug_info=False, remove_imports=True, remove_path_terminator=True)
            c += 1
    
if __name__ == "__main__":
    proj = angr.Project("../samples/ais3_crackme", load_options={'auto_load_libs':False})
    main = proj.loader.main_bin.get_symbol("main")
    analyze(proj, main.addr, "ais3")

