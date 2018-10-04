#! /usr/bin/env python

import angr
import angr.analyses.decompiler

from angrutils import plot_func_graph, hook0


def analyze(b, addr, name=None):
    start_state = b.factory.blank_state(addr=addr)
    start_state.stack_push(0x0)
    with hook0(b):
        cfg = b.analyses.CFGEmulated(fail_fast=True, starts=[addr], initial_state=start_state, context_sensitivity_level=2, keep_state=True, call_depth=100, normalize=True)

    for func in b.kb.functions.values():
        if func.is_simprocedure:
            continue
        ri = b.analyses.RegionIdentifier(func)
        plot_func_graph(b, func.transition_graph, "%s" % (func.name), asminst=True, vexinst=False, structure=ri.region, color_depth=True)

if __name__ == "__main__":
    proj = angr.Project("../samples/1.6.26-libjsound.so", load_options={'auto_load_libs':False, 'main_opts':{'base_addr':0}})
    main = proj.loader.main_object.get_symbol("Java_com_sun_media_sound_MixerSequencer_nAddControllerEventCallback")
    analyze(proj, main.rebased_addr, "libjsound")

