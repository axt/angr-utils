#! /usr/bin/env python

import angr
from angrutils import plot_func_graph


def analyze(b, addr, name=None):
    start_state = b.factory.blank_state(addr=addr)
    start_state.stack_push(0x0)
    cfg = b.analyses.CFGAccurate(fail_fast=True, starts=[addr], initial_state=start_state, context_sensitivity_level=2, keep_state=True, call_depth=100, normalize=True)

    for func in b.kb.functions.values():
        try:
            ri = b.analyses.RegionIdentifier(func)
            plot_func_graph(b, func.transition_graph, "%s" % (func.name), asminst=True, vexinst=False, structure=ri.region, color_depth=True)
        except:
            pass
            
if __name__ == "__main__":
    proj = angr.Project("../samples/1.6.26-libjsound.so", load_options={'auto_load_libs':False, 'main_opts':{'custom_base_addr':0}})
    main = proj.loader.main_bin.get_symbol("Java_com_sun_media_sound_MixerSequencer_nAddControllerEventCallback")
    analyze(proj, main.addr, "libjsound")

