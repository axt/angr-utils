#! /usr/bin/env python

import angr
from angrutils import *


def analyze(b, addr, name=None):
    start_state = b.factory.blank_state(addr=addr)
    start_state.stack_push(0x0)
    with hook0(b):
        cfg = b.analyses.CFGEmulated(fail_fast=False, starts=[addr], context_sensitivity_level=1, enable_function_hints=False, keep_state=True, enable_advanced_backward_slicing=False, enable_symbolic_back_traversal=False,normalize=True)

    plot_cg(b.kb, "%s_callgraph" % name, format="png")
    plot_cg(b.kb, "%s_callgraph_verbose" % name, format="png", verbose=True)

if __name__ == "__main__":
    proj = angr.Project("../samples/ais3_crackme", load_options={'auto_load_libs':False})
    main = proj.loader.main_object.get_symbol("main")
    analyze(proj, main.rebased_addr, "ais3")

    proj = angr.Project("../samples/1.6.26-libjsound.so", load_options={'auto_load_libs':False, 'main_opts': {'base_addr': 0x0}})
    main = proj.loader.main_object.get_symbol("Java_com_sun_media_sound_MixerSequencer_nAddControllerEventCallback")
    analyze(proj, main.rebased_addr, "jsound")

