#! /usr/bin/env python

import angr
from angrutils import plot_cfg, plot_cdg, hook0


def analyze(b, addr, name=None):
    start_state = b.factory.blank_state(addr=addr)
    start_state.stack_push(0x0)
    with hook0(b):
        cfg = b.analyses.CFGEmulated(fail_fast=True, starts=[addr], initial_state=start_state, context_sensitivity_level=2, keep_state=True, call_depth=100, normalize=True)

    plot_cfg(cfg, "%s_cfg" % (name), asminst=True, vexinst=False, debug_info=False, remove_imports=True, remove_path_terminator=True)

    cdg = b.analyses.CDG(cfg=cfg, start=addr)
    plot_cdg(cfg, cdg, "%s_cdg" % name, pd_edges=True, cg_edges=True)


if __name__ == "__main__":
    proj = angr.Project("../samples/1.6.26-libjsound.so", load_options={'auto_load_libs':False, 'main_opts': {'base_addr': 0x0}})
    main = proj.loader.main_object.get_symbol("Java_com_sun_media_sound_MixerSequencer_nAddControllerEventCallback")
    analyze(proj, main.rebased_addr, "libjsound")

    proj = angr.Project("../samples/simple1", load_options={'auto_load_libs':False})
    main = proj.loader.main_object.get_symbol("main")
    analyze(proj, main.rebased_addr, "simple1")
