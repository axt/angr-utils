#! /usr/bin/env python

import angr
from angrutils import plot_cfg


def analyze(b, addr, name=None):
    start_state = b.factory.blank_state(addr=addr)
    start_state.stack_push(0x0)
    cfg = b.analyses.CFGFast(fail_fast=True, function_starts=[addr], base_state=start_state, normalize=True)
    
    plot_cfg(cfg, "%s_cfg" % (name), asminst=True, vexinst=False, debug_info=False, remove_imports=True, remove_path_terminator=True, color_depth=True)

if __name__ == "__main__":
    proj = angr.Project("../samples/1.6.26-libjsound.so", load_options={'auto_load_libs':False, 'main_opts':{'custom_base_addr':0}})
    main = proj.loader.main_object.get_symbol("Java_com_sun_media_sound_MixerSequencer_nAddControllerEventCallback")
    analyze(proj, main.rebased_addr, "libjsound")

