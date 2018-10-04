#! /usr/bin/env python

import angr
from angrutils import plot_func_graph


def analyze(b, name):
    cfg = b.analyses.CFG(normalize=True)
    for func in proj.kb.functions.values():
        if func.name.find('Java_') == 0:
            plot_func_graph(b, func.transition_graph, "%s_%s_cfg" % (name, func.name), asminst=True, vexinst=False)

if __name__ == "__main__":
    proj = angr.Project("../samples/1.6.26-libjsound.so", load_options={'auto_load_libs':False, 'main_opts':{'base_addr':0}})
    analyze(proj, "libjsound")

