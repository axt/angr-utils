#!/usr/bin/python

import angr
import simuvex

from collections import defaultdict

from angr.analyses import vfg,cdg,ddg
from angrutils.vis import DotOutput
from angrutils.vis.angr import *
from angrutils.vis.angr.x86 import *

                    


if __name__ == "__main__":

    bname = "../samples/simple0"
    fname = "main"
    
    project = angr.Project(bname, load_options={'auto_load_libs':False})
    symb = project.loader.main_bin.get_symbol(fname)
    
    project.hook(0x0, simuvex.SimProcedures['stubs']['PathTerminator'])
    cfg = project.analyses.CFGAccurate(fail_fast=False, starts=[symb.addr], context_sensitivity_level=1, enable_function_hints=False, keep_state=True, enable_advanced_backward_slicing=False, enable_symbolic_back_traversal=False,normalize=False)

    vis = AngrVisFactory().default_cfg_pipeline(project, asminst=False, vexinst=True)
    vis.set_output(DotOutput('cfg_vex'))
    vis.process(cfg.graph)

    cdg = project.analyses.CDG(cfg=cfg, start=symb.addr)
    ddg = project.analyses.DDG(cfg=cfg)

    targets = []
    for n in cfg.get_all_nodes(0x8048427):
        targets.append((n, 6))

    bs = project.analyses.BackwardSlice(cfg, cdg, ddg, targets=targets, control_flow_slice=False)
    

    
    
    vis = AngrVisFactory().default_cfg_pipeline(project, asminst=False, vexinst=True)
    vis.set_output(DotOutput('cfg_vex_annotated'))
    vis.add_content_annotator(AngrBackwardSliceAnnotatorVex(bs))
    vis.process(cfg.graph) 

    
