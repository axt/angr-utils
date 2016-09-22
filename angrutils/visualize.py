import networkx

from collections import defaultdict

from bingraphvis import DotOutput
from bingraphvis.angr import *
from bingraphvis.angr.x86 import *

def plot_cfg(cfg, fname, format="png", path=None, asminst=False, vexinst=False, func_addr=None, remove_imports=True, remove_path_terminator=True, debug_info=False):
   
    vis = AngrVisFactory().default_cfg_pipeline(cfg.project, asminst=asminst, vexinst=vexinst)
        
    if remove_imports:
        vis.add_transformer(AngrRemoveImports(cfg.project))
        
    if func_addr:
        vis.add_transformer(AngrFilterNodes(lambda node: node.obj.function_address in func_addr and func_addr[node.obj.function_address]))
    
    if debug_info:
        vis.add_content(AngrCFGDebugInfo())

    if path:
        vis.add_edge_annotator(AngrPathAnnotator(path))
        vis.add_node_annotator(AngrPathAnnotator(path))

    vis.set_output(DotOutput(fname, format=format))    
    vis.process(cfg.graph) 

def plot_cg(kb, fname, format="png", verbose=False):
    vis = AngrVisFactory().default_cg_pipeline(kb, verbose=verbose)
    vis.set_output(DotOutput(fname, format=format))    
    vis.process(kb) 
    
