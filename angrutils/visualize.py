import networkx

from collections import defaultdict

from vis import DotOutput
from vis.angr import *
from vis.angr.x86 import *

# NOTE: kept for compatibility reason
def plot_cfg(cfg, fname, format="png", path=None, asminst=False, vexinst=False, func_addr=None, remove_imports=True, remove_path_terminator=True, debug_info=False):
    vis = Vis()
    vis.set_source(AngrCFGSource())
    
    if remove_path_terminator:
        vis.add_transformer(AngrRemovePathTerminator())
        
    if remove_imports:
        vis.add_transformer(AngrRemoveImports(cfg.project))
        
    if func_addr:
        vis.add_transformer(AngrFilterNodes(lambda node: node.obj.function_address == func_addr))

    vis.add_content(AngrCFGHead())
    vis.add_node_annotator(AngrColorSimprocedures())

    if asminst:
        vis.add_content(AngrAsm(cfg.project))
        
    if vexinst:
        vis.add_content(AngrVex(cfg.project))
        vis.add_edge_annotator(AngrColorEdgesVex())
    elif asminst:
        vis.add_edge_annotator(AngrColorEdgesAsm())
    
    if debug_info:
        vis.add_content(AngrCFGDebugInfo())

    if path:
        vis.add_edge_annotator(AngrPathAnnotator(path))
        vis.add_node_annotator(AngrPathAnnotator(path))

    vis.set_output(DotOutput(fname, format=format))    
    vis.process(cfg.graph) 

