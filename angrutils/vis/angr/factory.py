from ..base import *
from . import *
from .x86 import *

class AngrVisFactory(object):
    def __init__(self):
        pass

    def default_cfg_pipeline(self, project, asminst=False, vexinst=False, remove_path_terminator=True):
        vis = Vis()
        vis.set_source(AngrCFGSource())
        if remove_path_terminator:
            vis.add_transformer(AngrRemovePathTerminator())
        vis.add_content(AngrCFGHead())
        vis.add_node_annotator(AngrColorSimprocedures())
        if asminst:
            vis.add_content(AngrAsm(project))
            vis.add_content_annotator(AngrCommentsAsm(project))
        if vexinst:
            vis.add_content(AngrVex(project))
            vis.add_edge_annotator(AngrColorEdgesVex())
        elif asminst:
            vis.add_edge_annotator(AngrColorEdgesAsm())
        return vis
