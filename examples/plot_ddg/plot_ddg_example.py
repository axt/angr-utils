#! /usr/bin/env python

import angr
from angrutils import plot_cfg, plot_ddg_stmt, plot_ddg_data
from simuvex import SimMemoryVariable

def analyze(b, addr, name=None):
    start_state = b.factory.blank_state(addr=addr)
    start_state.stack_push(0x0)
    cfg = b.analyses.CFGAccurate(fail_fast=True, starts=[addr], initial_state=start_state, context_sensitivity_level=2, keep_state=True, call_depth=100, normalize=True)

    plot_cfg(cfg, "%s_cfg" % (name), asminst=True, vexinst=True, debug_info=False, remove_imports=True, remove_path_terminator=True)


    ddg = b.analyses.DDG(cfg=cfg)
    
    plot_ddg_stmt(ddg.graph, "%s_ddg_stmt" % name, project=b)

    ddg._build_function_dependency_graphs()
    for k,v in ddg._function_data_dependencies.iteritems():
        plot_ddg_stmt(v, "%s_fdg_stmt_%x" % (name, k.addr), project=b)
    
    
    plot_ddg_data(ddg.data_graph, "%s_ddg_data" % name, project=b)
    plot_ddg_data(ddg.simplified_data_graph, "%s_ddg_simplified_data" % name, project=b)

    mem_var_node = None
    for node in ddg.simplified_data_graph.nodes_iter():
        if isinstance(node.variable, SimMemoryVariable):
            mem_var_node = node
            subgraph = ddg.data_sub_graph(mem_var_node, simplified=True, killing_edges=True)
            plot_ddg_data(subgraph, "%s_ddg_subgraph_%x" % (name, node.location.ins_addr), project=b)
    

if __name__ == "__main__":
    proj = angr.Project("../samples/simple1", load_options={'auto_load_libs':False})
    main = proj.loader.main_bin.get_symbol("main")
    analyze(proj, main.addr, "simple1")
