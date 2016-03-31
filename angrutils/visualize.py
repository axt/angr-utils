import pydot
    
from pydot import Dot
from pydot import Edge
from pydot import Node
from pydot import Subgraph

import networkx

from collections import defaultdict

# NOTE: the code is a bit fuzzy, will be refactored in later releases
# TODO: add user-supplied edge labels
#       add user-supplied node info
#       it seems one edge is missing from angr cfg for the 'plot_cfg_graph' example, needs to be investigated
#       support VFG plots

default_node_attributes = {
    'shape'    : 'Mrecord',
    'fontname' : 'monospace',
    'fontsize' : '8.0',
}

default_edge_attributes = {
    'fontname' : 'monospace',
    'fontsize' : '8.0',
}

EDGECOLOR_CONDITIONAL_TRUE  = 'green'
EDGECOLOR_CONDITIONAL_FALSE = 'red'
EDGECOLOR_UNCONDITIONAL     = 'blue'
EDGECOLOR_CALL              = 'black'
EDGECOLOR_RET               = 'grey'
EDGECOLOR_UNKNOWN           = 'yellow'

LEFT_ALIGN = '\\l'

escape_map = {
    "!" : "&#33;",
    "#" : "&#35;",
    ":" : "&#58;",
    "{" : "&#123;",
    "}" : "&#125;",
    "<" : "&#60;",
    ">" : "&#62;",
}

def escape(text):
    return "".join(escape_map.get(c,c) for c in text)
        
def print_asm(p):
    return escape(''.join(map(lambda _: str(_)+ LEFT_ALIGN, p.capstone.insns)))
    
def print_vex(p):
    text = ""
    for j, s in enumerate(p.vex.statements):
        text += ("   %02d : %s\\l" % (j, s))
    text += "NEXT: PUT(%s) = %s; %s\\l" % (p.vex.arch.translate_register_name(p.vex.offsIP), p.vex.next, p.vex.jumpkind)
    return escape(text)

def import_addrs(project):
    eaddrs=[]
    for _ in project.loader.main_bin.imports.values():
        if _.resolvedby != None:
            eaddrs.append(_.value)
    return set(eaddrs)
    
def safehex(val):
    return str(hex(val) if val != None else None)
    
def node_debug_info(node):
    ret = ""
    ret += "callstack_key: " + str([safehex(k) for k in node.callstack_key]) + "\\l"
    ret += "predecessors:\\l"
    for k in node.predecessors:
        ret += " - " + escape(str(k)) + "\\l"
    ret += "successors:\\l"
    for k in node.successors:
        ret += " - " + escape(str(k)) + "\\l"
    ret += "return_target: " + safehex(node.return_target) + "\\l"
    ret += "looping_times: " + str(node.looping_times) + "\\l"
    ret += "size: " + str(node.size) + "\\l"
    #node.final_states:
    #node.input_state
    return ret

def node_matches(node, trace):
    cs = list(filter(lambda _: _ !=None, node.callstack_key))   
    current = cs.pop()
    tpos = len(trace)-1
    while tpos > 0:
        if trace[tpos] == current:
            if len(cs) > 0:
                current = cs.pop()
            else:
                break
        tpos -= 1
    return len(cs) == 0
    
def plot_cfg(cfg, fname, format="png", path=None, asminst=False, vexinst=False, func_addr=None, remove_imports=True, remove_path_terminator=True, debug_info=False):
    
    dot_graph = Dot(graph_type="digraph", rankdir="TB")
        
    nodes = {}
    blocks = {}
    nmap = {}
    nidx = 0
    
    ccfg_graph = networkx.DiGraph(cfg.graph)
    filtered_addr = set()
    if func_addr != None:
        for node in ccfg_graph.nodes():
            if node.function_address not in func_addr:
                ccfg_graph.remove_node(node)
                filtered_addr.add(node.addr)
    else:
        if remove_imports:
            eaddrs = import_addrs(cfg.project)
            for node in ccfg_graph.nodes():
                if node == None: 
                    continue
                if node.addr in eaddrs:
                    try:
                        ccfg_graph.remove_node(node)
                        filtered_addr.add(node.addr)
                    except:
                        pass
                    for pnode in node.predecessors:
                        try:
                            ccfg_graph.remove_node(pnode)
                            filtered_addr.add(node.addr)
                        except:
                            pass
        
        if remove_path_terminator:
            for node in ccfg_graph.nodes():
                if hasattr(node, 'is_simprocedure') and  hasattr(node, 'simprocedure_name') and node.is_simprocedure and node.simprocedure_name == "PathTerminator":
                    ccfg_graph.remove_node(node)
                    filtered_addr.add(node.addr)

    node_path = []
    if path != None:
        trace = list(filter(lambda _: _ not in filtered_addr, path.addr_trace))
        for i in range(len(trace)):
            nodes_at_addr = cfg.get_all_nodes(trace[i])
            if len(nodes_at_addr) == 1:
                node_path.append(nodes_at_addr[0])
            else:
                for n in nodes_at_addr:
                    if node_matches(n, trace[:i+1]):
                        node_path.append(n)
                        break
    
    active_nodes = set(node_path)
    active_edges = {}
    
    if len(node_path) > 0:
        for s,t in zip(node_path[:-1],node_path[1:]):
            if s not in active_edges:
                active_edges[s] = set()
            active_edges[s].add(t)


    for node in sorted(filter(lambda _: _ != None,ccfg_graph.nodes()), key=lambda _: _.addr):
        blocks[node.addr] = cfg.project.factory.block(addr=node.addr)
    
        attributes=[]
        if node.is_simprocedure:
            attributes.append("SIMP")
        if node.is_syscall:
            attributes.append("SYSC")
        if node.no_ret:
            attributes.append("NORET")


        nmap[node] = nidx
        nidx += 1
        label = "{{<f0> {:#08x} ({:#08x}) {} {}".format(node.addr, node.function_address, node.name, ' '.join(attributes))
        if not node.is_simprocedure:
            if asminst:
                label += "| " + print_asm(blocks[node.addr])
            if vexinst:
                label += "| " + print_vex(blocks[node.addr])
        if debug_info:
            label += "| " + node_debug_info(node)
        label += "}}"

        penwidth = '1'
        if node in active_nodes:
            penwidth = '3'

        if not node.is_simprocedure:
            nodes[nmap[node]] = Node(nmap[node], label=label, penwidth=penwidth, **default_node_attributes)
        else:
            if node.simprocedure_name == "PathTerminator":
                nodes[nmap[node]] = Node(nmap[node], label=label, penwidth=penwidth, style="filled", fillcolor="#dd5555", **default_node_attributes)
            else:
                nodes[nmap[node]] = Node(nmap[node], label=label, penwidth=penwidth, style="filled", fillcolor="#dddddd", **default_node_attributes)
        dot_graph.add_node(nodes[nmap[node]])

    #for n in ccfg.graph.nodes():
    #    nn = filter(lambda node: node in nmap, cfg.get_all_nodes(n.addr))
    #    if len(nn)>1:
    #        for n in nn[1:]:
    #            dot_graph.add_edge(Edge(nodes[nmap[nn[0]]],nodes[nmap[n]],style="invis"))

    edgeprop = {}    
    for source,target in ccfg_graph.edges():
        if source == None or target == None:
            continue
        key = (nmap[source], nmap[target])

        edge_style='solid'
        if not key in edgeprop:
            if blocks[source.addr].vex.jumpkind == 'Ijk_Boring':
                if len(blocks[source.addr].vex.constant_jump_targets) > 1:
                    if len (blocks[source.addr].vex.next.constants) == 1:
                        if target.addr == blocks[source.addr].vex.next.constants[0].value:
                            color=EDGECOLOR_CONDITIONAL_FALSE
                        else:
                            color=EDGECOLOR_CONDITIONAL_TRUE
                    else:
                        color=EDGECOLOR_UNKNOWN
                else:
                    color=EDGECOLOR_UNCONDITIONAL
            elif blocks[source.addr].vex.jumpkind == 'Ijk_Call':
                color=EDGECOLOR_CALL
                if len (blocks[source.addr].vex.next.constants) == 1 and blocks[source.addr].vex.next.constants[0].value != target.addr:
                    edge_style='dotted'
            elif blocks[source.addr].vex.jumpkind == 'Ijk_Ret':
                color=EDGECOLOR_RET
            else:
                color=EDGECOLOR_UNKNOWN
    
            penwidth='1'
            if source in active_edges and target in active_edges[source]:
                penwidth='3'
            
            edgeprop[key]= {
                "color" : color,
                "penwidth": penwidth,
            }
        
        dot_graph.add_edge(Edge(nodes[nmap[source]],nodes[nmap[target]],color=edgeprop[key]["color"], style=edge_style, penwidth=edgeprop[key]["penwidth"], **default_edge_attributes))
    
    dot_graph.write("{}.{}".format(fname, format), format=format)

