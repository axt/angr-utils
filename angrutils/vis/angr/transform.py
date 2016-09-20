
from ..base import *

import networkx

class AngrRemovePathTerminator(Transformer):
    def __init__(self):
        pass
        
    def transform(self, graph):
        remove = []
        for n in graph.nodes:
            if n.obj.is_simprocedure and n.obj.simprocedure_name == 'PathTerminator':
                remove.append(n)
        for r in remove:
            graph.remove_node(r)


class AngrRemoveSimProcedures(Transformer):
    def __init__(self):
        pass
        
    def transform(self, graph):
        remove = []
        for n in graph.nodes:
            if n.obj.is_simprocedure:
                remove.append(n)
                cs = []
                for e in graph.edges:
                    if e.dst == n:
                        cs.append(e.src)
                found = False
                for c in cs:
                    for e in graph.edges:
                        if e.src == c and e.dst != n:
                            found = True
                            break
                    if not found:
                        remove.append(c)
        for r in remove:
            graph.remove_node(r)

class AngrFilterNodes(Transformer):
    def __init__(self, node_filter):
        self.node_filter = node_filter
        pass
        
    def transform(self, graph):
        remove = filter(lambda _: not self.node_filter(_), graph.nodes)

        for r in remove:
            graph.remove_node(r)


class AngrRemoveImports(Transformer):
    def __init__(self, project):
        self.project = project
        self.eaddrs = self.import_addrs(project)
        
    def import_addrs(self, project):
        eaddrs=[]
        for _ in project.loader.main_bin.imports.values():
            if _.resolvedby != None:
                eaddrs.append(_.value)
        return set(eaddrs)

    def transform(self, graph):
        remove = []
        for n in graph.nodes:
            if n.obj.addr in self.eaddrs:
                remove.append(n)
                cs = []
                for e in graph.edges:
                    if e.dst == n:
                        cs.append(e.src)
                found = False
                for c in cs:
                    for e in graph.edges:
                        if e.src == c and e.dst != n:
                            found = True
                            break
                    if not found:
                        remove.append(c)
        for r in remove:
            graph.remove_node(r)

