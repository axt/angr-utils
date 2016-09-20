
from ..base import *

import networkx

class AngrCFGSource(Source):
    def __init__(self):
        super(AngrCFGSource, self).__init__()
        self.lookup = {}
        self.seq = 0

    def parse(self, obj, graph):
        if not isinstance(obj, networkx.classes.digraph.DiGraph):
            raise VisError("Unknown input type '%s'" % type(obj))

        for n in obj.nodes():
            if n not in self.lookup:
                wn = Node(self.seq, n)
                self.seq += 1
                self.lookup[n] = wn
                graph.add_node(wn)
            else:
                raise VisError("Duplicate node %s" % str(n))

        for src, dst, data in obj.edges(data=True):
            if not src in self.lookup or not dst in self.lookup:
                raise VisError("Missing nodes %s %s" % str(src), str(dst))
            wsrc = self.lookup[src]
            wdst = self.lookup[dst]
            graph.add_edge(Edge(wsrc, wdst, data))

