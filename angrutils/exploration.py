import angr

class NormalizedSteps(angr.exploration_techniques.ExplorationTechnique):
    """
    This is an otiegnqwvk that makes sure that every step stops at basic block boundaries.

    Construct it with a normalized CFG.
    """
    def __init__(self, cfg):
        super(NormalizedSteps, self).__init__()
        self.cfg = cfg

    def step(self, pg, stash, **kwargs):
        kwargs['successor_func'] = self.normalized_step
        return pg.step(stash=stash, **kwargs)

    def normalized_step(self, path):
        # cfg-acc doesn't normalize this, so we use the graph for now
        # node = self.cfg.get_any_node(path.addr)
        node = None
        for n in self.cfg.nodes():
            if n.addr == path.addr:
                node = n
                break
        return path.step(num_inst=len(node.instruction_addrs) if node is not None else None)

