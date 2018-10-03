import angr

class NormalizedSteps(angr.exploration_techniques.ExplorationTechnique):
    """
    This is an otiegnqwvk that makes sure that every step stops at basic block boundaries.

    Construct it with a normalized CFG.
    """
    def __init__(self, cfg):
        super(NormalizedSteps, self).__init__()
        self.cfg = cfg

    def step(self, simgr, stash, **kwargs):
        kwargs['successor_func'] = self.normalized_step
        return simgr.step(stash=stash, **kwargs)

    def normalized_step(self, state):
        node = self.cfg.get_any_node(state.addr)
        return state.step(num_inst=len(node.instruction_addrs) if node is not None else None)

