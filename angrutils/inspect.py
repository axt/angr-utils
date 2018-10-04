# Some pretty-printing routines to help dealing with angr objects
import angr
import claripy

def _consolidate_expr(e0):
    if hasattr(e0, 'op') and e0.op == 'Reverse':
        e1 = e0.args[0]
        if e1.op == 'Extract':
            p0 = e1.args[0]
            p1 = e1.args[1]
            e2 = e1.args[2]
            if e2.op == 'Reverse':
                return claripy.Extract(e2.size()-1-p1, e2.size()-1-p0, e2.args[0])
    return e0

def _read_consolidate(r):
    r.inspect.mem_read_expr = _consolidate_expr(r.inspect.mem_read_expr)
    r.inspect.reg_read_expr = _consolidate_expr(r.inspect.reg_read_expr)

def consolidate_reverse_exprs(initial_state):
    """
    Tries to simplify the Reverse(Extract(Reverse())) pattern in expressions.
    
    NOTE: Experimental! Maybe not working correctly, use it with care!
    """
    initial_state.inspect.b('mem_read', when=angr.BP_AFTER, action=_read_consolidate)
    initial_state.inspect.b('reg_read', when=angr.BP_AFTER, action=_read_consolidate)
