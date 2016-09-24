# Expression evaluation routines
import claripy

def get_signed_range(se, expr):
    """
    Calculate the range of the expression with signed boundaries
    """
    size = expr.size()
    umin = umax = smin = smax = None
    if not sat_zero(se, expr):
        try: 
            umin = se.min(expr, extra_constraints=[claripy.Extract(size-1,size-1,expr) == 0])
            umax = se.max(expr, extra_constraints=[claripy.Extract(size-1,size-1,expr) == 0])
            return (umin, umax)
        except:
            pass
        try: 
            smin = -(1 << size) + se.min(expr, extra_constraints=[claripy.Extract(size-1,size-1,expr) == 1])
            smax = -(1 << size) + se.max(expr, extra_constraints=[claripy.Extract(size-1,size-1,expr) == 1])
            return (smin, smax)
        except:
            pass
        return None
    else:
        try: 
            umax = se.max(expr, extra_constraints=[claripy.Extract(size-1,size-1,expr) == 0])
            smin = 0
            try:
                smin = -(1 << size) + se.min(expr, extra_constraints=[claripy.Extract(size-1,size-1,expr) == 1])
            except:
                pass
            return (smin, umax)
        except:
            pass

        return None

def sat_zero(se, expr):
    return se.satisfiable(extra_constraints=([expr == 0]))

def sat_negative(se, expr):
    size = expr.size()
    return se.satisfiable(extra_constraints=([claripy.Extract(size-1,size-1,expr) == 1]))

def sat_positive(se, expr):
    return se.satisfiable(extra_constraints=([claripy.Extract(size-1,size-1,expr) == 0]))
