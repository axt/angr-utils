# Some pretty-printing routines to help dealing with angr objects

import angr
import claripy


def pp(obj, **kwargs):
    if isinstance(obj, angr.path_group.PathGroup):
        return pathgroup(obj, **kwargs)
    elif isinstance(obj, angr.path.Path):
        return path(obj, **kwargs)
    elif isinstance(obj, claripy.ast.base.Base):
        return ast(obj)
    else:
        raise TypeError(type(obj))
    
def addr_trace(arr, delimiter=",", cols=10, fmtwidth=8, level=0):
    ret = ""
    for i in range(len(arr)):
        if i % cols == 0:
            ret += "\t"*level
        ret += ("0x%%0%dx" % fmtwidth) % arr[i]
        if i != len(arr)-1:
            ret += delimiter
        if i % cols == (cols-1) or i == len(arr)-1:
            ret += "\n"
    return ret

def path(p, delimiter=" -> ", cols=10, fmtwidth=8, level=0):
    ret = "\t"*level + "path '%s':\n" % p.path_id
    ret += addr_trace(p.addr_trace.hardcopy, delimiter=delimiter, level=level+1, cols=cols, fmtwidth=fmtwidth)
    return ret
    
def pathgroup(pg, delimiter=" -> ", cols=10, fmtwidth=8, level=0):
    ret = "\t" * level + "pathgroups\n"
    for sname, stash in pg.stashes.iteritems():
        if len(stash) > 0:
            ret += ("\t" * (level+1) + "%s %d\n") % (sname,len(stash))
            for p in stash:
                ret += path(p, delimiter=delimiter, level=level+2, cols=cols, fmtwidth=fmtwidth)
    return ret

def ast(obj, level=0, last=True):
    ret = ""
    if hasattr(obj, 'op'):
        ret += "\t"*level + obj.op +"("
        if any([hasattr(arg, 'op') for arg in obj.args]):
            ret += "\n"
            for argidx in range(len(obj.args)):
                arg = obj.args[argidx]
                ret += ast(arg, level=level+1, last=argidx==len(obj.args)-1)
            ret += "\t"*level + ")" + ("," if not last else "") +"\n"
        else:
            ret += ",".join(map(str,obj.args)) + ")" + ("," if not last else "") + "\n"
    else:
        ret += "\t"*level + str(obj) + ("," if not last else "") + "\n"
    return ret
