# Some pretty-printing routines to help dealing with angr objects

import angr
import claripy
import simuvex
from expr import *

def pp(obj, **kwargs):
    if isinstance(obj, angr.path_group.PathGroup):
        return pathgroup(obj, **kwargs)
    elif isinstance(obj, angr.path.Path):
        return path(obj, **kwargs)
    elif isinstance(obj, claripy.ast.base.Base):
        return ast(obj, **kwargs)
    elif isinstance(obj, simuvex.s_state.SimState):
        return state(obj, **kwargs)
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

def _mem(se, reg):
    if reg.concrete:
        return "%08x" % reg.args[0]
    elif reg.symbolic:
        l,u = get_signed_range(se, reg)
        l = abs(l)
        if len(reg.args) == 1 and reg.args[0].op == 'BVS':
            return "%08x..%08x" % (l,u) + " ; " + str(reg.args[0].args[0])
        else:
            return "%08x..%08x" % (l,u) + " ; DEP: " + str(list(reg.variables))
    else:
        return "UNKNOWN " + type(reg)
    
def state(state, level=0, regs=True, stack=True, stackrange=[0,32], header=True):
    ret = ""
    if regs:
        if header:
            ret += "\t"*level + "====== Registers ======\n"
        ret += "\t"*level + "EAX: %s\n" % _mem(state.se, state.regs.eax)
        ret += "\t"*level + "EBX: %s\n" % _mem(state.se, state.regs.ebx)
        ret += "\t"*level + "ECX: %s\n" % _mem(state.se, state.regs.ecx)
        ret += "\t"*level + "EDX: %s\n" % _mem(state.se, state.regs.edx)
        ret += "\t"*level + "ESI: %s\n" % _mem(state.se, state.regs.esi)
        ret += "\t"*level + "EDI: %s\n" % _mem(state.se, state.regs.edi)
        ret += "\t"*level + "EBP: %s\n" % _mem(state.se, state.regs.ebp)
        ret += "\t"*level + "ESP: %s\n" % _mem(state.se, state.regs.esp)
        ret += "\t"*level + "EIP: %s\n" % _mem(state.se, state.regs.eip)
    if stack:
        if header:
            ret += "\t"*level + "======== Stack ========\n"
        ba = state.regs.esp.args[0]
        for i in range(stackrange[0],stackrange[1],4):
            ret += "\t"*level + "%+03x: %08x %s\n" % (i, ba+i, _mem(state.se, state.memory.load(ba+i, inspect=False)))
    return ret

