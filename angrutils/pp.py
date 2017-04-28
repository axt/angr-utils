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
    elif isinstance(obj, simuvex.s_action.SimAction):
        return action(obj, **kwargs)
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
    trace = p.addr_trace.hardcopy
    trace.append(p.addr)
    ret += addr_trace(trace, delimiter=delimiter, level=level+1, cols=cols, fmtwidth=fmtwidth)
    return ret
    
def pathgroup(pg, delimiter=" -> ", cols=10, fmtwidth=8, level=0):
    ret = "\t" * level + "pathgroups\n"
    for sname, stash in pg.stashes.iteritems():
        if len(stash) > 0:
            ret += ("\t" * (level+1) + "%s %d\n") % (sname,len(stash))
            for p in stash:
                ret += path(p, delimiter=delimiter, level=level+2, cols=cols, fmtwidth=fmtwidth)
    return ret

def ast(obj, level=0, last=True, annotations=False):
    def _to_str(annotations):
        return " ".join(map(str, annotations))
        
    ret = ""
    if hasattr(obj, 'op'):
        ret += "\t"*level + obj.op +"("
        if any([hasattr(arg, 'op') for arg in obj.args]):
            ret += "\n"
            for argidx in range(len(obj.args)):
                arg = obj.args[argidx]
                ret += ast(arg, level=level+1, last=argidx==len(obj.args)-1, annotations=annotations)
            ret += "\t"*level + ")" 
        else:
            ret += ",".join(map(str,obj.args)) + ")" 
        if annotations and hasattr(obj, 'annotations') and len(obj.annotations)>0:
            ret += " [" + _to_str(obj.annotations) + "]"
        ret += ("," if not last else "") + "\n"
    else:
        ret += "\t"*level + str(obj) + ("," if not last else "") + "\n"
    return ret

def _regname(regidx, arch=None):
    return arch.register_names[regidx] if arch else 'reg_'+str(regidx)

def _ao(obj, level=0, arch=None):
    s = "\t"*level
    if obj is not None:
        s +=  str(obj.ast)
        if len(obj.tmp_deps) > 0:
            s +=  " " + str(map(lambda x: "t%d" % x, obj.tmp_deps)) 
        if len(obj.reg_deps) > 0:
            s +=  " " + str(map(lambda x: _regname(x, arch), obj.reg_deps)) 
    return s
    
def action(obj, level=0, arch=None):
    if obj.sim_procedure is not None:
        location = "%s()" % obj.sim_procedure
    else:
        if obj.stmt_idx is not None:
            location = "0x%x:%d" % (obj.bbl_addr, obj.stmt_idx)
        else:
            location = "0x%x" % obj.bbl_addr

    s = "\t"*level + location + "\t"
    if obj.type == 'operation':
        tmpit = iter(obj.tmp_deps)
        exprit = iter(obj.exprs)        
        s += "operation\t%s" % (obj.op)
        for expr in exprit:
            s += "\te:["+str(expr.ast)
            try:
                s += "[t" + str(next(tmpit)) + "]"
            except StopIteration:
                pass
            s += "] "
    elif obj.type == 'exit':
        s += obj.type
        s += "/" + obj.exit_type + " "
        s += "target:" + _ao(obj.target, arch=arch) + " "
        s += "cond:" + _ao(obj.condition, arch=arch) 

    elif obj.type == 'constraint':
        s += obj.type
        s += "cons:" + _ao(obj.constraint, arch=arch) + " "
        s += "cond:" + _ao(obj.condition, arch=arch) 
    else: #SimActionData
        s += obj.type
        s += "/%s(%s) " % ('r' if obj.action == 'read' else 'w', _ao(obj.size, arch=arch))
        if obj.type == 'reg':
            s += _regname(obj.addr.ast,arch)
        elif obj.type == 'tmp':
            s += str("t%d"%obj.tmp)
        else:
            s += "\ta:[" + _ao(obj.addr, arch=arch) + "]"
            
        s += "\td:[" + _ao(obj.data, arch=arch) + "]"
        if len(obj._tmp_dep) > 0:
            s +=  " _tmp_dep: " + str(map(lambda x: "t%d" % x, obj._tmp_dep)) 
        if len(obj._reg_dep) > 0:
            s +=  " _reg_dep: " + str(map(lambda x: _regname(x, arch), obj._reg_dep)) 
    return s

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

