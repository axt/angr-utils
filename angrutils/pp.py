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

def _regname(regidx, arch=None):
    return arch.register_names[regidx] if arch else 'reg_'+str(regidx)
    
def action(obj, level=0, arch=None):
    if obj.sim_procedure is not None:
        location = "%s()" % obj.sim_procedure
    else:
        if obj.stmt_idx is not None:
            location = "0x%x:%d" % (obj.bbl_addr, obj.stmt_idx)
        else:
            location = "0x%x" % obj.bbl_addr

    s = "\t"*level + location + ": "
    if obj.type == 'operation':
        tmpit = iter(obj.tmp_deps)
        exprit = iter(obj.exprs)
        
        s += "OP  " + obj.op + " "
        for expr in exprit:
            s += str(expr)
            try:
                s += "(t" + str(next(tmpit)) + ")"
            except StopIteration:
                pass
            s += " "        
    elif obj.type == 'exit':
        #'all_objects', 'bbl_addr', 'condition', 'copy', 'downsize', 'exit_type', 'id', 'ins_addr', 'objects', 'reg_deps', 'sim_procedure', 'stmt_idx', 'target', 'tmp_deps', 'type'
        s = "\t"*level + obj.__repr__()
    elif obj.type == 'reg':
        
        #'action', 'actual_addrs', 'actual_value', 'added_constraints', 'addr', 'all_objects', 'bbl_addr', 'condition', 'copy', 'data', 'downsize', 'fallback', 'fd', 'id', 'ins_addr', 'objects', 'offset', 'reg_deps', 'sim_procedure', 'size', 'stmt_idx', 'tmp', 'tmp_deps', 'type'
        if len(obj.reg_deps) == 0:
            if len(obj.tmp_deps) == 0:
                s += "REG " + obj.action + " " + _regname(obj.actual_addrs[0],arch) + " '" + str(obj.data)+"'"
            elif len(obj.tmp_deps) == 1:
                s += "REG " + obj.action + " " + _regname(obj.actual_addrs[0],arch) +  " t" +  str(next(iter(obj.tmp_deps)))
            else:
                import ipdb; ipdb.set_trace()
        elif len(obj.reg_deps) == 1:
            regidx = next(iter(obj.reg_deps))
            s += "REG " + obj.action + " " +  _regname(regidx, arch) + " " + str(obj.tmp_deps) + " '" + str(obj.data)+"'"
        else:
            import ipdb; ipdb.set_trace()
    elif obj.type == 'mem':
        #'action', 'actual_addrs', 'actual_value', 'added_constraints', 'addr', 'all_objects', 'bbl_addr', 'condition', 'copy', 'data', 'downsize', 'fallback', 'fd', 'id', 'ins_addr', 'objects', 'offset', 'reg_deps', 'sim_procedure', 'size', 'stmt_idx', 'tmp', 'tmp_deps', 'type'
        s += "MEM " + obj.action + " " + str(obj.reg_deps) + " " + str(obj.tmp_deps) + " " + str(obj.actual_addrs) + " " + str(obj.data)
    elif obj.type == 'tmp':
        # 'action', 'actual_addrs', 'actual_value', 'added_constraints', 'addr', 'all_objects', 'bbl_addr', 'condition', 'copy', 'data', 'downsize', 'fallback', 'fd', 'id', 'ins_addr', 'objects', 'offset', 'sim_procedure', 'size', 'stmt_idx'
        s += "TMP " + obj.action + " t" +  str(obj.tmp)
    elif obj.type == 'constraint':
        s = "\t"*level + obj.__repr__()
        #'all_objects', 'bbl_addr', 'condition', 'constraint', 'copy', 'downsize', 'id', 'ins_addr', 'objects', 'reg_deps', 'sim_procedure', 'stmt_idx', 'tmp_deps', 'type'
    else:
        s = "UNKNOWN" + str(dir(s))
        import ipdb; ipdb.set_trace()
    #'action', 'actual_addrs', 'actual_value', 'added_constraints', 'addr', 'all_objects', 'bbl_addr', 'condition', 'copy', 'data', 'downsize', 'fallback', 'fd', 'id', 'ins_addr', 'objects', 'offset', 'reg_deps', 'sim_procedure', 'size', 'stmt_idx', 'tmp', 'tmp_deps', 'type'
    # type : reg, mem, tmp, operation, exit
    # action: read/write
    # operation : 'bbl_addr', 'ins_addr', 'sim_procedure', 'stmt_idx', 
    
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

