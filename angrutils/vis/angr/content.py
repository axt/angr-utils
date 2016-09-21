
from ..base import *
import angr

def safehex(val):
    return str(hex(val) if val != None else None)
        
class AngrCFGHead(Content):
    def __init__(self):
        super(AngrCFGHead, self).__init__('head', ['addr', 'func_addr', 'name', 'attributes'])

    def gen_render(self, n):
        node = n.obj
        attributes=[]
        if node.is_simprocedure:
            attributes.append("SIMP")
        if node.is_syscall:
            attributes.append("SYSC")
        if node.no_ret:
            attributes.append("NORET")
        
        label = "{:#08x} ({:#08x}) {} {}".format(node.addr, node.function_address, node.name, ' '.join(attributes))
        
        n.content[self.name] = {
            'data': [{
                'addr': {
                    'content': "{:#08x}".format(node.addr),
                },
                'func_addr' : {
                    'content': "({:#08x})".format(node.function_address),
                },
                'name': {
                    'content': node.name, 
                    'style':'B'
                },
                'attributes': {
                    'content': ' '.join(attributes)
                }
            }], 
            'columns': self.get_columns()
        }

class AngrCGHead(Content):
    def __init__(self):
        super(AngrCGHead, self).__init__('head', ['name','addr'])
        
    def gen_render(self, n):
        node = n.obj
        n.content[self.name] = {
            'data': [{
                'addr': {
                    'content': "("+hex(n.obj.addr)+")"
                },
                'name': {
                    'content': n.obj.name,
                    'style':'B'
                }
            }], 
            'columns': self.get_columns()
        }

    
class AngrAsm(Content):
    def __init__(self, project):
        super(AngrAsm, self).__init__('asm', ['addr', 'mnemonic', 'operands'])
        self.project = project        

    def gen_render(self, n):
        node = n.obj
        if node.is_simprocedure or node.is_syscall:
            return None

        insns = self.project.factory.block(addr=node.addr, max_size=node.size).capstone.insns

        data = []
        for ins in insns:
            data.append({
                'addr': {
                    'content': "0x%08x:\t" % ins.address,
                    'align': 'LEFT'
                },
                'mnemonic': {
                    'content': ins.mnemonic,
                    'align': 'LEFT'
                },
                'operands': {
                    'content': ins.op_str,
                    'align': 'LEFT'
                },
                '_ins': ins,
                '_addr': ins.address
            })
            
        n.content[self.name] = {
            'data': data,
            'columns': self.get_columns(),
        }


class AngrVex(Content):
    def __init__(self, project):
        super(AngrVex, self).__init__('vex', ['addr', 'statement'])
        self.project = project        

    def gen_render(self, n):
        node = n.obj
        if node.is_simprocedure or node.is_syscall:
            return None

        vex = self.project.factory.block(addr=node.addr, max_size=node.size).vex

        data = []
        for j, s in enumerate(vex.statements):
            data.append({
                'addr': {
                    'content': "0x%08x:" % j,
                    'align': 'LEFT'
                },
                'statement': {
                    'content': str(s),
                    'align': 'LEFT'
                },
                '_stmt': s
            })
        data.append({
            'addr': {
                'content': "NEXT: ",
                'align': 'LEFT'
            },
            'statement': {
                'content': 'PUT(%s) = %s; %s' % (vex.arch.translate_register_name(vex.offsIP), vex.next, vex.jumpkind),
                'align': 'LEFT'
            }
        })
            
        n.content[self.name] = {
            'data': data,
            'columns': self.get_columns(),
            'vex': vex
        }
    
class AngrCFGDebugInfo(Content):
        
    def __init__(self):
        super(AngrCFGDebugInfo, self).__init__('debug_info', ['text'])

    def add_line(self, data, text):
        data.append({
            'text' : {
                'align': 'LEFT',
                'content' : text
            }
        })
        
    def gen_render(self, n):
        node = n.obj

        data = []
    
        self.add_line(data, "callstack_key: " + str([safehex(k) for k in node.callstack_key]))
        self.add_line(data, "predecessors:")
        for k in node.predecessors:
            self.add_line(data, " - " + str(k))
        self.add_line(data, "successors:")
        for k in node.successors:
            self.add_line(data, " - " + str(k))
        self.add_line(data, "return_target: " + safehex(node.return_target))
        self.add_line(data, "looping_times: " + str(node.looping_times))
        self.add_line(data, "size: " + str(node.size))
            
        n.content[self.name] = {
            'data': data,
            'columns': self.get_columns(),
        }



class AngrKbFunctionDetails(Content):
        
    def __init__(self):
        super(AngrKbFunctionDetails, self).__init__('debug_info', ['prop', 'val'])

    def add_line(self, data, prop, val):
        data.append({
            'prop' : {
                'align': 'LEFT',
                'content' : prop,
                'style':'B'
            },
            'val' : {
                'align': 'LEFT',
                'content' : val
            }
        })

    def sitespp(self, arg):
        ret = []
        for k in arg:
            if isinstance(k, angr.knowledge.BlockNode):
                ret.append(hex(k.addr))
            elif isinstance(k, angr.knowledge.HookNode):
                ret.append(hex(k.addr))
            else:
                ret.append("UNKNOWN")
        return "[" + ",".join(ret) + "]"
        
    def gen_render(self, n):
        fn = n.obj
        
        data = []
        self.add_line(data, "addr", safehex(fn.addr))

        attrs = []
        if fn.is_plt:
            attrs.append("PLT")
        if fn.is_simprocedure:
            attrs.append("SIMPROC")
        if fn.is_syscall:
            attrs.append("SYSCALL")
        
        if fn.has_return:
            attrs.append("HASRET")
        if fn.has_unresolved_calls:
            attrs.append("UNRES_CALLS")
        if fn.has_unresolved_jumps:
            attrs.append("UNRES_JUMPS")
        
        if fn.returning == True:
            attrs.append("RET")
        elif fn.returning == False:
            attrs.append("NO_RET+")
        elif fn.returning == None:
            attrs.append("NO_RET")

        if fn.bp_on_stack:
            attrs.append("BP_ON_STACK")
        if fn.retaddr_on_stack:
            attrs.append("RETADDR_ON_STACK")
            
        attrs.append("SP_DELTA_"+str(fn.sp_delta))
        
        self.add_line(data, "attributes", " ".join(attrs))    

        self.add_line(data, "num_arguments", str(fn.num_arguments))
        self.add_line(data, "arguments", str(fn.arguments))

        #self.add_line(data, "block_addrs", str(map(safehex, fn.block_addrs)))

        self.add_line(data, "call_convention", str(type(fn.call_convention)))
        self.add_line(data, "callout_sites", self.sitespp(fn.callout_sites))
        self.add_line(data, "jumpout_sites", self.sitespp(fn.jumpout_sites))
        self.add_line(data, "get_call_sites", str(map(hex,fn.get_call_sites())))
        self.add_line(data, "ret_sites", self.sitespp(fn.ret_sites))

        #self.add_line(data, "prepared_registers", str(fn.prepared_registers))
        #self.add_line(data, "prepared_stack_variables", str(fn.prepared_stack_variables))
        #self.add_line(data, "registers_read_afterwards", str(fn.registers_read_afterwards))
        #self.add_line(data, "get_call_return", str(fn.get_call_return(x)))
        #self.add_line(data, "get_call_target", str(fn.get_call_target(x)))
        
        n.content[self.name] = {
            'data': data,
            'columns': self.get_columns(),
        }


    # 'block_addrs_set', 'blocks', 'callable', 'code_constants', 'endpoints', 'get_node', 'graph', 'info', 'instruction_size', 'local_runtime_values', 'mark_nonreturning_calls_endpoints', 
    # 'nodes', 'normalize', 'operations', 'runtime_values', 'startpoint', 'string_references', 'subgraph', 'transition_graph'
