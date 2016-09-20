
from ..base import *


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
                '_ins': ins
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
        if node.is_simprocedure or node.is_syscall:
            return None

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


