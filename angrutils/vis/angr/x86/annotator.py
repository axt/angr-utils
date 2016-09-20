
from ...base import *
from capstone.x86 import *



class AngrColorEdgesAsm(EdgeAnnotator):
    EDGECOLOR_CONDITIONAL_TRUE  = 'green'
    EDGECOLOR_CONDITIONAL_FALSE = 'red'
    EDGECOLOR_UNCONDITIONAL     = 'blue'
    EDGECOLOR_CALL              = 'black'
    EDGECOLOR_RET               = 'grey'
    EDGECOLOR_UNKNOWN           = 'yellow'

    def __init__(self):
        super(AngrColorEdgesAsm, self).__init__()


    def annotate_edge(self, edge):
        if 'jumpkind' in edge.meta:
            jk = edge.meta['jumpkind']
            if jk == 'Ijk_Ret':
                edge.color = self.EDGECOLOR_RET
            elif jk == 'Ijk_FakeRet':
                edge.color = self.EDGECOLOR_RET
                edge.style = 'dotted'
            elif jk == 'Ijk_Call':
                edge.color = self.EDGECOLOR_CALL
            elif jk == 'Ijk_Boring':
                if 'asm' in edge.src.content:
                    last = edge.src.content['asm']['data'][-1]
                    #ins = edge.src.content['asm']['data'][-1]['_ins']
                    #if ins.group(capstone.CS_GRP_JUMP):
                    #    pass
                    if last['mnemonic']['content'].find('jmp') == 0:
                        edge.color = self.EDGECOLOR_UNCONDITIONAL
                    elif last['mnemonic']['content'].find('j') == 0:
                        try:
                            if int(last['operands']['content'],16) == edge.dst.obj.addr:
                                edge.color = self.EDGECOLOR_CONDITIONAL_TRUE
                            else:
                                edge.color = self.EDGECOLOR_CONDITIONAL_FALSE
                        except Exception, e:
                            #TODO warning
                            edge.color = self.EDGECOLOR_UNKNOWN
            else:
                #TODO warning
                edge.color = self.EDGECOLOR_UNKNOWN

class AngrArrayAccessAnnotator(ContentAnnotator):
    def __init__(self):
        super(AngrArrayAccessAnnotator, self).__init__('asm')

    def register(self, content):
        content.add_column_after('comment')
        
    def annotate_content(self, node, content):
        for k in content['data']:
            ins = k['_ins']
            if ins.mnemonic == 'mov':
                if len(ins.operands) > 0:
                    c = -1
                    for i in ins.operands:
                        c += 1
                        if i.type == X86_OP_MEM:
                            if i.mem.index != 0:
                                k['comment'] = {
                                    'content': "R" if c == 1 else "W" + "," + ins.reg_name(i.mem.base) +"," + ins.reg_name(i.mem.index)+","+hex(i.mem.disp)+",+"+hex(i.mem.scale),
                                    'color':'gray',
                                    'align': 'LEFT'
                                }
                                node.fillcolor = '#ffff33'
                                node.style = 'filled'
