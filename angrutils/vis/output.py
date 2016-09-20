import pydot

from subprocess import Popen, PIPE, STDOUT

from .base import Output

escape_map = {
    "!" : "&#33;",
    "#" : "&#35;",
    ":" : "&#58;",
    "{" : "&#123;",
    "}" : "&#125;",
    "<" : "&#60;",
    ">" : "&#62;",
    "\t": "&nbsp;"
}

def escape(text):
    return "".join(escape_map.get(c,c) for c in text)

default_node_attributes = {
    'shape'    : 'Mrecord',
    'fontname' : 'monospace',
    'fontsize' : '8.0',
}

default_edge_attributes = {
    'fontname' : 'monospace',
    'fontsize' : '8.0',
}

class XDot(pydot.Dot):
    def __init__(self, content):
        super(XDot, self).__init__()
        self.content = content
    def to_string(self):
        return self.content

class DotOutput(Output):

    def __init__(self, fname, format='png', show=False, pause=False):
        super(DotOutput, self).__init__()
        self.fname = fname
        self.format = format
        self.show = show
        self.pause = pause

    def render_attributes(self, default, attrs):
        a = {}
        a.update(default)
        a.update(attrs)
        r = []
        for k,v in a.iteritems():
            r.append(k+"="+v)
        
        return "["+", ".join(r)+"]"
    
    def render_cell(self, key, data):
        if data != None and data['content'] != None:
            ret = '<TD '+ ('ALIGN="'+data['align']+'"' if 'align' in data else '' )+'>'
            if 'color' in data:
                ret += '<FONT COLOR="'+data['color']+'">'
            if 'style' in data:
                ret += '<'+data['style']+'>'
            ret += escape(data['content'])
            if 'style' in data:
                ret += '</'+data['style']+'>'
            if 'color' in data:
                ret += '</FONT>'
            ret += "</TD>"
            return ret
        else:
            return "<TD></TD>"
    
    def render_row(self, row, colmeta):
        ret = "<TR>"
        for k in colmeta:
            ret += self.render_cell(k, row[k] if k in row else None) 
        ret += "</TR>"
        return ret
    
    def render_content(self, c):
        ret = '<TABLE BORDER="0" CELLPADDING="1" ALIGN="LEFT">'
        for r in c['data']:
            ret += self.render_row(r, c['columns'])
        ret += '</TABLE>'
        return ret
        
    def render_node(self, n):
        attrs = {}
        if n.style:
            attrs['style'] = n.style
        if n.fillcolor:
            attrs['fillcolor'] = '"'+n.fillcolor+'"'
        if n.color:
            attrs['color'] = n.color
        if n.width:
            attrs['penwidth'] = str(n.width)

        label = "|".join([self.render_content(c) for c in n.content.values()])
        if label:
            attrs['label'] = '<{ %s }>' % label
        
        return "%d %s" % (n.seq, self.render_attributes(default_node_attributes, attrs))

    def render_edge(self, e):
        attrs = {}
        if e.color:
            attrs['color'] = e.color
        if e.label:
            attrs['label'] = e.label
        if e.style:
            attrs['style'] = e.style
        if e.width:
            attrs['penwidth'] = str(e.width)

        return "%d -> %d %s" % (e.src.seq, e.dst.seq, self.render_attributes(default_node_attributes, attrs))
        
    def generate(self, graph):
        ret  = "digraph G {\n"
        ret += "rankdir=TB;\n"
        
        #TODO
        #for n in sorted(self.vis.nodes, key=lambda n: n.obj.addr):
        for n in graph.nodes:
            ret += self.render_node(n) + "\n"
        
        for e in graph.edges:
            ret += self.render_edge(e) + "\n"
            
        ret += "}\n"
                
        if self.show:
            p = Popen(['xdot', '-'], stdin=PIPE)
            p.stdin.write(ret)
            p.stdin.flush()
            p.stdin.close()
            if self.pause:
                p.wait()
        
        if self.fname:
            dotfile = XDot(ret)
            dotfile.write("{}.{}".format(self.fname, self.format), format=self.format)

