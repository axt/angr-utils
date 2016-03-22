# angr-utils

Angr-utils is a collection of utilities for angr binary analysis framework.

## Functionality
* Create fancy CFG-s
* Thats all for now :)

## Usage

Plot fancy cfg-s:

```python
import angr
from angrutils import *
proj = angr.Project("<...>/ais3_crackme", load_options={'auto_load_libs':False})
main = proj.loader.main_bin.get_symbol("main")
start_state = proj.factory.blank_state(addr=main.addr)
cfg = proj.analyses.CFG(fail_fast=True, starts=[main.addr], initial_state=start_state)
for addr,func in proj.kb.functions.iteritems():
    plot_cfg(cfg, "ais3_%s_%x_cfg" % (func.name, addr), asminst=True, vexinst=False, func_addr={addr:True}, remove_imports=True, remove_path_terminator=True)  
```

## TODO

Well, a lot of things :-).
