# angr-utils

Angr-utils is a collection of utilities for [angr](https://github.com/angr/angr) binary analysis framework.

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
plot_cfg(cfg, "ais3_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)  
```

## TODO

Well, a lot of things :-).
