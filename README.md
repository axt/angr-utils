# angr-utils

Angr-utils is a collection of utilities for [angr](https://github.com/angr/angr) binary analysis framework.

## Note

Visualisation for various graphs (currently supported: CFG, CG; planned: DFG, CDG, DDG) has been moved to [bingraphvis](https://github.com/axt/bingraphvis).

The API of the facade functions in `visualize.py` are considered stable (except marked otherwise in comment), and should not break between releases, although they provide only a limited subset of [bingraphvis](https://github.com/axt/bingraphvis) functionalities.

This tool is not designed to support interactive CFGs. For full interactivity, check out [angr-management](https://github.com/angr/angr-management), for navigable static CFGs check out [cfg-explorer](https://github.com/axt/cfg-explorer).

## Main functionality
* CFG visualisation
* Pretty printers
* Utility functions

## Install
```
cd angr-dev
git clone https://github.com/axt/bingraphvis
pip install -e ./bingraphvis
git clone https://github.com/axt/angr-utils
pip install -e ./angr-utils
```
## Usage

**See [examples][examples] for more details.**

Plot fancy cfg-s:

```python
import angr
from angrutils import *
proj = angr.Project("<...>/ais3_crackme", load_options={'auto_load_libs':False})
main = proj.loader.main_object.get_symbol("main")
start_state = proj.factory.blank_state(addr=main.rebased_addr)
cfg = proj.analyses.CFGEmulated(fail_fast=True, starts=[main.rebased_addr], initial_state=start_state)
plot_cfg(cfg, "ais3_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)  
```

![cfg][cfg]

[cfg]: https://i.imgur.com/QnxZzSF.png
[examples]: https://github.com/axt/angr-utils/tree/master/examples
