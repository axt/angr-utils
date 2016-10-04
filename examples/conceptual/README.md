No source code is provided here. These are just conceptual graphs, to demonstrate future plans, but the API of this is not stabilized yet.

## Taint tracking in cfg
ASM | VEX
--- | ---
![cfg_asm][cfg_asm] | ![cfg_vex][cfg_vex]

## DDG #1
Statement graph | Data graph
--- | ---  
![ddg_stmt][ddg_stmt] | ![ddg_data][ddg_data]

## DDG #2 
32bit | 64 bit
--- | --- 
![ddg_hr1][ddg_hr1] | ![ddg_hr2][ddg_hr2]

[cfg_asm]: https://raw.githubusercontent.com/axt/angr-utils/master/examples/conceptual/cfg_asm_annotated.png
[cfg_vex]: https://raw.githubusercontent.com/axt/angr-utils/master/examples/conceptual/cfg_vex_annotated.png
[ddg_stmt]: https://raw.githubusercontent.com/axt/angr-utils/master/examples/conceptual/ddg_stmt.png
[ddg_data]: https://raw.githubusercontent.com/axt/angr-utils/master/examples/conceptual/ddg_data.png
[ddg_hr1]: http://i.imgur.com/CrrCRBW.png
[ddg_hr2]: http://i.imgur.com/ekX0lxO.png
