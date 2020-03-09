# 695 to 7 - IDAPython API name converter
A Python script to convert IDAPython API names from 6.x to 7.x.

## How to use
Execute 695_to_7.py as the following:
```
$ python 695_to_7.py test.py 
[*] Read /Applications/IDA Pro 7.4/ida.app/Contents/MacOS/python/2/idc_bc695.py
[*] Read idapython_tools/695_to_7/695_to_7_doc.html
[*] Save converted script as test_new.py
[*] The script is using the following modules:
ida_kernwin, ida_ua
$
$ diff test.py test_new.py
10,11c10,11
<     start_addr = AskAddr(ScreenEA(), 'Start address')
<     end_addr   = AskAddr(ScreenEA(), 'End address')
---
>     start_addr = ida_kernwin.ask_addr(ida_kernwin.get_screen_ea(), 'Start address')
>     end_addr   = ida_kernwin.ask_addr(ida_kernwin.get_screen_ea(), 'End address')
13c13
<         data = GetOpnd(ea, 1)
---
>         data = ida_ua.print_operand(ea, 1)
```

The script attempts to download https://www.hex-rays.com/products/ida/support/idapython_docs/toc-everything.html if 695_to_7_doc.html doesn't exist, 

```

```
