# FindGUID
An IDAPython script to resolve GUID names like ClassAndInterfaceToNames.py. [ComIDA](https://github.com/airbus-cert/comida) or [COM-Code-Helper](https://github.com/fboldewin/COM-Code-Helper) will be better choices if you want to analyze COM related things only.

FindGUID supports the following GUID types:

* Class ID
* Interface ID
* Folder ID
* Media Type

## How to use
Execute findguid.py on your IDA. Tested on IDA 7.6 for macOS/Windows.

## Todo
1. Additional GUID support
2. Performance improvement
