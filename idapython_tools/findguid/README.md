# FindGUID
An IDAPython script to resolve GUID names like ClassAndInterfaceToNames.py. [ComIDA](https://github.com/airbus-cert/comida) or [COM-Code-Helper](https://github.com/fboldewin/COM-Code-Helper) will be better choices if you want to analyze COM related things only.

FindGUID supports the following GUID types:

* Class ID
* Interface ID
* Folder ID
* Media Type

## How to use
Execute findguid.py on your IDA. Tested on IDA 7.4 for macOS/Windows.

## Todo
1. Python 3 support - Not sure if the script supports Python 3 because I'm still using Python 2 on IDA.
2. Additional GUID support
3. Performance improvement
