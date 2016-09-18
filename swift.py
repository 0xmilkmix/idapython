import idc
import idaapi
import subprocess

ea = ScreenEA()
for funcea in Functions(SegStart(ea), SegEnd(ea)):
    name = GetFunctionName(funcea)
    if name.startswith("__T") or name.startswith("_T"):
        newname = subprocess.check_output(['xcrun', 'swift-demangle', '--compact', name])
        idc.MakeComm(funcea, newname)
