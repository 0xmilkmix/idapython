# patch MIPS binary with call with offsets to get proper xrefs

import idautils
import idc
import idaapi

for f in Functions():
    func = idaapi.get_func(f)
    gp = 0
    for head in Heads(func.startEA,func.endEA):
        if GetMnem(head) == "li" and GetOpnd(head, 0) == "$gp":
            gp = int(GetOpnd(head, 1), 16)
        if gp != 0 and GetMnem(head) == "lw" and ("$gp" in GetOpnd(head, 1)):
            off = GetOpnd(head, 1).split('(')[0].split('-')[1]
            addr = gp - int(off, 16)
            idaapi.add_cref(head, addr, 16)
            idc.MakeComm(head, "%s" % GetFunctionName(Dword(addr)))
            print "[+] adding cref from %x to %x" % (head, addr)
