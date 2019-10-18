import struct
import idc, idautils, ida_name
import ida_bytes
import ida_ua
from consts import *

if idc.BADADDR == 0xFFFFFFFF:
    digits = 8
else:
    digits = 16

def convert_to_byte_array(const):
    byte_array = []
    if const["size"] == "B":
        byte_array = const["array"]
    elif const["size"] == "L":
        for val in const["array"]:
            byte_array += [x for x in bytearray(struct.pack('<L', val))]
    elif const["size"] == "Q":
        for val in const["array"]:
            byte_array += [x for x in bytearray(struct.pack('<Q', val))]
    return byte_array

def main():
    print("[*] loading crypto constants")
    for const in non_sparse_consts:
        const["byte_array"] = convert_to_byte_array(const)

    for start in idautils.Segments():
        print("[*] searching for crypto constants in %s" % idc.get_segm_name(start))
        ea = start
        while ea < idc.get_segm_end(start):
            bbbb = list(struct.unpack("BBBB", idc.get_bytes(ea, 4)))
            for const in non_sparse_consts:
                if bbbb != const["byte_array"][:4]:
                    continue
                if map(lambda x:ord(x), idc.get_bytes(ea, len(const["byte_array"]))) == const["byte_array"]:
                    print(("0x%0" + str(digits) + "X: found const array %s (used in %s)") % (ea, const["name"], const["algorithm"]))
                    idc.set_name(ea, const["name"], ida_name.SN_FORCE)
                    if const["size"] == "B":
                        idc.create_byte(ea)
                    elif const["size"] == "L":
                        idc.create_dword(ea)
                    elif const["size"] == "Q":
                        idc.create_qword(ea)
                    idc.make_array(ea, len(const["array"]))
                    ea += len(const["byte_array"]) - 4
                    break
            ea += 4

        ea = start
        if idc.get_segm_attr(ea, idc.SEGATTR_TYPE) == idc.SEG_CODE:
            while ea < idc.get_segm_end(start):
                d = ida_bytes.get_dword(ea)
                for const in sparse_consts:
                    if d != const["array"][0]:
                        continue
                    tmp = ea + 4
                    for val in const["array"][1:]:
                        for i in range(8):
                            if ida_bytes.get_dword(tmp + i) == val:
                                tmp = tmp + i + 4
                                break
                        else:
                            break
                    else:
                        print(("0x%0" + str(digits) + "X: found sparse constants for %s") % (ea, const["algorithm"]))
                        cmt = idc.get_cmt(idc.prev_head(ea), 0)
                        if cmt:
                            idc.set_cmt(idc.prev_head(ea), cmt + ' ' + const["name"], 0)
                        else:
                            idc.set_cmt(idc.prev_head(ea), const["name"], 0)
                        ea = tmp
                        break
                ea += 1

    print("[*] searching for crypto constants in immediate operand")
    funcs = idautils.Functions()
    for f in funcs:
        flags = idc.get_func_flags(f)
        if (not flags & (idc.FUNC_LIB | idc.FUNC_THUNK)):
            ea = f
            f_end = idc.get_func_attr(f, idc.FUNCATTR_END)
            while (ea < f_end):
                imm_operands = []
                insn = ida_ua.insn_t()
                ida_ua.decode_insn(insn, ea)
                for i in range(len(insn.ops)):
                    if insn.ops[i].type == ida_ua.o_void:
                        break
                    if insn.ops[i].type == ida_ua.o_imm:
                        imm_operands.append(insn.ops[i].value)
                if len(imm_operands) == 0:
                    ea = idc.find_code(ea, idc.SEARCH_DOWN)
                    continue
                for const in operand_consts:
                    if const["value"] in imm_operands:
                        print(("0x%0" + str(digits) + "X: found immediate operand constants for %s") % (ea, const["algorithm"]))
                        cmt = idc.get_cmt(ea, 0)
                        if cmt:
                            idc.set_cmt(ea, cmt + ' ' + const["name"], 0)
                        else:
                            idc.set_cmt(ea, const["name"], 0)
                        break
                ea = idc.find_code(ea, idc.SEARCH_DOWN)
    print("[*] finished")

if __name__ == '__main__':
    main()
