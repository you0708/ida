import idc, idaapi, idautils, ida_bytes, ida_search, ida_segment
#import time

junk_patterns_x86 = []
junk_patterns_x64 = []

# .text:100046E4 004 90                                      nop
# .text:100046E5 004 48                                      dec     eax
# .text:100046E6 004 40                                      inc     eax
# .text:100046E7 004 90                                      nop
junk_patterns_x86.append(['90 48 40 90', 4])
junk_patterns_x86.append(['90 40 48 90', 4])

def get_code_segments():
    segments = []
    for ea in idautils.Segments():
        s = ida_segment.getseg(ea)
        if ida_segment.get_segm_class(s) == 'CODE':
            segments.append(s)
    return segments

def main():
    print('[*] start debfuscation')

    for s in get_code_segments():
        print('[*] try to deobfuscate {} section'.format(ida_segment.get_segm_name(s)))

        if s.use32():
            junk_patterns = junk_patterns_x86
        elif s.use64():
            junk_patterns = junk_patterns_x64
        else:
            print('[!] unsupported arch')

        print('[*] replace junk code to nop')
        for pattern, pattern_len in junk_patterns:
            addr_from = idc.find_binary(s.start_ea, ida_search.SEARCH_DOWN, pattern)
            while addr_from != idaapi.BADADDR and addr_from < s.end_ea:
                ida_bytes.patch_bytes(addr_from, '\x90'*pattern_len)
                addr_from = idc.find_binary(addr_from+pattern_len, ida_search.SEARCH_DOWN, pattern)

        print('[*] hide nop code')
        addr_from = ida_search.find_text(s.start_ea, 0, 0, 'nop', ida_search.SEARCH_CASE|ida_search.SEARCH_DOWN)
        while addr_from != idaapi.BADADDR and addr_from < s.end_ea:
            func_offset = idc.get_func_off_str(addr_from) 
            if type(func_offset) == str and func_offset.find('+') == -1:
                addr_from = ida_search.find_text(idc.next_head(addr_from), 0, 0, 'nop', ida_search.SEARCH_CASE|ida_search.SEARCH_DOWN)
            else:
                i = 0
                while True:
                    if ida_bytes.get_byte(addr_from+i) == 0x90:
                        i += 1
                    else:
                        break
                if i >= 3:
                    idc.add_hidden_range(addr_from, addr_from+i, 'nop', None, None, 0xFFFFFFFF)
                    print("%08X" % addr_from)
                addr_from = ida_search.find_text(idc.next_head(addr_from+i), 0, 0, 'nop', ida_search.SEARCH_CASE|ida_search.SEARCH_DOWN)

        #print('[*] renanlyze')
        #idc.del_items(s.start_ea, size=s.size())
        #time.sleep(1)
        #idc.plan_and_wait(s.start_ea, s.end_ea)
    print('[*] done')

if __name__ == '__main__':
    main()
