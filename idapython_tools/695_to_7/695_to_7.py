import platform, re, os
import argparse

if platform.system() == 'Darwin':
    BC695_FILE = '/Applications/IDA Pro 7.5/ida.app/Contents/MacOS/python/2/idc_bc695.py'
elif platform.system() == 'Windows':
    BC695_FILE = 'C:\\Program Files\\IDA Pro 7.5\\python\\2\\idc_bc695.py'
else:
    print('[!] Unsupported OS')
    exit()

# def AskYN(defval, prompt): return ask_yn(defval, prompt)
# Warning=ida_kernwin.warning
DEF_PATTERNS = [re.compile(r'def ([^\(]+)\(.*\): return ([^\(]+)\(.*\)'),
                re.compile(r'(.+)=(.+)')]

IDAPYTHON_DOC_URL = 'https://www.hex-rays.com/products/ida/support/idapython_docs/toc-everything.html'
IDAPYTHON_DOC_HTML = os.path.join(os.path.dirname(__file__), '695_to_7_doc.html')

def main():
    parser = argparse.ArgumentParser(description="IDAPython API name converter")
    parser.add_argument("-o", "--out", action="store", dest="out", help="Specify output file name")
    parser.add_argument("FILE", help="Input IDAPython script")
    args = parser.parse_args()

    if args.out:
        out_file = args.out
    else:
        root, ext = os.path.splitext(args.FILE)
        out_file = root + "_new.py"
    
    print('[*] Read {}'.format(BC695_FILE))
    fp = open(BC695_FILE, 'r')
    bc695 = []
    for line in fp.readlines():
        line = line.strip('\n')
        for pattern in DEF_PATTERNS:
            m = re.match(pattern, line)
            if m:
                bc695.append([m.group(1), m.group(2), line])
                break
    fp.close()

    if os.path.exists(IDAPYTHON_DOC_HTML):
        print('[*] Read {}'.format(IDAPYTHON_DOC_HTML))
        fp = open(IDAPYTHON_DOC_HTML, 'r')
        text = fp.read()
        fp.close()
    else:
        print('[*] Obtain new API name list from {}'.format(IDAPYTHON_DOC_URL))
        import requests
        response = requests.get(IDAPYTHON_DOC_URL)
        text = response.text
        fp = open(IDAPYTHON_DOC_HTML, 'w')
        fp.write(text)
        fp.close()
    html_tag_pattern = re.compile(r"<[^>]*?>")
    new_names = sorted(set(html_tag_pattern.sub("", text).split(' ')), reverse=True)

    replace_list = []
    for old, new, line in bc695:
        if new.isdigit() or new.startswith('0x') or len(new.split('.')) == 2:
            replace_list.append([old, new, line])
            continue
        for name in new_names:
            if new in name:
                replace_list.append([old, name, line])
                break

    print('[*] Convert {}'.format(args.FILE))
    fp = open(args.FILE, 'r')
    data = fp.read()
    fp.close()
    used_modules = []
    flag_modified = False
    for old, new, line in replace_list:
        tmp = re.sub(re.compile(r'([ \n])(idc\.|idaapi\.)*'+old), r'\1'+new, data)
        if data != tmp:
            flag_modified = True
            print(format(line))
            used_modules.append(new.split('.')[0])
            data = tmp
    
    if flag_modified:
        fp = open(out_file, 'w')
        fp.write(data)
        fp.close()
        print('[*] Save converted script as {}'.format(out_file))
        print('[*] The script is using the following modules:\n{}'.format(', '.join(set(used_modules))))
    else:
        print('[*] Nothing to do')

if __name__ == "__main__":
    main()