'''
Gdb-Orthrus
'''

try:
    import gdb
except ImportError as e:
    raise ImportError("This script must be run in GDB: ", str(e))

import json
import re

class GdbOrthrus(gdb.Function):
    """JSONify core dump via GDB python plugin. Takes jsonfile as arg"""


    _re_gdb_bt = re.compile(r"""
                        ^\#(?P<frame_no>[0-9]+)\s*
                        ((?P<address>0x[A-Fa-f0-9]+)\s*)?
                        (in\s(?P<func>[A-Za-z0-9_:\-\?<>,]+)\s*)?
                        (?P<paramlist>\([A-Za-z0-9_\'\"\\\=\-:\&\,\s\*]*\)\s*)?
                        (at\s*(?P<file>[A-Za-z0-9_\.\-]*):(?P<line>[0-9]+)\s*)?
                        ((\s)?\((?P<module>.+?)\+(?P<offset>0x[A-Fa-f0-9]+)\))?
                        """, re.MULTILINE | re.VERBOSE)
    _re_gdb_exploitable = re.compile(r".*Description: (?P<desc>[\w|\s]+).*"
                                     r"Short description: (?P<shortdesc>[\w|\s\(\)\/]+).*"
                                     r"Hash: (?P<hash>[0-9A-Za-z\.]+).*"
                                     r"Exploitability Classification: (?P<class>[A-Z_]+).*"
                                     r"Explanation: (?P<explain>[\w|\s|\.|\/,]+).*"
                                     r"Other tags: (?P<other>[\w|\s,\(\)\/]+).*",
                                     re.DOTALL)

    def __init__(self):
        super(GdbOrthrus, self).__init__("jsonify")
        self.gdb_dict = {}

    def invoke(self, jsonfile):
        self.jsonfile = jsonfile.string()

        ## Get and parse backtrace
        bt_string = gdb.execute("bt", False, True)
        bt_dict = {}
        for match in self._re_gdb_bt.finditer(bt_string):
            frame_no, address, func, paramlist, filename, line, module, offset = \
                match.group("frame_no", "address", "func", "paramlist", "file", "line", "module", "offset")
            frame_str = "frame{}".format(frame_no)

            bt_dict[frame_str] = {"frame_no": frame_no, "address": address, "function": func, "func_params": paramlist }

            if filename and line:
                bt_dict[frame_str]['file'] = filename
                bt_dict[frame_str]['line'] = line
            if module and offset:
                bt_dict[frame_str]['module'] = module
                bt_dict[frame_str]['offset'] = offset
        self.gdb_dict['backtrace'] = bt_dict
        self.gdb_dict['debug'] = bt_string


        # Parse fault address and exploitable output
        self.gdb_dict['fault_addr'] = gdb.execute('printf "%#lx", $_siginfo._sifields._sigfault.si_addr', False, True)
        exp_string = gdb.execute('exploitable', False, True)
        match = self._re_gdb_exploitable.match(exp_string)
        if match is not None:
            exp_dict = {}
            exp_dict['description'] = match.group("desc").rstrip()
            exp_dict['short_desc'] = match.group("shortdesc").rstrip()
            exp_dict['hash'] = match.group("hash").rstrip()
            exp_dict['classification'] = match.group("class").rstrip()
            exp_dict['explanation'] = match.group("explain").rstrip()
            exp_dict['tags'] = match.group("other").rstrip()
            self.gdb_dict['exploitable_info'] = exp_dict

        with open(self.jsonfile, 'w') as fp:
            json.dump(self.gdb_dict, fp, indent=4)
        return True

GdbOrthrus()