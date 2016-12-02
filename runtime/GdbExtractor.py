'''
Extractor for GDB
'''
import subprocess
import fcntl
import os
import time
import re
import json

class GdbExtractor(object):
    '''
    Gdb Extractor interfaces Gdb to extract information,
    such as arguments for a particular frame
    '''
    # _re_gdb_startup = re.compile(  r"""
    #                                 .+
    #                                 \[New\sLWP\s(?P<pid>[0-9]+)\]
    #                                 .+
    #                                 Core\swas\sgenerated\sby\s\`
    #                                 (?P<cmdline>[A-Za-z0-9./\s\$=_:,+-]+)\'\.
    #                                 """, re.VERBOSE | re.DOTALL)
    
    # _re_gdb_var_info = re.compile(  r"""
    #                                 ^(?P<var_name>(\$)?[A-Za-z0-9_?]+)
    #                                 \s=\s
    #                                 (\(.+?\)\s)?
    #                                 (?P<value>((@)?0x[A-Fa-f0-9]+)?([0-9\-]+)?(<[a-z\s]+>)?([A-Za-z0-9_?]+)?)(:)?
    #                                 (\s)?(<[a-z\.]+>\s)?
    #                                 ((?P<data>(\"|\').*?(\"$|\'$|>$))?
    #                                 (?P<blob>(\{).+?(>$|\}$))?)?
    #                                 """, re.VERBOSE | re.DOTALL | re.MULTILINE)
    #
    # _re_gdb_var_info_comma_sep = re.compile(  r"""
    #                                 (?P<var_name>(\$)?[A-Za-z0-9_?]+)
    #                                 \s=\s
    #                                 (\(.+?\)\s)?
    #                                 (?P<value>((@)?0x[A-Fa-f0-9]+)?([0-9\-]+)?(\s)?(<[a-z\s]+>)?([A-Za-z0-9_?]+)?)(:)?
    #                                 (<[a-z\.]+>)?((\s)?
    #                                 (?P<data>(\"|\').*?(\"|\'|>))((?=([.]+)?,\s[^"^'])|\}|$))?((\s)?
    #                                 (?P<blob>(\{).+?([\"\'\}]+))(?=;\s|$))?
    #                                 """, re.VERBOSE | re.DOTALL)
    #
    # _re_gdb_type_info = re.compile( r"""
    #                                 ^type\s=\s
    #                                 (?P<type>(struct\s|class\s)?(([A-Za-z0-9_<>, ]+::)+)?[A-Za-z0-9\_ ]+)     # Optional Namespace and Base type
    #                                 (\s)?(.+\}(\s)?)?((?P<modifier>[0-9\[\]\*\&]+))?                          # Type modifier (Array, Ptr, Reference)
    #                                 """, re.VERBOSE | re.DOTALL);
    #
    # _re_gdb_blob_normalize = re.compile(r"""
    #                                     (\"|\')(?P<data>.+?)(\",\s|\"$|\'\s)(<repeats\s(?P<repeat>[0-9]+)\stimes>)?
    #                                     """, re.VERBOSE | re.DOTALL)

    _re_gdb_bt = re.compile(r"""
                        ^\s*\#(?P<frame_no>[0-9]+)\s*
                        (?P<address>0x[A-Fa-f0-9]+)\s
                        (in\s)?((?P<func>[A-Za-z0-9_:\?<>,\s]+)
                        ((?P<paramlist>\([A-Za-z0-9_:\&\,\s\*]*\)))?\s)?
                        ((?P<file>.+?):(?P<line>[0-9]+)(:(?P<column>[0-9]+))?)?
                        ((\s)?\((?P<module>.+?)\+(?P<offset>0x[A-Fa-f0-9]+)\))?
                        """, re.MULTILINE | re.VERBOSE)

    _re_gdb_signal = re.compile(r""".*Program received signal (?P<sig>\w+),.*""", re.DOTALL)
    _re_exp_class = re.compile(r""".*Exploitability Classification: (?P<classification>\w+)\s*""", re.DOTALL)
    _re_exp_others = re.compile(r""".*Other tags: (?P<tags>[A-Za-z0-9()/\s]+)\nFaulting.*""", re.DOTALL)
    _re_fault_info = re.compile(r"""
                                Faulting mem location is (?P<faddr>0x[A-Fa-f0-9]+),             # Fault mem addr
                                pc is (?P<pc>0x[A-Fa-f0-9]+),                                       # Faulting PC
                                esp is (?P<esp>0x[A-Fa-f0-9]+),                                     # Stack pointer
                                ebp is (?P<ebp>0x[A-Fa-f0-9]+)                                  # Base pointer
                                """, re.VERBOSE)
    
    def __init__(self, program, params, jsonfile):
        '''
        Constructor
        '''
        self._pid = int(0)
        self._cmd_line = ""
        self.jsonfile = jsonfile
        
        '''
        Requires ~/.gdbinit to have something like this (basically rc0r's exploitable patch + some scripted commands):
        set auto-load safe-path /
        define hook-quit
            set confirm off
        end
        define printfault
            printf "Faulting mem location is %#lx, pc is %#lx, esp is %#x, ebp is %#x\n", $_siginfo._sifields._sigfault.si_addr, $pc, $esp, $ebp
        end
        source /home/users/bshastry/.local/lib/python3.5/site-packages/exploitable-1.32_rcor-py3.5.egg/exploitable/exploitable.py
        set pagination off
        '''

        self.p = subprocess.Popen(['gdb', '-q', '-ex=set args {}'.format(params), '-ex=r',
                                   '-ex=exploitable', '-ex=printfault', '-ex=bt', '-ex=quit', program],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        # fl = fcntl.fcntl(self.p.stdout, fcntl.F_GETFL)
        # fcntl.fcntl(self.p.stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        
    def run(self):
        # FIXME: Error handling if necessary
        diag_report = self.p.communicate()[0]
        match = self._re_gdb_signal.match(diag_report)
        if match is not None:
            self._signal = match.group("sig")
        match = self._re_exp_class.search(diag_report)
        if match is not None:
            self._classification = match.group("classification")
        match = self._re_exp_others.search(diag_report)
        if match is not None:
            self._tags = match.group("tags")
        match = self._re_fault_info.match(diag_report)
        if match is not None:
            self._faultaddr = match.group("faddr")
            self._faultpc = match.group("pc")
            self._esp = match.group("esp")
            self._ebp = match.group("ebp")
        # Backtrace of fault
        # start = diag_report.find("    #")
        # end = 0
        # for line in diag_report[start:].splitlines():
        #     if line.startswith("    #"):
        #         end = diag_report.find(line)
        #         end += diag_report[end:].find("\n")
        #     else:
        #         break

        self._fault_bt = {}
        for match in self._re_gdb_bt.finditer(diag_report):
            frame_no, address, func, paramlist, filename, line, column, module, offset = match.group("frame_no",
                                                                                                     "address", "func",
                                                                                                     "paramlist",
                                                                                                     "file", "line",
                                                                                                     "column", "module",
                                                                                                     "offset")
            frame_str = "frame{}".format(frame_no)

            self._fault_bt[frame_str] = {"frame_no": frame_no,
                                          "address": address,
                                          "function": func,
                                          "func_params": paramlist,
                                          }
            if filename and line and column:
                self._fault_bt[frame_str]['file'] = filename
                self._fault_bt[frame_str]['line'] = line
                self._fault_bt[frame_str]['column'] = column
            if module and offset:
                self._fault_bt[frame_str]['module'] = module
                self._fault_bt[frame_str]['offset'] = offset
        self.jsonify()
        return True

    def serialize(self):
        serial_dict = {}
        for key, value in self.__dict__.iteritems():
            attr = getattr(self, key)
            if not key.startswith('__') and not callable(attr) and not type(attr) is staticmethod:
                if type(value) is str or type(value) is int:
                    serial_dict[key] = value
                if type(value) is dict and key is '_fault_bt':
                    serial_dict[key] = value
        return serial_dict

    def jsonify(self):
        with open(self.jsonfile, 'w') as file:
            json.dump(self.serialize(), file, indent=4)

    def _read_one_shot(self, blocking = 0.09):
        with open('.orthrus_gdbout', 'r') as fp:
            return fp.read()

        # buf = ''
        # try:
        #     buf = self.p.stdout.read()
        # except IOError:
        #     time.sleep(blocking)
        #     self.p.stdout.flush()
        # finally:
        #     if not buf:
        #         buf = self.p.stdout.read()
        # return buf

    # def _send(self, cmd):
    #     self.p.stdin.write(cmd + '\n')
    #     self.p.stdin.flush()
    #
    # def _readAll(self):
    #     blocking = 0.001
    #     return self._read(blocking)
    #
    # def _read(self, blocking = 0):
    #     buf = ''
    #     while True:
    #         try:
    #             buf += self.p.stdout.read()
    #         except IOError:
    #             time.sleep(blocking)
    #             self.p.stdout.flush()
    #             if buf.find("(gdb)") > -1:
    #                 break
    #     return buf[0:buf.find("(gdb)") - 1]
    #
    # def _selectFrameByName(self, function):
    #     if function == None:
    #         return False
    #     self._send("frame 0")
    #     while True:
    #         data = self._readAll()
    #         if "you cannot go up." in data:
    #             return False
    #         if " " + function + " (" in data:
    #             return True
    #         if " __interceptor_" + function + " (" in data:
    #             return True
    #         self._send("up")
    #
    #     return False
    #
    # def _getTypeForVar(self, var_name):
    #     vartype = ""
    #     self._send("ptype " + var_name)
    #     typeinfo = self._readAll()
    #     if "You can't do that without a process to debug." in typeinfo:
    #         return ""
    #
    #     match = self._re_gdb_type_info.search(typeinfo)
    #     if match:
    #         vartype = match.group("type")
    #         if vartype:
    #             vartype = vartype.rstrip(" ")
    #         modifier = match.group("modifier")
    #         if modifier != None:
    #             vartype += " " + modifier
    #
    #     return vartype
    #
    # def _getInfoForVar(self, var_name, ptrBaseType, depth = 1):
    #     if depth == 0:
    #         return ("", "")
    #
    #     cmd = ""
    #     if ptrBaseType:
    #         cmd = "p *"
    #     else:
    #         cmd = "p "
    #
    #     self._send(cmd + var_name)
    #     rawdata = self._readAll()
    #     if rawdata.startswith("Attempt to dereference a generic pointer."):
    #         return ("", "")
    #     if rawdata.startswith("Cannot access memory at address"):
    #         return ("", "")
    #     if rawdata.startswith("No symbol \"operator*\""):
    #         return ("", "")
    #     if rawdata.startswith("value has been optimized out"):
    #         return ("", "")
    #
    #     tmp = ""
    #     for line in rawdata.splitlines(False):
    #         tmp += line.lstrip(" ")
    #     rawdata = tmp
    #
    #     match = self._re_gdb_var_info.search(rawdata)
    #     value, blob = match.group("value", "blob")
    #
    #     if not blob:
    #         return ("", (value or ""))
    #
    #     blob_copy = blob
    #     blob = self._insertBlobTerminator(blob)
    #     offset = 0
    #
    #     data_dict = OrderedDict()
    #     for mat in self._re_gdb_var_info_comma_sep.finditer(blob):
    #         var, val, da, bl = mat.group("var_name", "value", "data", "blob")
    #         var_end = mat.end("var_name")
    #
    #         ty = self._getTypeForVar(var_name + "." + var)
    #         ty = "<"  + ty + "> "
    #         blob_copy = blob_copy[:offset + var_end + 3] + ty + blob_copy[offset + var_end + 3:]
    #         offset += len(ty)
    #
    #         if da and isinstance(da, str)  and (" <repeats " in da):
    #             da = self._normalizeData(da)
    #
    #         data_dict[var] = [ty, val, da, bl]
    #         # Try to emplace the blob of descendant
    #         if ("*" in ty) and ("0x" in val) and (da == None):
    #             val_end = mat.end("value")
    #             rec_blob, rec_data = self._getInfoForVar(var_name + "." + var, True, depth - 1)
    #             blob_copy = blob_copy[:offset + val_end] + " " + rec_blob + blob_copy[offset + val_end:]
    #             offset += len(" " + rec_blob)
    #
    #             data_dict[var] = [ty, val, rec_data, bl]
    #
    #         if bl and ((val == None) or val == ""):
    #             bl_start = mat.start("blob")
    #             bl_end = mat.end("blob")
    #             rec_blob, rec_data = self._getInfoForVar(var_name + "." + var, False, depth - 1)
    #
    #             blob_copy = blob_copy[:offset + bl_start] + rec_blob + blob_copy[offset + bl_end:]
    #             offset -= len(bl)
    #             offset += len(rec_blob)
    #
    #             data_dict[var] = [ty, val, rec_data, bl]
    #
    #     if not data_dict and blob_copy:
    #         data_dict = blob_copy.lstrip("{").rstrip("}").replace(", ", ";").split(";")
    #
    #     return (blob_copy, data_dict)
    #
    # def _insertBlobTerminator(self, blob):
    #     level = 0
    #     start = False
    #
    #     bloblist = list(blob)
    #     for i, c in enumerate(bloblist):
    #         if "{" in c:
    #             level += 1
    #             start = True
    #         if "}" in c:
    #             level -= 1
    #         if start and level == 1:
    #             if bloblist[i + 1] == ",":
    #                 bloblist[i + 1] = ";"
    #             start = False
    #     return "".join(bloblist)
    #
    # def _normalizeData(self, rawdata):
    #     normalized = "\""
    #     for match in self._re_gdb_blob_normalize.finditer(rawdata):
    #         data, repeat = match.group("data", "repeat")
    #         if repeat:
    #             repeat = int(repeat)
    #             while repeat > 0:
    #                 normalized += data
    #                 repeat -= 1
    #         else:
    #             normalized += data
    #
    #     return normalized + "\""
    #
    # def getSymbolsInSourceLineForPc(self, pc):
    #     sym = list()
    #     re_vars = re.compile("(?P<symbol>[a-zA-Z0-9_]+)")
    #     self._send("list *" + pc + ",*" + pc)
    #     rawdata = self._readAll().splitlines()[1]
    #     rawdata = rawdata[rawdata.find(" "):].lstrip(" ")
    #
    #     for match in re_vars.finditer(rawdata):
    #         sym.append(match.group("symbol"))
    #
    #     return sym
    #
    # def getArglistByFuncName(self, function):
    #     args = OrderedDict()
    #     if self._selectFrameByName(function) == False:
    #         return OrderedDict()
    #
    #     self._send("info args")
    #     rawdata = self._readAll()
    #     if "No arguments" in rawdata:
    #         return OrderedDict()
    #
    #     for match in self._re_gdb_var_info.finditer(rawdata):
    #         var_name, value, data, blob = match.group("var_name", "value", "data", "blob")
    #         vartype = self._getTypeForVar(var_name)
    #
    #         # Try to derefence pointer to extract more information
    #         if not blob and not data and ("0x" in value) and ("*" in vartype):
    #             blob, data = self._getInfoForVar(var_name, True, 5)
    #
    #         if blob and (not value or "@" in value) and ("*" not in vartype):
    #             blob, data = self._getInfoForVar(var_name, False, 5)
    #
    #         if data and isinstance(data, str)  and (" <repeats " in data):
    #             data = self._normalizeData(data)
    #
    #         if data and isinstance(data, str) and ("<incomplete sequence" in data):
    #             data = data[:data.find("<incomplete sequence")].lstrip("\"").rstrip(" \",")
    #
    #         args[var_name] = [vartype, value, data, blob]
    #
    #     return args
    #
    # def getLocalsByFuncName(self, function):
    #     locs = OrderedDict()
    #     if self._selectFrameByName(function) == False:
    #         return OrderedDict()
    #
    #     self._send("info locals")
    #     rawdata = self._readAll()
    #     if "No locals" in rawdata:
    #         return OrderedDict()
    #
    #     for match in self._re_gdb_var_info.finditer(rawdata):
    #         var_name, value, data, blob = match.group("var_name", "value", "data", "blob")
    #         vartype = self._getTypeForVar(var_name)
    #
    #         # Try to derefence pointer to extract more information
    #         if not blob and not data and value and ("*" in vartype):
    #             blob, data = self._getInfoForVar(var_name, True, 5)
    #
    #         if blob and (not value or "@" in value) and ("*" not in vartype):
    #             blob, data = self._getInfoForVar(var_name, False, 5)
    #
    #         if data and isinstance(data, str) and (" <repeats " in data):
    #             data = self._normalizeData(data)
    #
    #         if data and isinstance(data, str) and ("<incomplete sequence" in data):
    #             data = data[:data.find("<incomplete sequence")].lstrip("\"").rstrip(" \",")
    #
    #         locs[var_name] = [vartype, value, data, blob]
    #
    #     return locs
    
    @property
    def pid(self):
        """ Process ID """
        return self._pid
    
    @property
    def command_line(self):
        """ Command line of execution """
        return self._cmd_line