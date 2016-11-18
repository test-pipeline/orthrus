'''
Extractor for GDB
'''
import subprocess
import fcntl
import os
import sys
import time
import re
from collections import OrderedDict

class GdbExtractor(object):
    '''
    Gdb Extractor interfaces Gdb to extract information,
    such as arguments for a particular frame
    '''
    _re_gdb_startup = re.compile(  r"""
                                    .+
                                    \[New\sLWP\s(?P<pid>[0-9]+)\]
                                    .+
                                    Core\swas\sgenerated\sby\s\`
                                    (?P<cmdline>[A-Za-z0-9./\s\$=_:,+-]+)\'\.
                                    """, re.VERBOSE | re.DOTALL)
    
    _re_gdb_var_info = re.compile(  r"""
                                    ^(?P<var_name>(\$)?[A-Za-z0-9_?]+)
                                    \s=\s
                                    (\(.+?\)\s)?
                                    (?P<value>((@)?0x[A-Fa-f0-9]+)?([0-9\-]+)?(<[a-z\s]+>)?([A-Za-z0-9_?]+)?)(:)?
                                    (\s)?(<[a-z\.]+>\s)?
                                    ((?P<data>(\"|\').*?(\"$|\'$|>$))?
                                    (?P<blob>(\{).+?(>$|\}$))?)?
                                    """, re.VERBOSE | re.DOTALL | re.MULTILINE)
    
    _re_gdb_var_info_comma_sep = re.compile(  r"""
                                    (?P<var_name>(\$)?[A-Za-z0-9_?]+)
                                    \s=\s
                                    (\(.+?\)\s)?
                                    (?P<value>((@)?0x[A-Fa-f0-9]+)?([0-9\-]+)?(\s)?(<[a-z\s]+>)?([A-Za-z0-9_?]+)?)(:)?
                                    (<[a-z\.]+>)?((\s)?
                                    (?P<data>(\"|\').*?(\"|\'|>))((?=([.]+)?,\s[^"^'])|\}|$))?((\s)?
                                    (?P<blob>(\{).+?([\"\'\}]+))(?=;\s|$))?
                                    """, re.VERBOSE | re.DOTALL)
    
    _re_gdb_type_info = re.compile( r"""
                                    ^type\s=\s
                                    (?P<type>(struct\s|class\s)?(([A-Za-z0-9_<>, ]+::)+)?[A-Za-z0-9\_ ]+)     # Optional Namespace and Base type
                                    (\s)?(.+\}(\s)?)?((?P<modifier>[0-9\[\]\*\&]+))?                          # Type modifier (Array, Ptr, Reference)
                                    """, re.VERBOSE | re.DOTALL);
                                    
    _re_gdb_blob_normalize = re.compile(r"""
                                        (\"|\')(?P<data>.+?)(\",\s|\"$|\'\s)(<repeats\s(?P<repeat>[0-9]+)\stimes>)?
                                        """, re.VERBOSE | re.DOTALL)
    
    def __init__(self, program, corefile, verbose=False):
        '''
        Constructor
        '''
        self._pid = int(0)
        self._cmd_line = ""
        self._verbose = verbose
        
        if self._verbose:
            sys.stdout.write("Using program: " + program + "\n")
            sys.stdout.write("Using core file: " + corefile + "\n")
        
        self.p = subprocess.Popen(['gdb',
                                         '--se=' + program, 
                                         '--core=' + corefile,
                                         '--quiet',
                                         '--nx'], 
                                         bufsize = 0, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds = True)
        fl = fcntl.fcntl(self.p.stdout, fcntl.F_GETFL)
        fcntl.fcntl(self.p.stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        
        data = self._readAll()
        match = self._re_gdb_startup.search(data)
        if match != None:
            self._pid = int(match.group("pid"))
            self._cmd_line = match.group("cmdline")

    def _send(self, cmd):
        self.p.stdin.write(cmd + '\n')
        self.p.stdin.flush()
        
    def _readAll(self):
        blocking = 0.001
        return self._read(blocking)
    
    def _read(self, blocking = 0):
        buf = ''
        while True:
            try:
                buf += self.p.stdout.read()
            except IOError:
                time.sleep(blocking)
                self.p.stdout.flush()
                if buf.find("(gdb)") > -1:
                    break
        return buf[0:buf.find("(gdb)") - 1]
    
    def _selectFrameByName(self, function):
        if function == None:
            return False
        self._send("frame 0")
        while True:
            data = self._readAll()
            if "you cannot go up." in data:
                return False
            if " " + function + " (" in data:
                return True
            if " __interceptor_" + function + " (" in data:
                return True
            self._send("up")
            
        return False
    
    def _getTypeForVar(self, var_name):
        vartype = ""
        self._send("ptype " + var_name)
        typeinfo = self._readAll()
        if "You can't do that without a process to debug." in typeinfo:
            return ""
        
        match = self._re_gdb_type_info.search(typeinfo)
        if match:
            vartype = match.group("type")
            if vartype:
                vartype = vartype.rstrip(" ")
            modifier = match.group("modifier")
            if modifier != None:
                vartype += " " + modifier
        
        return vartype
    
    def _getInfoForVar(self, var_name, ptrBaseType, depth = 1):
        if depth == 0:
            return ("", "")
        
        cmd = ""
        if ptrBaseType:
            cmd = "p *"
        else:
            cmd = "p "

        self._send(cmd + var_name)
        rawdata = self._readAll()
        if rawdata.startswith("Attempt to dereference a generic pointer."):
            return ("", "")
        if rawdata.startswith("Cannot access memory at address"):
            return ("", "")
        if rawdata.startswith("No symbol \"operator*\""):
            return ("", "")
        if rawdata.startswith("value has been optimized out"):
            return ("", "")
        
        tmp = ""
        for line in rawdata.splitlines(False):
            tmp += line.lstrip(" ")
        rawdata = tmp
        
        match = self._re_gdb_var_info.search(rawdata)
        value, blob = match.group("value", "blob")

        if not blob:
            return ("", (value or ""))
        
        blob_copy = blob
        blob = self._insertBlobTerminator(blob)
        offset = 0

        data_dict = OrderedDict()
        for mat in self._re_gdb_var_info_comma_sep.finditer(blob):
            var, val, da, bl = mat.group("var_name", "value", "data", "blob")
            var_end = mat.end("var_name")
            
            ty = self._getTypeForVar(var_name + "." + var)
            ty = "<"  + ty + "> "
            blob_copy = blob_copy[:offset + var_end + 3] + ty + blob_copy[offset + var_end + 3:]
            offset += len(ty)
            
            if da and isinstance(da, str)  and (" <repeats " in da):
                da = self._normalizeData(da)
                
            data_dict[var] = [ty, val, da, bl]
            # Try to emplace the blob of descendant
            if ("*" in ty) and ("0x" in val) and (da == None):
                val_end = mat.end("value")
                rec_blob, rec_data = self._getInfoForVar(var_name + "." + var, True, depth - 1)
                blob_copy = blob_copy[:offset + val_end] + " " + rec_blob + blob_copy[offset + val_end:]
                offset += len(" " + rec_blob)
                
                data_dict[var] = [ty, val, rec_data, bl]

            if bl and ((val == None) or val == ""):
                bl_start = mat.start("blob")
                bl_end = mat.end("blob")
                rec_blob, rec_data = self._getInfoForVar(var_name + "." + var, False, depth - 1)

                blob_copy = blob_copy[:offset + bl_start] + rec_blob + blob_copy[offset + bl_end:]
                offset -= len(bl)
                offset += len(rec_blob)
                
                data_dict[var] = [ty, val, rec_data, bl]
        
        if not data_dict and blob_copy:
            data_dict = blob_copy.lstrip("{").rstrip("}").replace(", ", ";").split(";")
            
        return (blob_copy, data_dict)
    
    def _insertBlobTerminator(self, blob):
        level = 0
        start = False
        
        bloblist = list(blob)
        for i, c in enumerate(bloblist):
            if "{" in c:
                level += 1
                start = True
            if "}" in c:
                level -= 1
            if start and level == 1:
                if bloblist[i + 1] == ",":
                    bloblist[i + 1] = ";"
                start = False
        return "".join(bloblist)
                
    def _normalizeData(self, rawdata):
        normalized = "\""
        for match in self._re_gdb_blob_normalize.finditer(rawdata):
            data, repeat = match.group("data", "repeat")
            if repeat:
                repeat = int(repeat)
                while repeat > 0:
                    normalized += data
                    repeat -= 1
            else:
                normalized += data
        
        return normalized + "\""
    
    def getSymbolsInSourceLineForPc(self, pc):
        sym = list()
        re_vars = re.compile("(?P<symbol>[a-zA-Z0-9_]+)")
        self._send("list *" + pc + ",*" + pc)
        rawdata = self._readAll().splitlines()[1]
        rawdata = rawdata[rawdata.find(" "):].lstrip(" ")
        
        for match in re_vars.finditer(rawdata):
            sym.append(match.group("symbol"))
        
        return sym
    
    def getArglistByFuncName(self, function):
        args = OrderedDict()
        if self._selectFrameByName(function) == False:
            return OrderedDict()

        self._send("info args")
        rawdata = self._readAll()
        if "No arguments" in rawdata:
            return OrderedDict()

        for match in self._re_gdb_var_info.finditer(rawdata):
            var_name, value, data, blob = match.group("var_name", "value", "data", "blob")
            vartype = self._getTypeForVar(var_name)
            
            # Try to derefence pointer to extract more information
            if not blob and not data and ("0x" in value) and ("*" in vartype):
                blob, data = self._getInfoForVar(var_name, True, 5)
            
            if blob and (not value or "@" in value) and ("*" not in vartype):
                blob, data = self._getInfoForVar(var_name, False, 5)
                
            if data and isinstance(data, str)  and (" <repeats " in data):
                data = self._normalizeData(data)
                
            if data and isinstance(data, str) and ("<incomplete sequence" in data):
                data = data[:data.find("<incomplete sequence")].lstrip("\"").rstrip(" \",")
                
            args[var_name] = [vartype, value, data, blob]
        
        return args
    
    def getLocalsByFuncName(self, function):
        locs = OrderedDict()
        if self._selectFrameByName(function) == False:
            return OrderedDict()
        
        self._send("info locals")
        rawdata = self._readAll()
        if "No locals" in rawdata:
            return OrderedDict()
        
        for match in self._re_gdb_var_info.finditer(rawdata):
            var_name, value, data, blob = match.group("var_name", "value", "data", "blob")
            vartype = self._getTypeForVar(var_name)

            # Try to derefence pointer to extract more information
            if not blob and not data and value and ("*" in vartype):
                blob, data = self._getInfoForVar(var_name, True, 5)
            
            if blob and (not value or "@" in value) and ("*" not in vartype):
                blob, data = self._getInfoForVar(var_name, False, 5)
                
            if data and isinstance(data, str) and (" <repeats " in data):
                data = self._normalizeData(data)

            if data and isinstance(data, str) and ("<incomplete sequence" in data):
                data = data[:data.find("<incomplete sequence")].lstrip("\"").rstrip(" \",")
                
            locs[var_name] = [vartype, value, data, blob]

        return locs
    
    @property
    def pid(self):
        """ Process ID """
        return self._pid
    
    @property
    def command_line(self):
        """ Command line of execution """
        return self._cmd_line