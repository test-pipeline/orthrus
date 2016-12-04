'''
Santizer Report
'''
# from GdbExtractor import GdbExtractor

import re
import sys
import os
from collections import OrderedDict
import json

class StackFrame(object):
    '''
    Representation of a stack frame
    '''
    def __init__(self, frameNo, address, function, paramlist, filename, line, column, module, offset):
        self._frame_no = frameNo
        self._address = address
        self._function = function
        self._paramlist = paramlist
        self._filename = os.path.normpath(filename or "")
        if os.path.isfile(self._filename):
            self._filename = os.path.abspath(self._filename)
        else:
            # Path information is incomplete, thus we have to search for the file
            candidates = []
            for dirpath, dirnames, filenames in os.walk('./'):
                for fn in filenames:
                    if fn == filename:
                        fpath = os.path.join(dirpath, fn)
                        candidates.append(fpath)
            if len(candidates) > 0:
                # We found one or more source file candidate, doing some heuristics
                found = False
                for fn in candidates:
                    fh = open(fn, "r")
                    for linestr in fh:
                        if function in linestr:
                            self._filename = os.path.abspath(os.path.normpath(fn))
                            found = True
                            break
                    fh.close()
                    if found:
                        break
            else:
                self._filename = filename or ""
            
        self._line = int(line or 0)
        self._column = int(column or 0)
        self._module = module or ""
        self._offset = offset or ""
        
        # VarName : [0] = type, [1] = value (ptr/primitive), [2] = data/ subDict (member of struct/class), [3] = blob (row data)
        self._args = OrderedDict()
        self._locals = OrderedDict()
        
    # def getVarInfo(self, var_name):
    #     var_seq = var_name.replace("->", ".").split(".")
    #     var_info = self._traverseVar(self._args, var_seq)
    #     if var_info:
    #         if isinstance(var_info[2], OrderedDict):
    #             var_info[2] = None
    #         return var_info
    #     var_info = self._traverseVar(self._locals, var_seq)
    #     if var_info:
    #         if isinstance(var_info[2], OrderedDict):
    #             var_info[2] = None
    #         return var_info
    #     return None
    #
    # def _traverseVar(self, obj, var_seq, level = 0):
    #     for key, value in obj.items():
    #         if var_seq[level] == key:
    #             if level != len(var_seq) - 1:
    #                 if isinstance(value[2], OrderedDict):
    #                     return self._traverseVar(value[2], var_seq, level + 1)
    #                 else:
    #                     return None
    #             else:
    #                 return value

    @property
    def frameNo(self):
        """ Position of frame on stack """
        return self._frame_no
    @frameNo.setter
    def frameNo(self, value):
        self._frameNo = value

    @property
    def address(self):
        """ Address in frame """
        return self._address
    @address.setter
    def address(self, value):
        self._address = value

    @property
    def function(self):
        """ Function name """
        return self._function
    @function.setter
    def function(self, value):
        self._function = value

    @property
    def filename(self):
        """ Source Location filename """
        return self._filename
    @filename.setter
    def filename(self, value):
        self._filename = value

    @property
    def paramlist(self):
        """ Parameter list """
        return self._paramlist
    @paramlist.setter
    def paramlist(self, value):
        self._paramlist = value

    @property
    def line(self):
        """ Source Location line """
        return self._line
    @line.setter
    def line(self, value):
        self._line = value

    @property
    def column(self):
        """ Source Location column """
        return self._column
    @column.setter
    def column(self, value):
        self._column = value

    @property
    def module(self):
        """ Module name """
        return self._module
    @module.setter
    def module(self, value):
        self._module = value

    @property
    def offset(self):
        """ Offset in module """
        return self._offset
    @offset.setter
    def offset(self, value):
        self._offset = value

    @property
    def args(self):
        """ Arguments of the function """
        return self._args
    @args.setter
    def args(self, value):
        self._args = value

    @property
    def locals(self):
        """ Locals of the function """
        return self._locals
    @locals.setter
    def locals(self, value):
        self._locals = value

    # def _printArgList(self, args, max_level = 0, level = 0):
    #     if level > max_level:
    #         return
    #     for var, value in args.iteritems():
    #         sys.stdout.write("      " + ("  " * level) + var + "=" + "<" + value[0] + "> " + value[1] + " ")
    #         if isinstance(value[2], OrderedDict):
    #             sys.stdout.write("\n");
    #             self._printArgList(value[2], max_level, level + 1)
    #         else:
    #             sys.stdout.write((value[2] or ""))
    #             sys.stdout.write("\n");
    #
    #         #sys.stdout.write(" " + (value[3] or "") + "\n")
    #
    # def printArgList(self):
    #     if self._args:
    #         sys.stdout.write("    Arglist: \n")
    #         self._printArgList(self._args)
    #
    # def _printLocals(self, locs, max_level = 0, level = 0):
    #     if level > max_level:
    #         return
    #     for var, value in locs.iteritems():
    #         sys.stdout.write("      " + ("  " * level) + var + "=" + "<" + value[0] + "> " + value[1] + " ")
    #         if isinstance(value[2], OrderedDict):
    #             sys.stdout.write("\n");
    #             self._printArgList(value[2], max_level, level + 1)
    #         else:
    #             sys.stdout.write((value[2] or ""))
    #         sys.stdout.write("\n");
    #         #sys.stdout.write(" " + (value[3] or "") + "\n")
    #
    # def printLocals(self):
    #     if self._locals:
    #         sys.stdout.write("    Locals: \n")
    #         self._printArgList(self._locals)
    #
    # def printFrame(self):
    #     if not self._paramlist:
    #         paramlist = "("
    #         for var, value in self._args.iteritems():
    #             paramlist += value[0] + " " + var + ", "
    #         paramlist = paramlist.rstrip(", ")
    #         paramlist += ")"
    #     else:
    #         paramlist = self._paramlist
    #
    #     sys.stdout.write("  #{} {} in {}{} at {} {}:{} {} {}\n".format(self._frame_no,
    #                                                                    self._address,
    #                                                                    self._function,
    #                                                                    paramlist,
    #                                                                    self._filename,
    #                                                                    self._line,
    #                                                                    self._column,
    #                                                                    self._module,
    #                                                                    self._offset))

class SanitizerReport(object):
    '''
    Base class for a sanitizer log
    '''
    def __init__(self, path_prefix, verbose, jsonfile):
        '''
        Constructor
        '''
        self._path_prefix = path_prefix
        self.jsonfile = jsonfile
        
        self._pid = int(0)
        self._command_line = ""
        self._exec_file = ""
        self._input_file = ""
        self._reason = ""
        self._fault_address = ""
        self._fault_var = ""
        self._pc = ""
        self._bp = ""
        self._sp = ""
        self._thread = ""
        self._operation = ""
        self._op_size = ""
        
        self._loc_offset = ""
        self._loc_position = ""
        self._loc_size = ""
        self._loc_region = ["", ""]
        self._loc_frame_no = ""
        self._loc_var_name = ""
        self._loc_function = ""
        self._loc_filename = ""
        self._loc_line = ""
        
        self._fault_bt = list()
        self._origin_bt = list()
        self._intermediate_bt = list()
        
        self._verbose = verbose
        
    def parse(self, report):
        pass
    
    # def addCoreDumpInfo(self, core_file):
    #     gdbExtractor = GdbExtractor(self._exec_file, core_file, self._verbose)
    #     if self._pid != gdbExtractor.pid:
    #         return False
    #
    #     # Set command line if not set
    #     if not self._command_line:
    #         self._command_line = gdbExtractor.command_line
    #         self._exec_file, self._input_file = self._parseCmdLine(self._command_line)
    #
    #     for frame in self._fault_bt:
    #         if self._path_prefix in frame.filename:
    #             args = gdbExtractor.getArglistByFuncName(frame.function)
    #             frame.args = args
    #
    #             locs = gdbExtractor.getLocalsByFuncName(frame.function)
    #             frame.locals = locs
    #
    #
    #     if self._loc_region[0] and self._loc_region[1]:
    #         offset = 0
    #         if "left" in self._loc_position:
    #             offset = int(self._loc_offset)
    #         if "right" in self._loc_position:
    #             offset = int(self._loc_offset) * -1
    #
    #         for frame in self._fault_bt:
    #             if self._path_prefix in frame.filename:
    #                 symbols = gdbExtractor.getSymbolsInSourceLineForPc(self._pc)
    #                 for var, value in frame.args.iteritems():
    #                     if "0x" in value[1]:
    #                         if (int(value[1], 0) + offset) >= int(self._loc_region[0], 0) and (int(value[1], 0) + offset) <= int(self._loc_region[1], 0):
    #                             if var in symbols:
    #                                 self._fault_var = var
    #
    #                 for var, value in frame.locals.iteritems():
    #                     if "0x" in value[1]:
    #                         if (int(value[1], 0) + offset) >= int(self._loc_region[0], 0) and (int(value[1], 0) + offset) <= int(self._loc_region[1], 0):
    #                             if var in symbols:
    #                                 self._fault_var = var
    #                 break
    #
    #     return True
    #
    def _parseCmdLine(self, cmd_line):
        if cmd_line:
            cmd_line = cmd_line.split(' ')
            for arg in cmd_line:
                if os.path.isfile(arg) and "id:" in arg:
                    return (cmd_line[0], arg)
        return (None, None)
    #
    # def printReport(self):
    #     sys.stdout.write("== Runtime Info Summary ==\n")
    #     summary = "Project Base Dir: {}\n".format(self._path_prefix)
    #     summary += "Command: {}\n".format(self._command_line)
    #     summary += "Filename: {}\n".format(self._input_file)
    #     summary += "Fault Reason: {}\n".format(self._reason)
    #     summary += "PID: {}, FA: {}, FA-Var: {}, PC: {}, ".format(self._pid,
    #                                                               self._fault_address,
    #                                                               self._fault_var,
    #                                                               self._pc)
    #     summary += "BP: {}, SP: {} in Thread T{}\n".format(self._bp,
    #                                                        self._sp,
    #                                                        self._thread)
    #     if self._operation:
    #         summary += "Operation: {} of size {}\n". format(self._operation, self._op_size)
    #
    #     if "stack" in self._loc_position:
    #         summary += "Location: Address {} of variable '{}' ".format(self._fault_address,
    #                                                                    self._loc_var_name)
    #         summary += "is {} in Region [{}, {}]\n".format(self._loc_position,
    #                                                        self._loc_region[0],
    #                                                        self._loc_region[1])
    #         summary += "of frame #{} {} {}:{}". format(self._loc_frame_no,
    #                                                    self._loc_function,
    #                                                    self._loc_filename,
    #                                                    self._loc_line)
    #     else:
    #         summary += "Location: Address {} is {} ".format(self._fault_address,
    #                                                         self._loc_offset)
    #         summary += "bytes {} of Region [{}, {}] ({}-bytes)\n".format(self._loc_position,
    #                                                                      self._loc_region[0],
    #                                                                      self._loc_region[1],
    #                                                                      self._loc_size)
    #
    #     sys.stdout.write(summary)
    #
    #     sys.stdout.write("\nFault Backtrace:\n")
    #     for frame in self._fault_bt:
    #         frame.printFrame()
    #         #frame.printArgList()
    #         #frame.printLocals()
    #
    #     if self._origin_bt:
    #         sys.stdout.write("\nOrigin Backtrace:\n")
    #         for frame in self._origin_bt:
    #             frame.printFrame()
    #
    #     if self._intermediate_bt:
    #         sys.stdout.write("\nIntermediate Backtrace:\n")
    #         for frame in self._intermediate_bt:
    #             frame.printFrame()
    #
    #     sys.stdout.write("== End Runtime Info Summary ==\n")

    @property
    def pid(self):
        """ Process ID """
        return self._pid

    @property
    def thread(self):
        """ Thread ID """
        return self._thread

    @property
    def reason(self):
        """ Reason of violation """
        return self._reason

    @property
    def operation(self):
        """ Access operation type """
        return self._operation

    @property
    def fault_address(self):
        """ Address of fault """
        return self._fault_address

    @property
    def fault_variable(self):
        """ Variable name corresponding to fault address """
        return self._fault_var

    @property
    def pc(self):
        """ Program counter """
        return self._pc

    @property
    def bp(self):
        """ Frame base pointer """
        return self._bp

    @property
    def sp(self):
        """ Stack pointer """
        return self._sp

    @property
    def executable_name(self):
        return self._exec_file

    @property
    def inputfile_name(self):
        return self._input_file

    @property
    def fault_frames(self):
        return self._fault_bt

    @property
    def origin_frames(self):
        return self._origin_bt

    @property
    def intermediate_frames(self):
        return self._intermediate_bt

    @property
    def location_position(self):
        return self._loc_position

    @property
    def location_region(self):
        return self._loc_region

    @property
    def location_function(self):
        return self._loc_function

    @property
    def location_variable(self):
        return self._loc_var_name

    @property
    def location_filename(self):
        return self._loc_filename

    @property
    def location_line(self):
        return self._loc_line

    @property
    def location_offset(self):
        return self._loc_offset
    
class ASANReport(SanitizerReport):
    '''
    A Adress Sanitizer Report
    '''
    _re_asan_hdr = re.compile(  r"""=+(?P<pid>[0-9]+)=+                             # Process ID
                                    \s*(ERROR|WARNING):\s*AddressSanitizer(:)?\s*           # Asan Header Magic
                                    (failed\sto\s)?
                                    (attempting\s)?(?P<reason>[A-Za-z0-9_-]+)(:)?\s+ # Reason fault
                                    (on\s)?((unknown\s)?address\s)?
                                    (which\swas\snot\smalloc\(\)-ed:\s)?
                                    (memory\sranges\s)?
                                    ((?P<allocsize>0x[A-Fa-f0-9]+)\sbytes)?    # malloc exceeded size
                                    (
                                    \[(?P<srcstart>0x[A-Fa-f0-9]+),(\s)?      # Region start address
                                    (?P<srcend>0x[A-Fa-f0-9]+)\)              # Region end address
                                    \sand\s
                                    \[(?P<dststart>0x[A-Fa-f0-9]+),(\s)?      # Region start address
                                    (?P<dstend>0x[A-Fa-f0-9]+)\)              # Region end address
                                    \soverlap
                                    )?
                                    ((?P<fault_addr>0x[A-Fa-f0-9]+)\s)?         # Address of fault
                                    (\()?(at\s)?
                                    (pc\s(?P<pc>0x[A-Fa-f0-9]+)\s)?               # PC Address
                                    (bp\s(?P<bp>0x[A-Fa-f0-9]+)\s)?             # Frame Base Address
                                    (sp\s(?P<sp>0x[A-Fa-f0-9]+)\s*)?            # Stack Base Address
                                    (in\sthread\s)?
                                    (T)?(?P<thread>[0-9]+)?                         # Thread number
                                """, re.VERBOSE)
    
    _re_asan_op = re.compile(  r"""(The signal is caused by a)?
                                    (?P<operation>(READ|WRITE))\s       # Access operation type
                                    (memory access)?
                                    (of\ssize\s
                                    (?P<size>[0-9]+)\s                 # Size of access violation
                                    at\s0x[A-Fa-f0-9]+\s
                                    thread\sT
                                    (?P<thread>[0-9]+))?                 # Thread number
                                """, re.VERBOSE)
    
    _re_asan_location_heap = re.compile(r"""
                                        ((?P<fault_addr>0x[A-Fa-f0-9]+)\s)?         # Address of fault
                                        is\slocated\s
                                        (?P<offset>[0-9]+)\s                    # Offset
                                        bytes\s(to\sthe\s)?
                                        (?P<position>(left|right|inside))\s     # Offset position explanation
                                        of\s
                                        (?P<size>[0-9]+)-byte\sregion\s         # Size of memory region
                                        \[(?P<start>0x[A-Fa-f0-9]+),            # Region start address
                                        (?P<end>0x[A-Fa-f0-9]+)\)               # Region end address
                                     """, re.VERBOSE)
    
    _re_asan_location_stack = re.compile(r"""is\slocated\s
                                             in\sstack\sof\sthread\sT[0-9]+\sat\soffset\s
                                             (?P<offset>[0-9]+)\sin\sframe\s+                # Offset
                                             \#(?P<frame_no>[0-9]+).+in\s                    # Which frame
                                             (?P<func>[A-Za-z0-9_\?]+)\s                     # Name of function
                                             (?P<file>.+?):                                  # Filename for function definition
                                             (?P<line>[0-9]+).+                              # Line number of definition
                                             \[(?P<start>[0-9]+),\s                          # Start offset in frame
                                             (?P<end>[0-9]+)\)\s.                            # End offset in frame
                                             (?P<var>[A-Za-z0-9_?]+).\s                      # Name of variable
                                             <==\sMemory\saccess
                                     """, re.VERBOSE | re.DOTALL)
    
    _re_asan_stack = re.compile(r"""
                                    ^\s*\#(?P<frame_no>[0-9]+)\s                    # Number of frame
                                    (?P<address>0x[A-Fa-f0-9]+)\s                   # Address of pc inside frame
                                    
                                    (in\s)?
                                    ((?P<func>[A-Za-z0-9_:\?<>,\s]+)                # Function name
                                    ((?P<paramlist>\([A-Za-z0-9_:\&\,\s\*]*\)))?\s)? # Parameter list
                                    ((?P<file>.+?):                                 # Path and filename
                                    (?P<line>[0-9]+)                                # Line number
                                    (:(?P<column>[0-9]+))?)?                        # Column
                                    
                                    ((\s)?\(
                                    (?P<module>.+?)\+                               # Module name in case of not symbolized
                                    (?P<offset>0x[A-Fa-f0-9]+)\)                    # Address inside the module
                                    )?
                                """, re.VERBOSE|re.MULTILINE)
    
    _re_asan_cmd_line = re.compile( r"""Command:\s
                                        (?P<cmdline>.+)    # Command used to launch program
                                     """, re.VERBOSE)
    def __init__(self, path_prefix, verbose, jsonfile):
        SanitizerReport.__init__(self, path_prefix, verbose, jsonfile)


    # @staticmethod
    # def serialize_dict(obj):
    #     local_dict = {}
    #     for key, value in obj.__dict__.iteritems():
    #         attr = getattr(obj, key)
    #         if not key.startswith('__') and not callable(attr) and not type(attr) is staticmethod:
    #             if type(value) is str or type(value) is int:
    #                 local_dict[key] = value
    #     return local_dict

    def update_asan_dict(self):
        for attr in ['_pid', '_reason', '_operation', '_op_size', '_fault_address', '_pc', '_bp', '_sp', '_thread'
                     '_loc_offset', '_loc_position', '_loc_size', '_loc_frame_no', '_loc_function', '_loc_filename'
                     '_loc_var_name', '_loc_line', '_command_line', '_exec_file', 'jsonfile', '_fault_var']:
            if hasattr(self, attr):
                self.asan_dict[attr] = getattr(self, attr)

    # def serialize(self):
    #     serial_dict = {}
    #     for key, value in self.__dict__.iteritems():
    #         attr = getattr(self, key)
    #         if not key.startswith('__') and not callable(attr) and not type(attr) is staticmethod:
    #             if type(value) is str or type(value) is int:
    #                 serial_dict[key] = value
    #             if type(value) is list and value and type(value[0]) is StackFrame:
    #                 sf_dict = {}
    #                 for idx, stackframe in enumerate(value):
    #                     sf_dict['frame{}'.format(idx)] = self.serialize_dict(stackframe)
    #                 serial_dict[key] = sf_dict
    #     return serial_dict

    def jsonify(self):
        self.update_asan_dict()
        with open(self.jsonfile, 'w') as file:
            json.dump(self.asan_dict, file, indent=4)

    # @Override
    def parse(self, report):
        self.asan_dict = {}
        # Parse ASAN header information into dict
        match = self._re_asan_hdr.search(report)
        if match is not None:
            self._pid = int(match.group("pid"))
            self._reason = match.group("reason")
            if self._reason == "free":
                self._reason = "bad-free"
            if self._reason == "allocate":
                self._reason = "bad-alloc"
                self._operation = "alloc"
                self._op_size = match.group("allocsize")
            
            self._fault_address = match.group("fault_addr")
            self._pc = match.group("pc")
            self._bp = match.group("bp")
            self._sp = match.group("sp")
            self._thread = match.group("thread")

        match = self._re_asan_op.search(report)
        if match is not None:
            self._operation = match.group("operation")
            self._op_size = match.group("size")
            self._thread = match.group("thread")
        
        #Backtrace of fault
        start = report.find("    #")
        end = 0
        for line in report[start:].splitlines():
            if line.startswith("    #"):
                end = report.find(line)
                end += report[end:].find("\n")
            else:
                break

        self.asan_dict['_fault_bt'] = {}
        bt_key = '_fault_bt'
        for match in self._re_asan_stack.finditer(report[start:end]):
            frame_no, address, func, paramlist, filename, line, column, module, offset = match.group("frame_no", "address", "func", "paramlist", "file", "line", "column", "module", "offset")
            self._fault_bt.append(StackFrame(frame_no, address, func, paramlist, filename, line, column, module, offset))

            # Don't want these frames in dict
            if (func == '_start' and module) or (func == '__libc_start_main'):
                continue

            # Dictify
            frame_key = 'frame{}'.format(frame_no)
            self.asan_dict[bt_key][frame_key] = {}
            self.asan_dict[bt_key][frame_key]['address'] = address
            self.asan_dict[bt_key][frame_key]['func'] = func
            self.asan_dict[bt_key][frame_key]['paramlist'] = paramlist
            self.asan_dict[bt_key][frame_key]['filename'] = filename
            self.asan_dict[bt_key][frame_key]['line'] = line
            self.asan_dict[bt_key][frame_key]['column'] = column
            self.asan_dict[bt_key][frame_key]['module'] = module
            self.asan_dict[bt_key][frame_key]['offset'] = offset
        
        #Origin location
        match = self._re_asan_location_heap.search(report)
        if match is not None:
            self._loc_offset = match.group("offset")
            self._loc_position = match.group("position")
            self._loc_size = match.group("size")
            self._loc_region[0] = self.asan_dict['_loc_start'] = match.group("start")
            self._loc_region[1] = self.asan_dict['_loc_end'] = match.group("end")
            if self._fault_address is None:
                self._fault_address = match.group("fault_addr")

        match = self._re_asan_location_stack.search(report)
        if match is not None:
            self._loc_position = "stack"
            self._loc_offset = match.group("offset")
            self._loc_frame_no = match.group("frame_no")
            self._loc_function = match.group("func")
            self._loc_filename = match.group("file")
            self._loc_line = match.group("line")
            self._loc_region[0] = match.group("start")
            self._loc_region[1] = match.group("end")
            self._loc_var_name = match.group("var")
            self._loc_size = str(int(match.group("end")) - int(match.group("start")))
            
            self._loc_region[0] = self.asan_dict['_loc_start'] = hex(int(self._fault_address, 0) - int(self._loc_offset) + int(self._loc_region[0]))
            self._loc_region[1] = self.asan_dict['_loc_end'] = hex(int(self._fault_address, 0) - int(self._loc_offset) + int(self._loc_region[1]))
        
        #Backtrace of origin
        start = report.find("allocated by")
        start += report[start:].find("    #") 
        end = 0
        for line in report[start:].splitlines():
            if line.startswith("    #"):
                end = report[start:].find(line) + start
                end += report[end:].find("\n")
            else:
                break

        self.asan_dict['_origin_bt'] = {}
        bt_key = '_origin_bt'
        for match in self._re_asan_stack.finditer(report[start:end]):
            frame_no, address, func, paramlist, filename, line, column, module, offset = match.group("frame_no", "address", "func", "paramlist", "file", "line", "column", "module", "offset")
            self._origin_bt.append(StackFrame(frame_no, address, func, paramlist, filename, line, column, module, offset))
            #self._origin_bt.append((frame_no, address, func or "", filename or "", line or "", column or "", module or "", offset or ""))

            # Dictify
            frame_key = 'frame{}'.format(frame_no)
            self.asan_dict[bt_key][frame_key] = {}
            self.asan_dict[bt_key][frame_key]['address'] = address
            self.asan_dict[bt_key][frame_key]['func'] = func
            self.asan_dict[bt_key][frame_key]['paramlist'] = paramlist
            self.asan_dict[bt_key][frame_key]['filename'] = filename
            self.asan_dict[bt_key][frame_key]['line'] = line
            self.asan_dict[bt_key][frame_key]['column'] = column
            self.asan_dict[bt_key][frame_key]['module'] = module
            self.asan_dict[bt_key][frame_key]['offset'] = offset
        
        #Backtrace of intermediate position
        start = report.find("freed by")
        start += report[start:].find("    #") 
        end = 0
        for line in report[start:].splitlines():
            if line.startswith("    #"):
                end = report[start:].find(line) + start
                end += report[end:].find("\n")
            else:
                break

        self.asan_dict['_freedby_bt'] = {}
        bt_key = '_freedby_bt'
        for match in self._re_asan_stack.finditer(report[start:end]):
            frame_no, address, func, paramlist, filename, line, column, module, offset = match.group("frame_no", "address", "func", "paramlist", "file", "line", "column", "module", "offset")
            self._intermediate_bt.append(StackFrame(frame_no, address, func, paramlist, filename, line, column, module, offset))

            # Dictify
            frame_key = 'frame{}'.format(frame_no)
            self.asan_dict[bt_key][frame_key] = {}
            self.asan_dict[bt_key][frame_key]['address'] = address
            self.asan_dict[bt_key][frame_key]['func'] = func
            self.asan_dict[bt_key][frame_key]['paramlist'] = paramlist
            self.asan_dict[bt_key][frame_key]['filename'] = filename
            self.asan_dict[bt_key][frame_key]['line'] = line
            self.asan_dict[bt_key][frame_key]['column'] = column
            self.asan_dict[bt_key][frame_key]['module'] = module
            self.asan_dict[bt_key][frame_key]['offset'] = offset
        
        match = self._re_asan_cmd_line.search(report)
        if match is not None:
            self._command_line = match.group("cmdline")
        
        # Try to extract the executable name if command line is available in report,
        # otherwise try to extract its name from the backtrace
        self._exec_file, self._input_file = self._parseCmdLine(self._command_line)
        if not self._exec_file:
            self._exec_file = self._fault_bt[-1].module
            
        if self._fault_bt[-1].function == "_start" and self._fault_bt[-1].module != None:
            del self._fault_bt[-1]
            
        if self._fault_bt[-1].function == "__libc_start_main":
            del self._fault_bt[-1]

        self.jsonify()
        return True

# class CustomGdbReport(SanitizerReport):
#     '''
#     A custom Gdb Sanitizer Report
#     '''
#     _re_customgdb_hdr = re.compile(
#                                 r"""
#                                 Starting\sprogram:\s(?P<cmd_line>.+?)\n       # Command line string
#                                 .+?
#                                 ==(?P<pid>[0-9]+)==.+?                        # Process ID
#                                 Faulting\smem\slocation\sis\s
#                                 (?P<fault_addr>0x[A-Fa-f0-9]+),\s             # Address of fault
#                                 pc\sis\s(?P<pc>0x[A-Fa-f0-9]+),\s             # PC Address
#                                 sp\sis\s(?P<sp>0x[A-Fa-f0-9]+),\s             # Stack Base Address
#                                 bp\sis\s(?P<bp>0x[A-Fa-f0-9]+)                # Frame Base Address
#                                 """, re.VERBOSE | re.DOTALL)
#
#     _re_customgdb_op = re.compile(
#                                 r"""
#                                 AccessViolation:\s
#                                 (?P<operation>READ|WRITE)\s       # Access operation type
#                                 of\ssize\s
#                                 (?P<size>[0-9]+)\s                # Size of access violation
#                                 at\s
#                                 (?P<fault_addr>0x[A-Fa-f0-9]+)    # Faulting memory location
#                                 """, re.VERBOSE)
#
#     _re_customgdb_location_stack = re.compile(
#                                         r"""
#                                         is\slocated\sin\sstack\sat\soffset\s
#                                         (?P<offset>[0-9]+)\s                  # Offset
#                                         in\sframe\s
#                                         \#(?P<frame_no>[0-9]+).+in\s          # Which frame
#                                         (?P<func>[A-Za-z0-9_\?]+)\s           # Name of function
#                                         \(.+?\)\sat\s
#                                         (?P<file>.+?):                        # Filename for function
#                                         (?P<line>[0-9]+).+                    # Line number of definition
#                                         This\sframe\shas\s
#                                         (?P<num_objects>[0-9]+)\sobject.+     # Number of objects
#                                         \[(?P<start>[0-9]+),                  # Start offset in frame
#                                         (?P<end>[0-9]+)\]\s.                  # End offset in frame
#                                         (?P<var>[A-Za-z0-9_?]+).\s            # Name of variable
#                                         <==\sMemory\saccess
#                                         """, re.VERBOSE | re.DOTALL)
#     _re_customgdb_stack = re.compile(
#                                 r"""
#                                 ^\#(?P<frame_no>[0-9]+)\s+          # Number of frame
#                                 ((?P<address>0x[A-Fa-f0-9]+)\s)?    # Address of pc inside frame
#                                 (in\s)?
#                                 (?P<func>[A-Za-z0-9_:\?<>,]+)\s     # Function name
#                                 (?P<paramlist>\(.*\))?              # Parameter list
#                                 (\sat\s)?
#                                 ((?P<file>.+?):                     # Path and filename
#                                 (?P<line>[0-9]+)                    # Line number
#                                 (:(?P<column>[0-9]+))?)?            # Column
#                                 """, re.VERBOSE | re.MULTILINE)
#
#     _re_customgdb_main = re.compile(
#                                     r"""
#                                     Main\sfunction:\sLine\s(?P<line>[0-9]+)\sof\s"(?P<filename>.+?)"\sstarts
#                                     """,re.VERBOSE)
#     _re_customgdb_exploitable = re.compile(
#                                 r"""
#                                 GDB\sexploitable\sinfo:\n
#                                 Description:\s(?P<description>.+?)\n                            # Fault description
#                                 Short\sdescription:\s(?P<short_desc>.+?)\s\(.+?\n               # Short fault description
#                                 Hash:\s(?P<major_hash>[a-z0-9]+)\.(?P<minor_hash>[a-z0-9]+)\s   # Major and minor hash of stack
#                                 Exploitability\sClassification:\s(?P<classification>[A-Z]+)\s   # Classification of bug
#                                 Explanation:\s(?P<explanation>.+)\s                             # Explanation string
#                                 Other\stags:
#                                 """, re.VERBOSE | re.DOTALL)
#
#     def __init__(self, path_prefix, verbose):
#         SanitizerReport.__init__(self, path_prefix, verbose)
#
#     def _getUniformReason(self, reason):
#         try:
#             return {
#                     'ReturnAv' : 'unknown-crash',
#                     'UseAfterFree' : 'unknown-crash',
#                     'SegFaultOnPc' : 'SEGV',
#                     'BranchAv' : 'unknown-crash',
#                     'StackCodeExecution' : 'unknown-crash',
#                     'StackBufferOverflow': 'stack-buffer-overflow',
#                     'PossibleStackCorruption' : 'unknown-crash',
#                     'DestAv' : 'unknown-crash',
#                     'BadInstruction' : 'unknown-crash',
#                     'ReturnAv' : 'unknown-crash',
#                     'HeapError' : 'unknown-crash',
#                     'StackOverflow': 'stack-buffer-overflow',
#                     'SegFaultOnPcNearNull' : 'unknown-crash',
#                     'BranchAvNearNull' : 'unknown-crash',
#                     'BlockMoveAv' : 'unknown-crash',
#                     'DestAvNearNull' : 'unknown-crash',
#                     'SourceAvNearNull' : 'unknown-crash',
#                     'FloatingPointException' : 'unknown-crash',
#                     'BenignSignal' : 'unknown-crash',
#                     'SourceAv' : 'unknown-crash',
#                     'AbortSignal' : 'unknown-crash',
#                     'AccessViolation' : 'unknown-crash',
#                     'UncategorizedSignal' : 'unknown-crash'
#                     }[reason]
#         except KeyError:
#             return 'unknown-crash'
#
#     # @Override
#     def parse(self, report):
#         # Parse custom gdb header information
#         match = self._re_customgdb_hdr.search(report)
#         if match:
#             self._command_line = match.group("cmd_line")
#             self._exec_file, self._input_file = self._parseCmdLine(self._command_line)
#
#             self._pid = int(match.group("pid"))
#             self._fault_address = match.group("fault_addr")
#             self._pc = match.group("pc")
#             self._bp = match.group("bp")
#             self._sp = match.group("sp")
#
#
#
#         match = self._re_customgdb_op.search(report)
#         if match:
#             self._operation = match.group("operation")
#             self._op_size = match.group("size")
#
#
#         match = self._re_customgdb_location_stack.search(report)
#         if match:
#             self._loc_position = "stack"
#             self._loc_offset = match.group("offset")
#             self._loc_frame_no = match.group("frame_no")
#             self._loc_function = match.group("func")
#             self._loc_filename = match.group("file")
#             self._loc_line = match.group("line")
#             self._loc_region[0] = match.group("start")
#             self._loc_region[1] = match.group("end")
#             self._loc_var_name = match.group("var")
#             self._loc_size = str(int(match.group("end")) - int(match.group("start")))
#
#             self._loc_region[0] = hex(int(self._fault_address, 0) - int(self._loc_offset) + int(self._loc_region[0]))
#             self._loc_region[1] = hex(int(self._fault_address, 0) - int(self._loc_offset) + int(self._loc_region[1]))
#
#         #Backtrace of fault
#         start = report.find("Program back trace:")
#         start += report[start:].find("#")
#         end = 0
#         for line in report[start:].splitlines():
#             if line.startswith("#"):
#                 end = report.find(line)
#                 end += report[end:].find("\n")
#             else:
#                 break
#
#         for match in self._re_customgdb_stack.finditer(report[start:end]):
#             frame_no, address, func, paramlist, filename, line, column = match.group("frame_no", "address", "func", "paramlist", "file", "line", "column")
#             self._fault_bt.append(StackFrame(frame_no, address, func, paramlist, filename, line, column, None, None))
#
#         incomplete = False
#         hasMain = False
#         for frame in self._fault_bt:
#             if frame.function == "??":
#                 incomplete = True
#             if frame.function == "main":
#                 hasMain = True
#
#         if incomplete and not hasMain:
#             match = self._re_customgdb_main.search(report)
#             if match:
#                 self._fault_bt.append(StackFrame(str(int(self._fault_bt[-1].frameNo) + 1), "0x0", "main", "", match.group("filename"), match.group("line"), 1, None, None))
#
#         match = self._re_customgdb_exploitable.search(report)
#         if match:
#             self._reason = self._getUniformReason(match.group("short_desc"))
#
#
#
# class UBSANReport(SanitizerReport):
#     '''
#     A UBSAN Sanitizer Report
#     '''
#
#     def __init__(self, path_prefix, verbose):
#         SanitizerReport.__init__(self, path_prefix, verbose)
#
#     # @Override
#     def parse(self, report):
#         print "Start to parse UBSANReport"
        