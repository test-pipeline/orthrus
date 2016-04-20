'''
Gdb-Orthrus
'''

try:
    import gdb
except ImportError as e:
    raise ImportError("This script must be run in GDB: ", str(e))

import os

ARCH = ""
COMPILER = ""
PC = ""
BP = ""
SP = ""

class CanaryBreakpoint(gdb.Breakpoint):
    def __init__(self, canary_addr, observe_frame):
        gdb.Breakpoint.__init__(self, "*(long*)" + hex(canary_addr), gdb.BP_WATCHPOINT, gdb.WP_WRITE, True)
        self._observe_frame = observe_frame
    
    def stop(self):
        frame = gdb.newest_frame()
        while True:
            if not frame:
                break
            if frame.name() and self._observe_frame in frame.name():
                if not self._validAccess(frame.pc()):
                    return True
            frame = frame.older()
        return False

    def _validAccess(self, pc):
        disasm = ""
        if "x86_64" in ARCH:
            disasm = gdb.execute("x/i " + hex(pc) + "-13", False, True)
        else:
            disasm = gdb.execute("x/i " + hex(pc) + "-9", False, True)
        if ("%gs:" in disasm) or ("%fs:" in disasm):
            return True
        return False
    
class GdbOrthrus(gdb.Command):
    _cmdstr = "orthrus"
    
    def __init__(self):
        gdb.Command.__init__(self, self._cmdstr, gdb.COMMAND_OBSCURE)
        
    def _platformInfo(self):
        arch = ""
        pc = ""
        bp = ""
        sp = ""
        
        data = gdb.execute("show architecture", False, True)
        if "x86-64" in data:
            arch = "x86_64"
            pc = "$rip"
            bp = "$rbp"
            sp = "$rsp"
        else:
            arch = "i386"
            pc = "$eip"
            bp = "$ebp"
            sp = "$esp"
            
        #TODO: Check which compiler was used
        compiler = "gcc"
        
        return (arch, compiler, pc, bp, sp)
    
    def _isStackCheckFail(self):
        frame = gdb.newest_frame()
        while True:
            if not frame:
                break 
            if frame.name() and "__stack_chk_fail" in frame.name():
                return True
            frame = frame.older()
               
        return False
    
    def _getTopUserCodeFrame(self):
        frame = gdb.newest_frame()
        while True:
            if not frame.is_valid():
                break
            if frame.find_sal().symtab:
                filename =frame.find_sal().symtab.filename
                for dirpath, dirnames, filenames in os.walk('./'):
                    for fn in filenames:
                        if os.path.basename(filename) == fn:
                            return frame
            frame = frame.older()
            
        return None
    
    def _getProgArgs(self):
        cmd_args = gdb.execute("show args", False, True)
        cmd_args = cmd_args[cmd_args.find("\""):]
        cmd_args = cmd_args[1:-3]
        
        return cmd_args
    
    def _getCanaryAddr(self, frame):
        disasm = ""
        pc = frame.pc()
        bp = gdb.parse_and_eval(BP)
         
        if "x86_64" in ARCH:
            disasm = gdb.execute("x/i " + hex(pc) + "-20", False, True)
        else:
            disasm = gdb.execute("x/i " + hex(pc) + "-17", False, True)
             
        tmp = disasm[disasm.find("mov"):]
        tmp = tmp[tmp.find(" "):tmp.find("(")].lstrip(" ")
        if "-" in tmp:
            return ((-1 * int(tmp[1:], 16)) + int(bp))
        else:
            return (int(tmp[1:], 16) + int(bp))

        return None
    
    def _getExploitableInfo(self):
        info =  "GDB exploitable info:\n" + gdb.execute("exploitable", False, True)
        gdb.execute("set disassembly-flavor att", False, True)
        
        return info
    
    def _updateExploitableHash(self, exploitable_info):
        exploitable_info = exploitable_info.splitlines()
        tmp = gdb.execute("exploitable", False, True).splitlines()
        gdb.execute("set disassembly-flavor att", False, True)
        
        exploitable_info[3] = tmp[2]
        
        return "".join(exploitable_info)
    
    def _describeLocals(self, frame, sp, fa_offset):
        local_vars = gdb.execute("info locals", False, True).splitlines()
        print ("This frame has " + str(len(local_vars)) + " object(s):")
        for loc_var in local_vars:
            loc_var = loc_var[:loc_var.find(" = ")]
            addr = gdb.execute("p &" + loc_var, False, True)
            addr = int(addr[addr.find("0x"):-1], 16)
            size = gdb.execute("p sizeof(" + loc_var + ")", False, True)
            size = int(size[size.find("= ") + 2:-1])

            overflow_str = ""
            if frame == gdb.newest_frame():
                if (addr - sp + size) == fa_offset:
                    overflow_str = " <== Memory access overflows this variable"
                print ("["+ str(addr - sp) + "," + str(addr - sp + size) + "] '" + loc_var + "'" + overflow_str) 
                overflow_str = ""
            else:
                if (addr - sp + size) == fa_offset:
                    overflow_str = " <== Memory access overflows this variable"
                print ("["+ str(addr - sp) + "," + str(addr - sp + size) + "] '" + loc_var + "'" + overflow_str) 
                overflow_str = ""

    def _printStackLocation(self, fa_addr):
        frame_no = 0
        frame = gdb.newest_frame()
        frame.select()
        while True:
            if not frame or not frame.is_valid():
                break
            bp = int(gdb.parse_and_eval(BP))
            sp = int(gdb.parse_and_eval(SP))
            pc = frame.pc()
            if int(fa_addr) < int(bp):      
                print ("Address " + hex(fa_addr) + " is located in stack at offset " + str(fa_addr - (sp)) + " in frame")
                print (gdb.execute("bt " + str(frame_no + 1), False, True).splitlines()[-1])
                self._describeLocals(frame, sp, fa_addr - sp)
                return
            frame = frame.older()
            frame.select()
            frame_no += 1
            
    def _printHeapLocation(self, fa_addr):
        print ("no information")
        
    def _printFault(self, fa_addr, isStack):
        pid = "0"
        re_pid = re.compile("\s+process\s(?P<pid>[0-9]+?)\s")
        inferior = gdb.execute("info inferior", False, True)
        match = re_pid.search(inferior)
        if match:
            pid = match.group("pid")

        pc = int(gdb.parse_and_eval(PC))
        bp = int(gdb.parse_and_eval(BP))
        sp = int(gdb.parse_and_eval(SP))

        print ("==" + pid + "==ERROR: GenericGdb:" )
        print ("Faulting mem location is " + hex(fa_addr) + ", pc is " + hex(pc) + ", sp is " + hex(sp) + ", bp is " + hex(bp))
        print ("AccessViolation: WRITE of size 4 at " + hex(fa_addr))
        
        if isStack:
            self._printStackLocation(fa_addr)
        else:
            self._printHeapLocation(fa_addr)
        
        bt = "\nProgram back trace:\n"
        bt += gdb.execute("bt", False, True)
        print (bt)
        
    def invoke(self, argstr, from_tty):
        global ARCH, COMPILER, PC, BP, SP
        ARCH, COMPILER, PC, BP, SP = self._platformInfo()
        #print ("Arch: " + ARCH + " Compiler:" + COMPILER + " PC: " + PC + " BP: " + BP + " SP: " + SP)
        
        exploitable_info = self._getExploitableInfo()
        #print (exploitable_info)
        
        cmd_args = self._getProgArgs()
        #print (cmd_args)
        
        frame = self._getTopUserCodeFrame()
        if not frame:
            print("Error: Couldn't find top user code frame!")
            return
        frame.select()
            
        isStack = False
        fa_addr = 0
        if self._isStackCheckFail():
            isStack = True
            
            observe_frame = frame.name()
            fa_addr = self._getCanaryAddr(frame)
            #print ("Canary: " + hex(canary_addr))
            CanaryBreakpoint(fa_addr, observe_frame)
            gdb.execute("run " + cmd_args, False, True)
            gdb.execute("set " + PC + "=" + PC + "-1")
            self._updateExploitableHash(exploitable_info)
            
        self._printFault(fa_addr, isStack)
        print (exploitable_info)
        
        gdb.newest_frame().select()
            
GdbOrthrus()