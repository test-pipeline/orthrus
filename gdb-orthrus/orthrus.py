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

class CanaryBreakpoint(gdb.Breakpoint):
    def __init__(self, canary_address, observe_frame_name):
        gdb.Breakpoint.__init__(self, "*(int*)" + hex(canary_address), gdb.BP_WATCHPOINT, gdb.WP_WRITE, True)

        self._observe_frame_name = observe_frame_name
    
    def stop(self):
        frame = gdb.newest_frame()
        while True:
            if not frame:
                break
            if frame.name() and self._observe_frame_name in frame.name():
                if not self._validAccess(frame.pc()):
                    return True
            frame = frame.older()
        return False

    def _validAccess(self, pc):
        disasm = gdb.execute("x/i " + hex(pc) + "-9", False, True)
        if "%gs:" in disasm:
            return True
        return False
    
class GdbOrthrus(gdb.Command):
    _cmdstr = "orthrus"
    
    def __init__(self):
        gdb.Command.__init__(self, self._cmdstr, gdb.COMMAND_OBSCURE)
        
    def _platformInfo(self):
        pass
    
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
                if os.path.isfile(os.path.abspath(frame.find_sal().symtab.filename)):
                    return frame
            frame = frame.older()
            
        return None
    
    def invoke(self, argstr, from_tty):
        print ("Hello Orthrus")
        
GdbOrthrus()