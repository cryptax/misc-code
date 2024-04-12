#?description=Dart byte arrays annotation - @cryptax June 19, 2023
#?shortcut=

from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext
from com.pnfsoftware.jeb.core.units import INativeCodeUnit
from com.pnfsoftware.jeb.core.units.code import ICodeUnit
import re

class DartBytes(IScript):
    def run(self, ctx):
        if not isinstance(ctx, IGraphicalClientContext):
            print('This script must ben run within a graphical client')
            return
     
        fragment = ctx.getFocusedView().getActiveFragment()
        if not fragment:
            print('Select the method to enhance')
            return
      
        unit = fragment.getUnit()  # returns a INativeCodeUnit
        if not unit.isProcessed():
            unit.process()

        # get current method
        method_addr = fragment.getActiveAddress()
        print('Active address: %s' % (method_addr))
        pos = method_addr.find('+')
        if pos >= 0:
            method_addr = method_addr[:pos]
        method = unit.getMethod(method_addr)
        if method is None:
            print('No method selected (%s). Please select a method.' % (method_addr))
        else:
            for i in method.getInstructions():
                current_inst = i.format(ctx)
                if re.search('mov *r.*, *[A-F0-9]*h', current_inst) is not None:
                    try:
                        literal = re.search('[A-F0-9]*h', current_inst).group(0)[:-1]
                        int_value = int(literal, 16) // 2
                        previous_comment = unit.getFullComment(method_addr)
                        if int_value >= 32 and int_value <= 126:
                            # it's a printable character
                            print("Loading: %c" % (chr(int_value)))
                            unit.setPrimaryComment(method_addr, '%s%c' % (previous_comment, chr(int_value)))
                        else:
                            print("Loading 0x%02x" % (int_value))
                    except ValueError:
                        print('Error for instruction: %s' % current_inst)
                
                
                
    

        
