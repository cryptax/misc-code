from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext, IUnitView
from com.pnfsoftware.jeb.core.units import IUnit, IXmlUnit
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit
from com.pnfsoftware.jeb.core import RuntimeProjectUtil

class Allatori(IScript):

    def run(self, ctx):
        engctx = ctx.getEnginesContext()
        if not engctx:
            print('Back-end engines not initialized')
            return

        projects = engctx.getProjects()
        if not projects:
            print('There is no opened project')
            return

        if not isinstance(ctx, IGraphicalClientContext):
            print('This script must be run within a graphical client')
            return

        prj = projects[0]
        
        fragment = ctx.getFocusedView().getActiveFragment()
        if not fragment:
            print "Select a view and the string to de-obfuscate"
            return
        
        selectedstring = fragment.getActiveItemAsText()
        if not selectedstring:
            print("Select a string to de-obfuscate")
            return

        selectedstring = self.prepare_string(selectedstring)
        x1, x2 = self.get_args(ctx, selectedstring)
        
        print self.deobfuscate(selectedstring,x1,x2)
        
    def get_args(self, ctx, caption):
        # ask user how to configure the de-obfuscation routine
        # caption is the title to display
        # returns two ints
        default_x1 = '53'
        default_x2 = '66'
        x1 = ctx.displayQuestionBox(caption, 'x1= (default is %s)' % (default_x1), default_x1)
        x2 = ctx.displayQuestionBox(caption, 'x2= (default is %s)' % (default_x2), default_x2)
        
        return int(x1), int(x2)

    def prepare_string(self, thestring):
        # Typically, you'll get this as input: '"T,Q0Z+QlT2ElT!A+Z,\u001B"'
        # and what this as output: u'T,Q0Z+QlT2ElT!A+Z,\x1b'
        
        # remove first and last quote
        l = len(thestring)
        s = thestring
        if thestring[0] == '"' and thestring[l-1] == '"':
            s = thestring[1:l-1]

        # handle unicode escaping
        return s.decode('unicode-escape')

    def deobfuscate(self, thestring, x1, x2):
        decoded = ''
        print "De-obfuscating: ", thestring
        index = len(thestring) -1
        while (index >=0):
            decoded = chr(ord(thestring[index]) ^ x1) + decoded
            if (index - 1) < 0:
                break
            index = index - 1
            decoded = (chr(ord(thestring[index]) ^ x2)) + decoded
            index = index - 1
        return decoded


        
        
        
