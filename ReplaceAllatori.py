from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext, IUnitView
from com.pnfsoftware.jeb.core.units import IUnit
from com.pnfsoftware.jeb.core import RuntimeProjectUtil
from com.pnfsoftware.jeb.core.units.code import ICodeUnit, ICodeItem
from com.pnfsoftware.jeb.core.units.code.java import IJavaSourceUnit, IJavaConstant, IJavaCall, IJavaMethod, IJavaClass, JavaElementType, IJavaAssignment
from com.pnfsoftware.jeb.core.events import JebEvent, J

class ReplaceAllatori(IScript):

    def run(self, ctx):
        self.ctx = ctx
        
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

        self.codeUnit = RuntimeProjectUtil.findUnitsByType(prj, ICodeUnit, False)[0]
        self.units = RuntimeProjectUtil.findUnitsByType(prj, IJavaSourceUnit, False)
        for unit in self.units:
            javaClass = unit.getClassElement()
            print "Processing class: ",javaClass.getName()
            self.cstbuilder = unit.getFactories().getConstantFactory()
            self.process_class(unit, javaClass)

    def process_class(self, unit, javaClass):
        for m in javaClass.getMethods():
            print "Processing method: ", m.getName()
            if m.getName() != 'ALLATORIxDEMO':
                for statement in m.getBody():
                    self.find_allatori(unit, statement, statement)


    def find_allatori(self, unit, father, element):
        if isinstance(element, IJavaCall) and element.getMethod().getName() == 'ALLATORIxDEMO':
            # get the obfuscated string
            try:
                obfuscated_string = self.prepare_string(element.getArguments()[0].getString())
                print "Processing obfuscated string: ", obfuscated_string
            except AttributeError:
                print "Not a call to ALLATORIxDEMO"
                return

            # the de-obfuscation routine is configured by two integers x1 and x2
            # those values are different for each routine
            # we ask the end-user what values to use
            x1, x2 = self.get_args(obfuscated_string)

            # de-obfuscate
            deobfuscated_string = self.deobfuscate(obfuscated_string,x1,x2)

            # if de-obfuscation was successful, we ask end-user if we should replace in the code or not
            if deobfuscated_string is not None:
                print "De-obfuscated string: ", deobfuscated_string
                answer = self.ctx.displayQuestionBox(deobfuscated_string, 'Shall we replace? (y/n)[n]', 'n')
                if answer == 'y':
                    father.replaceSubElement(element, self.cstbuilder.createString(deobfuscated_string))
                    unit.notifyListeners(JebEvent(J.UnitChange))
        else:
            if isinstance(element, IJavaAssignment):
                self.find_allatori(unit, element, element.getRight())
            else:
                for sub in element.getSubElements():
                    self.find_allatori(unit, element, sub)

    def get_args(self, caption):
        # ask user how to configure the de-obfuscation routine
        # caption is the title to display
        # returns two ints
        default_x1 = '53'
        default_x2 = '66'
        x1 = self.ctx.displayQuestionBox(caption, 'x1= (default is %s)' % (default_x1), default_x1)
        x2 = self.ctx.displayQuestionBox(caption, 'x2= (default is %s)' % (default_x2), default_x2)
        
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
        # ALLATORIxDEMO decoding routine
        decoded = ''
        try:
            index = len(thestring) -1
            while (index >=0):
                decoded = chr(ord(thestring[index]) ^ x1) + decoded
                if (index - 1) < 0:
                    break
                index = index - 1
                decoded = chr(ord(thestring[index]) ^ x2) + decoded
                index = index - 1
        except ValueError:
            print "WARNING: Failed to decode this string: ", thestring
            return None
        return decoded


        
        
        
