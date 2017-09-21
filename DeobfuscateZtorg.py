"""
Script to de-obfuscate Android/Ztorg string obfuscation

My first JEB2 script, so can certainly be improved!
Written with help from JEB2JavaASTDecryptStrings.py

A. Apvrille - Feb 2017
"""

from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext
from com.pnfsoftware.jeb.core import RuntimeProjectUtil
from com.pnfsoftware.jeb.core.actions import Actions, ActionContext, ActionXrefsData
from com.pnfsoftware.jeb.core.events import JebEvent, J
from com.pnfsoftware.jeb.core.output import AbstractUnitRepresentation, UnitRepresentationAdapter
from com.pnfsoftware.jeb.core.units.code import ICodeUnit, ICodeItem
from com.pnfsoftware.jeb.core.units.code.java import IJavaSourceUnit, IJavaStaticField, IJavaNewArray, IJavaConstant, IJavaCall, IJavaField, IJavaMethod, IJavaClass, IJavaArrayElt, JavaElementType

class DeobfuscateZtorg(IScript):

  def run(self, ctx):
    engctx = ctx.getEnginesContext()
    if not engctx:
      print('Back-end engines not initialized')
      return

    projects = engctx.getProjects()
    if not projects:
      print('There is no opened project')
      return

    prj = projects[0]
    print('Decompiling code units of %s...' % prj)

    self.codeUnit = RuntimeProjectUtil.findUnitsByType(prj, ICodeUnit, False)[0]
    self.units = RuntimeProjectUtil.findUnitsByType(prj, IJavaSourceUnit, False)
    self.parse()

  def parse(self):
    for unit in self.units:
      javaClass = unit.getClassElement()
      self.cstbuilder = unit.getFactories().getConstantFactory()
      print "[+] Processing class %s" % (javaClass.getName())
      # parse the project for static constructors that call the decoding method
      decode_method = 'La/b/c;->a([B)Ljava/lang/String;'
      for m in javaClass.getMethods():
            if m.getName() == '<clinit>': # only in static constructors
              for statement in m.getBody():
                '''
                catch typical assignments such as:
                c.a = c.decode(new byte[]{...})
                c.a = new String(c.decode(new byte[] {...})
                ...
                TODO: enhance so it catches assignments such as these:
                 v2[25] = 64;
                 v2[26] = 88;
                 v2[27] = 5;
                 v2[28] = 25;
                 v2[29] = 35;
                 v0[0] = c.a(v2);
                '''
                if statement.getElementType() == JavaElementType.Assignment:
                  if isinstance(statement.getRight(),IJavaCall) and statement.getRight().getMethod().getSignature() == decode_method:
                    #print "Right: ",statement.getRight()
                    self.replace(statement, statement.getRight(), statement, javaClass, unit)
                  else:
                    # parse all sub calls
                    for rightsub in statement.getRight().getSubElements():
                      #print "Rightsub: ",rightsub
                      if isinstance(rightsub,IJavaCall) and rightsub.getMethod().getSignature() == decode_method:
                        self.replace(statement.getRight(), rightsub, statement, javaClass, unit)

    return True

  def replace(self, father, elem, statement, javaClass, unit):
    for argument in elem.getArguments():
      if isinstance(argument, IJavaNewArray):
        encbytes = []
        decbytes = []
        for v in argument.getInitialValues():
          # retrieve the encoded values
          encbytes.append(v.getByte())
        if len(encbytes) > 0:
          decbytes = self.decodeBytes(encbytes)
          id = ''
          if isinstance(statement.getLeft(), IJavaArrayElt):
            id = str(statement.getLeft().getIndex())
          if isinstance(statement.getLeft(), IJavaStaticField):
            id = str(statement.getLeft().getField().getSignature())
          print "Class: %s Id: %s Value: %s" % (javaClass.getName(), id, ''.join(map(chr,decbytes)))
          father.replaceSubElement(elem, self.cstbuilder.createString(''.join(map(chr,decbytes))))
          unit.notifyListeners(JebEvent(J.UnitChange))


  def decodeBytes(self, buf):
    '''Decodes the buffer and returns the decoded result
    Similar to La/b/c;->a([B)Ljava/lang/String;
    '''
    key0 = buf[0]
    key1 = buf[len(buf)-1]

    # copy buffer
    result = buf[1:len(buf)-1]

    # decode
    for i in range(0, len(result)):
      result[i] = result[i] ^ key1
      result[i] = result[i] ^ key0

    return result
      

