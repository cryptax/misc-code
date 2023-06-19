import r2pipe
import re
import sys

'''
Helper r2pipe script for Radare2 to display useful comment to Dart byte array loading
@cryptax - June 19, 2023
Launch it with #!pipe python3 ./dart-bytes.py
'''

class R2DartBytes:
    def __init__(self, begin_str='', end_str='', verbose=False):
        self.r2 = r2pipe.open()
        if begin_str == '':
            self.begin_offset = self.get_current_offset()
        else:
            self.begin_offset = int(begin_str, 16)
            
        if end_str == '':
            self.end_offset = self.begin_offset + 1
        else:
            self.end_offset = int(end_str, 16)
            
        self.verbose = verbose

    def process_line(self, line):
        try:
            if re.search('mov r11d, 0x[a-f0-9]*$', line['disasm']) is not None:
                hexliteral = line['disasm'].split(',')[-1].strip().replace('0x','')
                value = int(hexliteral, 16) // 2
                comment = 'Load 0x%02x (character="%c")' % (value, chr(value))
                if self.verbose:
                    print(comment)
                self.r2.cmd("CC %s @ %d" % (comment, line['offset']))
        except KeyError:
            pass

    def get_current_offset(self):
        line = self.r2.cmdj("pdj 1")[0]
        return line['offset']

    def process(self):
        for offset in range(self.begin_offset, self.end_offset):
            line = self.r2.cmdj(f"pdj 1 @ {offset}")[0]
            self.process_line(line)

def main():
    print('Dart Bytes R2Pipe Script')
    nb_arguments = len(sys.argv) - 1
    if nb_arguments == 0:
        r = R2DartBytes()
    elif nb_arguments == 1:
        r = R2DartBytes(end_str=sys.argv[1])
    elif nb_arguments == 2:
        r = R2DartBytes(begin_str=sys.argv[1], end_str=sys.argv[2])
    else:
        print('dart-bytes.py <begin-offset> <end-offset>')
        print('dart-bytes.py <end-offset>')
        print('dart-bytes.py: processes the current line')
        return
    r.process()
    
    
if __name__ == '__main__':
    main()
