#!/usr/bin/env python3
import re
import argparse
import datetime

'''
__author__ = "@cryptax"
__license__ = "MIT License"
__version__ = "0.3"
'''

def computeSensorCrc(data):
    '''
    TI's CRC module is shifting the bits in the opposit direction of CRC16 CCITT. 
    http://www.ti.com/lit/ug/slau398f/slau398f.pdf
    https://e2e.ti.com/support/microcontrollers/msp430/f/166/t/19030
    '''
    crc=0x0000FFFF
    datalen=len(data)
    for i in range(0, datalen):
        rev = int('{:08b}'.format(data[i])[::-1],2) # reverse bits
        crc = ((crc >> 8) & 0x0000ffff) | ((crc << 8) & 0x0000ffff)
        crc = crc ^ rev
        crc = crc ^ (((crc & 0xff) >> 4) & 0x0000ffff)
        crc = crc ^ ((crc << 12) & 0x0000ffff)
        crc = crc ^ (((crc & 0xff) << 5) & 0x0000ffff)

    return crc


def read_proxmark_dump(filename):
    # read a NFC dump such as:
    # Block 00   F4 18 B0 32 03 01 02 08    ...2....          
    # Block 01   00 00 00 00 00 00 00 00    ........
    # and returns a binary string
    # b'\xf4\x18\xb0...'
    # Will not work if file has a header
    print("Reading {0} (proxmark3 dump)".format(filename))
    buffer = open(filename).read()
    dump_string = ''.join(re.findall("Block [0-9a-fA-F]+   (?P<myblock>[a-fA-F0-9 ]+)   ", buffer)).replace(' ','')
    return bytes.fromhex(dump_string)

def get_status_indicator(dump):
    if dump[4] == 0x01:
        return "Ready to Activate"
    if dump[4] == 0x02:
        return "Activating"
    if dump[4] == 0x03:
        return "Operational"
    if dump[4] == 0x05:
        return "Expired"
    if dump[4] == 0x06:
        return "Invalid"
    return "Unknown"

def get_activity_switch(dump):
    if dump[5] == 0x01:
        return "Active"
    return "Inactive"

def get_trend_index(dump):
    return dump[26]

def get_historic_index(dump):
    return dump[27]

def get_sensor_time(dump):
    # number of minutes the sensor has been used
    #print("Sensor bytes: high={0} low={1}".format(hex(dump[317]), hex(dump[316])))
    return ((0xff & dump[317])*256) + (dump[316] & 0xff)

def get_historic_record(dump, index):
    # b'm\x03\xc8\x1c\xd9\x00'
    return dump[124+(index*6):124+(index*6)+6]

def get_trend_record(dump, index):
    #print("Trend record no.{0:2}: {1}".format(index, dump[28+(index*6):28+(index*6)+6].hex()))
    return dump[28+(index*6):28+(index*6)+6]

def get_sensor_region(dump):
    if dump[323] == 0x1:
        return "Europe / UK"
    if dump[323] == 0x2:
        return "US"
    if dump[323] == 0x4:
        return "New Zealand"
    if dump[323] == 0x8:
        return "Israel / Asia"

def get_header_checksum(dump):
    return dump[0:2]
    
def get_record_checksum(dump):
    return dump[24:26]
    
def read_glucose(high, low):
    return (0x3fff & (256 * (0xff & high))+(0xff & low)) / 10.0

def read_all_records(dump):
    for i in range(0, 16):
        record = get_trend_record(dump, i)
        level = read_glucose(record[1], record[0])
        print("Trend record no.{0:2}: {1} = {2:5} mg/dL".format(i, record.hex(), level))

    for i in range(0,32):
        record = get_historic_record(dump, i)
        level = read_glucose(record[1], record[0])
        print("Historic record no.{0:2}: {1} = {2:5} mg/dL".format(i, record.hex(), level))
        

def get_arguments():
    parser = argparse.ArgumentParser(description='Read glucose dumps')
    parser.add_argument('-p', '--proxmark', help='read a proxmark3 memory dump', action='store')
    args = parser.parse_args()
    return args

def print_grayblock(dump, block, description=''):    
    print("%04X Block %02X \033[1;30;1m" % (0xf860+(block*8),block), end='', flush=True)
    for index in range( block*8, (block+1)*8):
        print("%02X " % (dump[index]), end='', flush=True)
    print("{0}\033[0m".format(description)) # \n

def print_block0(dump, block=0):
    print("%04X Block %02X " % (0xf860+(block*8),block), end='', flush=True)

    # CRC in yellow
    print("\033[1;33;1m%02X %02X" % (dump[block*8], dump[block*8+1]), end='', flush=True)
    # Two unknown bytes in gray
    print("\033[1;30;1m", end='')
    for i in range(0, 2):
        print(" %02X" % (dump[block*8+2+i]), end='')
    # Status indicator in red
    print("\033[1;31;1m %02X" % (dump[block*8+4]),end='')
    # Expired indicator in blue
    print("\033[1;34;1m %02X" % (dump[block*8+5]), end='')
    # remaining gray
    print("\033[1;30;1m", end='')
    for i in range(0, 2):
        print(" %02X" % (dump[block*8+6+i]), end='')

    # Description
    print(" \033[1;33;1mHeader CRC\033[1;31;1m Stage of Life\033[1;34;1m Expiration indicator\033[0m")
    
def print_block3(dump, block=3):
    print("%04X Block %02X " % (0xf860+(block*8),block), end='', flush=True)
        
    # CRC in yellow
    print("\033[1;33;1m%02X %02X" % (dump[block*8], dump[block*8+1]), end='', flush=True)
    # Trend index in red
    print("\033[1;31;1m %02X" % (dump[block*8+2]),end='')
    # History index in blue
    print("\033[1;34;1m %02X" % (dump[block*8+3]), end='')
    # Beginning of first block in gray
    print("\033[1;30;1m", end='')
    for i in range(0, 4):
        print(" %02X" % (dump[block*8+4+i]), end='')

    # Description
    print(" \033[1;33;1mBlock CRC\033[1;31;1m Trend index\033[1;34;1m History index \033[1;30;1m1st Trend Record\033[0m")

def print_block0f(dump, block=0x0f):
    print("%04X Block %02X " % (0xf860+(block*8), block), end='', flush=True)

    print("\033[1;37;1m", end='')
    for i in range(0, 4):
        print("%02X " % (dump[block*8+i]), end='')

    # History blocks
    print("\033[1;30;1m", end='')
    for i in range(0, 4):
        print("%02X " % (dump[block*8+4+i]), end='')

    print("\033[1;37;1mLast trend record \033[1;30;1m1st History Record\033[0m")

def print_block27(dump, block=0x27):
    print("%04X Block %02X " % (0xf860+(block*8),block), end='', flush=True)

    # Finish history record
    print("\033[1;37;1m", end='')
    for i in range(0, 4):
        print("%02X " % (dump[block*8+i]), end='')

    # Wear time
    print("\033[1;33;1m%02X %02X " % (dump[block*8+4], dump[block*8+5]), end='', flush=True)

    # Unknown
    print("\033[0m%02X %02X" % (dump[block*8+6], dump[block*8+7]), end='', flush=True)

    # Description
    print(" \033[1;37;1mLast history record \033[1;33;1mWear time\033[0m")
    
def print_block28(dump, block=0x28):
    
    print("%04X Block %02X " % (0xf860+(block*8),block), end='', flush=True)
    for i in range(0, 2):
        print("%02X " % (dump[block*8+i]), end='')

    print("\033[1;35;1m%02X %02X \033[0m" % (dump[block*8+2], dump[block*8+3]), end='', flush=True)
    
    for i in range(0, 4):
        print("%02X " % (dump[block*8+i+4]), end='')

    print("\033[1;35;1mSensor Region\033[0m")

def display(dump):
    # block 0
    print_block0(dump)

    # blocks 1 and 2 are the header - in gray
    for block in range(1,3):
        print_grayblock(dump, block, ' ... continued Header')

    # block 3
    print_block3(dump)

    # blocks 4 - 0x0e
    for block in range(4, 0x0f):
        print_grayblock(dump, block, ' ... continued Trend Records')

    # block 0x0f
    print_block0f(dump)

    # blocks 0x10 - 0x26
    for block in range(0x10, 0x27):
        print_grayblock(dump, block, ' ... continued History Records')
    print_block27(dump)
    print_block28(dump)

    if len(dump) > 1904:
        print('...\n')
        print_grayblock(dump, 0x2b, 'CRC and commands')
        print('...\n')
        print_grayblock(dump, 0xe9, 'Disabled commands')
        print('...\n')
        print_grayblock(dump, 0xeb, 'Enabled commands')

def print_crc(label, crc_read, data):
    crc_computed = computeSensorCrc(data).to_bytes(2, byteorder='little')

    print("{0:20.20}: read={1} computed={2}".format(label, bytearray(crc_read).hex(), bytearray(crc_computed).hex()), end='')

    if bytearray(crc_read).hex() == bytearray(crc_computed).hex():
        print("\033[1;32;1m OK\033[0m")
    else:
        print("\033[1;31;1m ERROR: CRC does not match\033[0m")
    
    
if __name__ == "__main__":
    args = get_arguments()
    dump = read_proxmark_dump(args.proxmark)
    display(dump)

    print("---")

    status_indicator = get_status_indicator(dump)
    expiration_indicator = get_activity_switch(dump)
    print("{0:20.20}: {1}".format('Status indicator', status_indicator))
    print("{0:20.20}: {1}".format('Expiration indicator', expiration_indicator))

    print_crc('Header CRC', get_header_checksum(dump), dump[2:2+(0x0b*2)])
    print_crc('Record CRC', get_record_checksum(dump), dump[26:26+(0x93*2)])
    
    trend_index = get_trend_index(dump)
    historic_index = get_historic_index(dump)
    print("{0:20.20}: {1}".format('Trend index', trend_index))
    print("{0:20.20}: {1}".format('Historic index', historic_index))

    current_trend = get_trend_record(dump, trend_index)
    level = read_glucose(current_trend[1], current_trend[0])
    print("{0:20.20}: {1} mg/dL".format('Trend Glucose level', level))
                                        
    current_historic = get_historic_record(dump, historic_index)
    level = read_glucose(current_historic[1], current_historic[0])
    print("{0:20.20}: {1} mg/dL".format('Historic Glucose level', level))

    sensor_time = get_sensor_time(dump)
    print("{0:20.20}: {1} minutes (i.e {2} hours)".format('Wear time', sensor_time, str(datetime.timedelta(minutes=sensor_time))))

    sensor_region = get_sensor_region(dump)
    print("{0:20.20}: {1}".format('Sensor region', sensor_region))

    if len(dump) > 1904:
        print_crc('Command CRC', dump[344:346], dump[346:346+(0x30b*2)])




    


    
