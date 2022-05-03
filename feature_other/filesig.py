import sys, io
from optparse import OptionParser
import struct
import shutil

def gather_file_info_win(binary):
        
        # Referenced format from stackoverflow and https://wiki.osdev.org/PE
        
        PE_header_data = {}
        binary = open(binary, 'rb')
        binary.seek(int('3C', 16))
        PE_header_data['buffer'] = 0
        PE_header_data['JMPtoCodeAddress'] = 0
        PE_header_data['dis_frm_pehdrs_sectble'] = 248
        PE_header_data['pe_header_location'] = struct.unpack('<i', binary.read(4))[0]
        
        # Start of COFF
        PE_header_data['COFF_Start'] = PE_header_data['pe_header_location'] + 4
        binary.seek(PE_header_data['COFF_Start'])
        PE_header_data['MachineType'] = struct.unpack('<H', binary.read(2))[0]
        binary.seek(PE_header_data['COFF_Start'] + 2, 0)
        PE_header_data['NumberOfSections'] = struct.unpack('<H', binary.read(2))[0]
        PE_header_data['TimeDateStamp'] = struct.unpack('<I', binary.read(4))[0]
        binary.seek(PE_header_data['COFF_Start'] + 16, 0)
        PE_header_data['SizeOfOptionalHeader'] = struct.unpack('<H', binary.read(2))[0]
        PE_header_data['Characteristics'] = struct.unpack('<H', binary.read(2))[0]
        #End of COFF
        
        PE_header_data['OptionalHeader_start'] = PE_header_data['COFF_Start'] + 20


        #Begin Standard Fields section of Optional Header
        binary.seek(PE_header_data['OptionalHeader_start'])
        PE_header_data['Magic'] = struct.unpack('<H', binary.read(2))[0]
        PE_header_data['MajorLinkerVersion'] = struct.unpack("!B", binary.read(1))[0]
        PE_header_data['MinorLinkerVersion'] = struct.unpack("!B", binary.read(1))[0]
        PE_header_data['SizeOfCode'] = struct.unpack("<I", binary.read(4))[0]
        PE_header_data['SizeOfInitializedData'] = struct.unpack("<I", binary.read(4))[0]
        PE_header_data['SizeOfUninitializedData'] = struct.unpack("<I",
                                                               binary.read(4))[0]
        PE_header_data['AddressOfEntryPoint'] = struct.unpack('<I', binary.read(4))[0]
        PE_header_data['PatchLocation'] = PE_header_data['AddressOfEntryPoint']
        PE_header_data['BaseOfCode'] = struct.unpack('<I', binary.read(4))[0]
        if PE_header_data['Magic'] != 0x20B:
            PE_header_data['BaseOfData'] = struct.unpack('<I', binary.read(4))[0]
        # End Standard Fields section of Optional Header
        

        # Begin Windows-Specific Fields of Optional Header
        if PE_header_data['Magic'] == 0x20B:
            PE_header_data['ImageBase'] = struct.unpack('<Q', binary.read(8))[0]
        else:
            PE_header_data['ImageBase'] = struct.unpack('<I', binary.read(4))[0]
        
        PE_header_data['SectionAlignment'] = struct.unpack('<I', binary.read(4))[0]
        PE_header_data['FileAlignment'] = struct.unpack('<I', binary.read(4))[0]
        PE_header_data['MajorOperatingSystemVersion'] = struct.unpack('<H',
                                                                   binary.read(2))[0]
        PE_header_data['MinorOperatingSystemVersion'] = struct.unpack('<H',
                                                                   binary.read(2))[0]
        PE_header_data['MajorImageVersion'] = struct.unpack('<H', binary.read(2))[0]
        PE_header_data['MinorImageVersion'] = struct.unpack('<H', binary.read(2))[0]
        PE_header_data['MajorSubsystemVersion'] = struct.unpack('<H', binary.read(2))[0]
        PE_header_data['MinorSubsystemVersion'] = struct.unpack('<H', binary.read(2))[0]
        PE_header_data['Win32VersionValue'] = struct.unpack('<I', binary.read(4))[0]
        PE_header_data['SizeOfImageLoc'] = binary.tell()
        PE_header_data['SizeOfImage'] = struct.unpack('<I', binary.read(4))[0]
        PE_header_data['SizeOfHeaders'] = struct.unpack('<I', binary.read(4))[0]
        PE_header_data['CheckSum'] = struct.unpack('<I', binary.read(4))[0]
        PE_header_data['Subsystem'] = struct.unpack('<H', binary.read(2))[0]
        PE_header_data['DllCharacteristics'] = struct.unpack('<H', binary.read(2))[0]
        
        if PE_header_data['Magic'] == 0x20B:
            PE_header_data['SizeOfStackReserve'] = struct.unpack('<Q', binary.read(8))[0]
            PE_header_data['SizeOfStackCommit'] = struct.unpack('<Q', binary.read(8))[0]
            PE_header_data['SizeOfHeapReserve'] = struct.unpack('<Q', binary.read(8))[0]
            PE_header_data['SizeOfHeapCommit'] = struct.unpack('<Q', binary.read(8))[0]

        else:
            PE_header_data['SizeOfStackReserve'] = struct.unpack('<I', binary.read(4))[0]
            PE_header_data['SizeOfStackCommit'] = struct.unpack('<I', binary.read(4))[0]
            PE_header_data['SizeOfHeapReserve'] = struct.unpack('<I', binary.read(4))[0]
            PE_header_data['SizeOfHeapCommit'] = struct.unpack('<I', binary.read(4))[0]
        PE_header_data['LoaderFlags'] = struct.unpack('<I', binary.read(4))[0]  # zero
        PE_header_data['NumberofRvaAndSizes'] = struct.unpack('<I', binary.read(4))[0]
        # End Windows-Specific Fields of Optional Header
        
        # Begin Data Directories of Optional Header
        PE_header_data['ExportTableRVA'] = struct.unpack('<I', binary.read(4))[0]
        PE_header_data['ExportTableSize'] = struct.unpack('<I', binary.read(4))[0]
        PE_header_data['ImportTableLOCInPEOptHdrs'] = binary.tell()
        
        #ImportTable SIZE|LOC
        PE_header_data['ImportTableRVA'] = struct.unpack('<I', binary.read(4))[0]
        PE_header_data['ImportTableSize'] = struct.unpack('<I', binary.read(4))[0]
        PE_header_data['ResourceTable'] = struct.unpack('<Q', binary.read(8))[0]
        PE_header_data['ExceptionTable'] = struct.unpack('<Q', binary.read(8))[0]
        PE_header_data['CertTableLOC'] = binary.tell()
        PE_header_data['CertLOC'] = struct.unpack("<I", binary.read(4))[0]
        PE_header_data['CertSize'] = struct.unpack("<I", binary.read(4))[0]
        binary.close()
        return PE_header_data


def writeCert(cert, exe, output):
    PE_header_data = gather_file_info_win(exe)
    
    if not output: 
        output = output = str(exe) + "_signed"

    shutil.copy2(exe, output)
    
    print("Output file: {0}".format(output))

    with open(exe, 'rb') as g:
        with open(output, 'wb') as f:
            f.write(g.read())
            f.seek(0)
            f.seek(PE_header_data['CertTableLOC'], 0)
            f.write(struct.pack("<I", len(open(exe, 'rb').read())))
            f.write(struct.pack("<I", len(cert)))
            f.seek(0, io.SEEK_END)
            f.write(cert)

    print("Signature appended. \nFIN.")

def copyCert(exe):
    PE_header_data = gather_file_info_win(exe)

    if PE_header_data['CertLOC'] == 0 or PE_header_data['CertSize'] == 0:
        # not signed
        print("Input file Not signed!")
        sys.exit(-1)

    with open(exe, 'rb') as f:
        f.seek(PE_header_data['CertLOC'], 0)
        cert = f.read(PE_header_data['CertSize'])
    return cert



def outputCert(exe, output):
    cert = copyCert(exe)
    if not output:
        output = str(exe) + "_sig"

    print("Output file: {0}".format(output))

    open(output, 'wb').write(cert)

    print("Signature ripped. \nFIN.")


def check_sig(exe):
    PE_header_data = gather_file_info_win(exe)
 
    if PE_header_data['CertLOC'] == 0 or PE_header_data['CertSize'] == 0:
        # not signed
        print("Inputfile Not signed!")
    else:
        print("Inputfile is signed!")


def truncate(exe, output):
    PE_header_data = gather_file_info_win(exe)
 
    if PE_header_data['CertLOC'] == 0 or PE_header_data['CertSize'] == 0:
        # not signed
        print("Inputfile Not signed!")
        sys.exit(-1)
    else:
        print( "Inputfile is signed!")

    if not output:
        output = str(exe) + "_nosig"

    print("Output file: {0}".format(output))

    shutil.copy2(exe, output)

    with open(output, "r+b") as binary:
        print('Overwriting certificate table pointer and truncating binary')
        binary.seek(-PE_header_data['CertSize'], io.SEEK_END)
        binary.truncate()
        binary.seek(PE_header_data['CertTableLOC'], 0)
        binary.write(b"\x00\x00\x00\x00\x00\x00\x00\x00")

    print("Signature removed. \nFIN.")


def signfile(exe, sigfile, output):
    PE_header_data = gather_file_info_win(exe)
    
    cert = open(sigfile, 'rb').read()

    if not output: 
        output = output = str(exe) + "_signed"

    shutil.copy2(exe, output)
    
    print("Output file: {0}".format(output))
    
    with open(exe, 'rb') as g:
        with open(output, 'wb') as f:
            f.write(g.read())
            f.seek(0)
            f.seek(PE_header_data['CertTableLOC'], 0)
            f.write(struct.pack("<I", len(open(exe, 'rb').read())))
            f.write(struct.pack("<I", len(cert)))
            f.seek(0, io.SEEK_END)
            f.write(cert)
    print("Signature appended. \nFIN.")


if __name__ == "__main__":
    usage = 'usage: %prog [options]'
    parser = OptionParser()
    parser.add_option("-i", "--file", dest="inputfile", 
                  help="file still signature from", metavar="FILE")
    parser.add_option('-r', '--rip', dest='ripsig', action='store_true',
                  help='rip signature off inputfile')
    parser.add_option('-a', '--add', dest='addsig', action='store_true',
                  help='add signautre to targetfile')
    parser.add_option('-o', '--output', dest='outputfile',
                  help='output file')
    parser.add_option('-s', '--sig', dest='sigfile',
                  help='binary signature from disk')
    parser.add_option('-t', '--target', dest='targetfile',
                  help='file to append signature too')
    parser.add_option('-c', '--checksig', dest='checksig', action='store_true',
                  help='file to check if signed; does not verify signature')
    parser.add_option('-T', '--truncate', dest="truncate", action='store_true',
                  help='truncate signature (i.e. remove sig)')
    (options, args) = parser.parse_args()
    
    # rip signature
    # inputfile and rip to outputfile
    if options.inputfile and options.ripsig:
        print("Ripping signature to file!")
        outputCert(options.inputfile, options.outputfile)
        sys.exit()    

    # copy from one to another
    # inputfile and rip to targetfile to outputfile    
    if options.inputfile and options.targetfile:
        cert = copyCert(options.inputfile)
        writeCert(cert, options.targetfile, options.outputfile)
        sys.exit()

    # check signature
    # inputfile 
    if options.inputfile and options.checksig:
        check_sig(options.inputfile) 
        sys.exit()

    # add sig to target file
    if options.targetfile and options.sigfile:
        signfile(options.targetfile, options.sigfile, options.outputfile)
        sys.exit()
        
    # truncate
    if options.inputfile and options.truncate:
        truncate(options.inputfile, options.outputfile)
        sys.exit()

    parser.print_help()
    parser.error("You must do something!")
