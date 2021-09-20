#!/usr/bin/python3
#
# A script that list DLL files properties for purpose of finding good Module Stomping candidates.
# The results of this script can then be used in Cobalt Strike Malleable C2 Profiles and
# for the sake of other shellcode process-injection tests.
#
# Let's the user find modules matching criterias such as:
#   - modules that are .NET ones
#   - modules of a big enough size / SizeOfImage / code section size
#   - modules with enough room to fit shellcode for Module Stomping/DLL Hollowing purposes
#     (calculated as a difference of upper code section address and an entry point address)
#   - modules present at the same time in System32 and SysWOW64
#   - modules used / not used by any process as examined during the scan
#
# CAUTION:
#    The PE Authenticode verification logic is somewhat flawed, as it is unable currently to pull executable's
#    signature if there is no PKCS7 structure pointed by IMAGE_DIRECTORY_ENTRY_SECURITY entry!
#
# Mariusz B. / mgeeky, '21
# <mb [at] binary-offensive.com>
#

import os
import re
import sys
import glob
import pprint
import psutil
import pefile
import tabulate
import platform
import textwrap
import argparse
import tempfile
import subprocess

DEFAULT_COLUMN_SORTED = 'hollow size'

args = None

headers = [
    'type',
    'filename',
    'file size',
    'image size',
    'code size',
    'hollow size',
    '.NET',
    'signed',
    'in System32',
    'in SysWOW64',
    'used by',
    'path',
]

is_wow64 = False
results = []
processModules = {}
filesProcessed = 0

def verbose(x):
    if args.verbose:
        print('[verbose] ' + x)

def isDotNetExecutable(pe):
    idx = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']

    pe.parse_data_directories()
    dir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]

    try:
        if dir_entry.VirtualAddress != 0 and dir_entry.Size > 0:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if entry.dll.decode('utf-8').lower() == 'mscoree.dll':
                    for func in entry.imports:
                        if func.name.decode() == '_CorExeMain':
                            return (True, 'exe')
                        elif func.name.decode() == '_CorDllMain':
                            return (True, 'dll')

                    verbose('Seemingly .NET module but no required imports found. Imported functions:\n' + '\t- '.join([x.name.decode() for x in entry.imports]))
                    return (True, 'unknown')

    except Exception as e:
        verbose(f'Exception occured while checking if .NET executable: {e}')

    return (False, '')

def getCodeSectionSize(pe):
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    for sect in pe.sections:
        if ep > sect.VirtualAddress and ep < (sect.VirtualAddress + sect.Misc_VirtualSize):
            verbose('\tCode section: ' + sect.Name.decode())
            return sect.Misc_VirtualSize

    verbose('\tCould not find section that Entry Point\'s point to. Returning first section\'s size.')
    return pe.sections[0].Misc_VirtualSize

def getHollowSize(pe):
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    hollowSize = 0

    for sect in pe.sections:
        if ep > sect.VirtualAddress and ep < (sect.VirtualAddress + sect.Misc_VirtualSize):
            hollowSize = sect.VirtualAddress + sect.Misc_VirtualSize - ep
            break

    if hollowSize == 0:
        hollowSize = pe.sections[0].VirtualAddress + pe.sections[0].Misc_VirtualSize - ep

    if hollowSize < 0: 
        hollowSize = 0

    return hollowSize

import pefile
 
def extractPKCS7(fname):
    '''A function extracting PKCS7 signature from a PE executable
 
    This function opens the file fname, extracts the PKCS7
    signature in binary (DER) format and returns it as
    a binary string
    '''
 
    # first get the size of the file
    totsize = os.path.getsize(fname)
 
    # open the PE file
    # at opening time we do not need to parse all the information
    # so we can use fast_load
    ape = pefile.PE(fname, fast_load = True)
 
    # parse directories, we are interested only in
    # IMAGE_DIRECTORY_ENTRY_SECURITY
    ape.parse_data_directories( directories=[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY'] ] )
 
    # reset the offset to the table containing the signature
    sigoff = 0
    # reset the lenght of the table
    siglen = 0
 
    # search for the 'IMAGE_DIRECTORY_ENTRY_SECURITY' directory
    # probably there is a direct way to find that directory
    # but I am not aware of it at the moment
    for s in ape.__structures__:
        if s.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY':
            # set the offset to the signature table
            sigoff = s.VirtualAddress
            # set the length of the table
            siglen = s.Size
            break
 
    # close the PE file, we do not need it anymore
    ape.close()
 
    if sigoff < totsize:
        # hmmm, okay we could possibly read this from the PE object
        # but is straightforward to just open the file again
        # as a file object
        f = open(fname, 'rb')
        # move to the beginning of signature table
        f.seek(sigoff)
        # read the signature table
        thesig = f.read(siglen)
        # close the file
        f.close()
 
        # now the 'thesig' variable should contain the table with
        # the following structure
        #   DWORD       dwLength          - this is the length of bCertificate
        #   WORD        wRevision
        #   WORD        wCertificateType
        #   BYTE        bCertificate[dwLength] - this contains the PKCS7 signature
        #                                    with all the
 
        # lets dump only the PKCS7 signature (without checking the lenght with dwLength)
        return thesig[8:]
    else:
        return None

def shell(cmd):
    CREATE_NO_WINDOW = 0x08000000
    timeout = 10
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE

    outs = ''
    errs = ''
    out = subprocess.run(
        cmd, 
        shell=True, 
        capture_output=True, 
        startupinfo=si, 
        creationflags=CREATE_NO_WINDOW,
        timeout=timeout
        )

    outs = out.stdout
    errs = out.stderr

    return outs.decode(errors='ignore').strip()

def verifyPeSignature(fname):
    sign = extractPKCS7(fname)

    if sign != None and len(sign) > 0:
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(sign)
        f.close()
        infile = f.name

        try:
            out = shell(f'openssl pkcs7 -inform DER -print_certs -text -in {infile}')

            verbose(f'[>] File signature verification status:\n{out}')

            if not ('code signing' in out.lower() and 'subject: ' in out.lower() and '-----begin certificate-----' in out.lower()):
                return 'Unsigned'

            signature = ''
            for line in out.split('\n'):
                line = line.strip()

                if 'subject: ' in line.lower():
                    org = ', O='
                    posA = line.find(org)
                    posB = line.find(',', posA+1)

                    if posA + len(org) >= posB:
                        continue 

                    signature = line[posA + len(org):posB]

            return signature

        except:
            raise

        finally:
            os.unlink(f.name)

    return 'Unsigned'

def scanProcessModules():
    global processModules

    verbose('Scanning processes and their modules...')
    for pid in psutil.pids():
        try:
            p = psutil.Process(pid)
            processModules[pid] = {}
            processModules[pid]['name'] = p.name()
            processModules[pid]['exe'] = p.exe()
            processModules[pid]['cmdline'] = p.cmdline()
            processModules[pid]['modules'] = []

            for dll in p.memory_maps():
                processModules[pid]['modules'].append(dll.path)

        except Exception as e:
            if pid in processModules.keys(): 
                del processModules[pid]

    verbose('Done.')

def findProcessesWithModuleLoaded(path):
    usedBy = set()

    for pid in processModules.keys():
        for dll in processModules[pid]['modules']:
            if path.lower() == dll.lower():
                usedBy.add(processModules[pid]['name'])
                break

    return usedBy

def processFile(path):
    global results
    global filesProcessed

    verbose('Processing file: ' + path)

    mod = None

    try:
        mod = pefile.PE(path, fast_load = True)
    except:
        return

    inSystem32 = False
    inSysWOW64 = False

    inSystem32 = os.path.isfile(os.path.join(os.path.join(os.environ['SystemRoot'], 'SysNative' if is_wow64 else 'System32'), os.path.basename(path)))
    inSysWOW64 = os.path.isfile(os.path.join(os.path.join(os.environ['SystemRoot'], 'SysWOW64' if not is_wow64 else 'System32'), os.path.basename(path)))

    infos = {
        'path' : path,
        'filename' : os.path.basename(path),
        'type' : 'dll' if (mod.OPTIONAL_HEADER.DllCharacteristics != 0) else 'exe',
        '.NET' : isDotNetExecutable(mod)[0],
        'signed' : verifyPeSignature(path),
        'file size' : os.path.getsize(path),
        'image size' : mod.OPTIONAL_HEADER.SizeOfImage,
        'code size' : getCodeSectionSize(mod),
        'hollow size' : getHollowSize(mod),
        'used by' : findProcessesWithModuleLoaded(path),
        'in System32' : inSystem32,
        'in SysWOW64' : inSysWOW64,
    }

    mod.close()

    assert len(infos.keys()) == len(headers), "headers and infos.keys() mismatch"
    assert list(infos.keys()).sort() == list(headers).sort(), "headers and infos.keys() mismatch while sorted"

    row = []
    MaxWidth = 40

    for h in headers:
        obj = None

        if type(infos[h]) == set or type(infos[h]) == list or type(infos[h]) == tuple:
            obj = ', '.join(infos[h])
        else:
            obj = infos[h]

        if type(obj) == str and len(obj) > MaxWidth:
            obj = '\n'.join(textwrap.wrap(obj, width = MaxWidth))

        row.append(obj)

    appendRow = True

    #
    # Unfilter criterias
    #
    if args.min_code_size > 0 and infos['code size'] < args.min_code_size:
        appendRow = False
        verbose(f'\tFile {infos["filename"]} not added as it\'s code section size is less than requested ({infos["code size"]} < {args.min_code_size})')

    if args.min_file_size > 0 and infos['file size'] < args.min_file_size:
        appendRow = False
        verbose(f'\tFile {infos["filename"]} not added as it\'s file size is less than requested ({infos["file size"]} < {args.min_file_size})')

    if args.min_image_size > 0 and infos['image size'] < args.min_image_size:
        appendRow = False
        verbose(f'\tFile {infos["filename"]} not added as it\'s image size is less than requested ({infos["image size"]} < {args.min_image_size})')

    if args.hollow_size > 0 and infos['hollow size'] < args.hollow_size + 16:
        appendRow = False
        verbose(f'\tFile {infos["filename"]} not added as it\'s room for Module Stomping/Hollowing is less than requested ({infos["hollow size"]} < {args.hollow_size})')

    if args.used and len(infos['used by']) == 0:
        appendRow = False
        verbose(f"\tFile {infos['filename']} not added as it was not used by any process during the scan.")

    if args.not_used and len(infos['used by']) != 0:
        appendRow = False
        verbose(f"\tFile {infos['filename']} not added as it was used by any process during the scan.")

    if args.dotnet and not infos['.NET']:
        appendRow = False
        verbose(f"\tFile {infos['filename']} not added as it was not a .NET assembly.")

    if args.signed and len(infos['signed']) == 0:
        appendRow = False
        verbose(f"\tFile {infos['filename']} not added as it was not code signed.")

    if args.unsigned and len(infos['signed']) > 0:
        appendRow = False
        verbose(f"\tFile {infos['filename']} not added as it was not unsigned.")

    if args.system_cross_arch and (not infos['in System32'] or not infos['in SysWOW64']):
        appendRow = False
        verbose(f"\tFile {infos['filename']} not added as it was not present in System32 and SysWOW64 at the same time.")

    if len(args.process) > 0 and args.process not in infos['used by']:
        appendRow = False
        verbose(f"\tFile {infos['filename']} not added as it was not used by process {args.process}.")

    if appendRow:
        results.append(row)
        verbose('Processed results:\n' + pprint.pformat(infos))

    else:
        verbose(f'File {os.path.basename(path)} did not met filter criterias.')

    filesProcessed += 1


def processDir(path):
    for file in glob.glob(os.path.join(path, '**'), recursive=args.recurse):
        if os.path.isfile(file) and file.lower().endswith('.dll'):
            processFile(file)

def opts(argv):
    params = argparse.ArgumentParser(
        prog = argv[0], 
        usage='%(prog)s [options] <path>'
    )

    params.add_argument('path', help = 'Path to a DLL/directory.')
    params.add_argument('-r', '--recurse', action='store_true', help='If <path> is a directory, perform recursive scan.')
    params.add_argument('-v', '--verbose', action='store_true', help='Verbose mode.')

    sorting = params.add_argument_group('Output sorting')
    sorting.add_argument('-a', '--ascending', action='store_true', help = 'Sort in ascending order instead of default of descending.')
    sorting.add_argument('-c', '--column', default=DEFAULT_COLUMN_SORTED, choices=headers, metavar='COLUMN', help = 'Sort by this column name. Default: filename. Available columns: "' + '", "'.join(headers) + '"')
    sorting.add_argument('-n', '--first', type=int, default=0, metavar='NUM', help='Show only first N results, as specified in this paremeter. By default will show all candidates.')

    filters = params.add_argument_group('Output filtering')
    filters.add_argument('-C', '--min-code-size', type=int, default=0, metavar='CODESIZE', help='Show only modules with code section bigger than this value.')
    filters.add_argument('-I', '--min-image-size', type=int, default=0, metavar='IMAGESIZE', help='Show only modules which images are bigger than this value.')
    filters.add_argument('-E', '--hollow-size', type=int, default=0, metavar='HOLLOWSIZE', help='Show only modules with enough room to fit shellcode in Module Stomping / DLL Hollowing technique. Example Beacon size requirement: 300KB (307200).')
    filters.add_argument('-S', '--min-file-size', type=int, default=0, metavar='SIZE', help='Show only modules of size bigger than this value. Cobalt Strike c2lint complains when module stomping target is smaller than 23MB (24117248).')
    filters.add_argument('-P', '--process', type=str, default='', metavar='NAME', help='Show only modules that are used by this process.')
    filters.add_argument('-U', '--used', action='store_true', help='Show only modules that are used by any process in the system.')
    filters.add_argument('-Q', '--not-used', action='store_true', help='Show only modules that are NOT used by any process in the system.')
    filters.add_argument('-D', '--dotnet', action='store_true', help='Show only modules that are .NET assemblies.')
    filters.add_argument('-G', '--signed', action='store_true', help='Show only code signed modules.')
    filters.add_argument('-H', '--unsigned', action='store_true', help='Show only unsigned modules.')
    filters.add_argument('-W', '--system-cross-arch', action='store_true', help='Show only modules that are present in both System32 and SysWOW64 directories.')
    
    args = params.parse_args()

    if len(args.process) > 0 and not args.process.lower().endswith('.exe'):
        args.process += '.exe'

    if args.signed or args.unsigned:
        print('[!] CAUTION: The PE Authenticode signature verification logic will return FALSE POSITIVES\n             as it\'s unable to determine some of the signatures! Proceed with cuation.\n')

    return args

def main(argv):
    global args
    global is_wow64

    print('''
    :: stomp-dll-info.py - Your Module Stomping / DLL Hollowing candidates headhunter!
    A script that scans, filters, analyzes DLL files displaying viable candidates for module stomping.
    
    Mariusz B. / mgeeky, '21
    <mb [at] binary-offensive.com> 
''')

    args = opts(argv)

    scanProcessModules()

    is_wow64 = (platform.architecture()[0] == '32bit' and 'ProgramFiles(x86)' in os.environ)

    try:
        if '\\system32\\' in args.path.lower() and is_wow64:
            verbose('Redirecting input path from System32 to SysNative as we run from 32bit Python.')
            args.path = args.path.lower().replace('\\system32\\', '\\SysNative\\')

        if os.path.isdir(args.path):
            processDir(args.path)

        else:
            if not os.path.isfile(args.path):
                print(f'[!] Input file does not exist! Path: {args.path}')
                sys.exit(1)

            processFile(args.path)

        if len(results) > 0:

            idx = headers.index(args.column)
            results.sort(key = lambda x: x[idx], reverse = not args.ascending)
            headers[idx] = '▼ ' + headers[idx] if not args.ascending else '▲ ' + headers[idx]

            if args.first > 0:
                for i in range(len(results) - args.first):
                    results.pop()

            table = tabulate.tabulate(results, headers=['#',] + headers, showindex='always', tablefmt='pretty')

            print(table)

            if args.first > 0:
                print(f'\n[+] Found {len(results)} files meeting all the criterias (but shown only first {args.first} ones).\n')
            else:
                print(f'\n[+] Found {len(results)} files meeting all the criterias.\n')

        else:
            print(f'[-] Did not find modules meeting specified criterias. Processed {filesProcessed} files.')

    except KeyboardInterrupt:
        print('[-] User interrupted the scan.')

if __name__ == '__main__':
    main(sys.argv)
