
import subprocess
import os
import re
import argparse
import time
import json

from termDisplay import cTermDisplay

ALL_SUPPORTED_ARGS = ["open", "write", "close"]

#TODO Compile all regex
#TODO - Speed analysis, possilby create True/Flase values for syscalls to spped up line processing

class visualStrace():
    def __init__(self, syscalls, program, verbose, display=False, graph=False, ):
        self.program = program
        self.syscalls = syscalls
        self.verbose = verbose
        self.display = display
        #self.termDisplay = vstraceTerminalDisplay()
        self.timeZero = time.time()
        self.graphname = graph
        self.runtimeData = {
            "start_t":        self.timeZero,
            "o_filepointers": {}, #contains current open file points from the program and what file they point to
            "c_filepointers": [], #contains previous closed file points open and close times
            "write_data":     {}, #contans information about file writes
            "read_data":       {},
            "sudo_filepointer": [],
        }

        #Create queue to share data between main thread and display thread

        print"Starting at: ", time.asctime(time.localtime(self.timeZero))

        #Holds data to be displayed
        self.data = {
                        'metadata':
                            {'start_t':     self.timeZero,
                             'end_t':       0,
                             'program':     self.program,
                             'syscalls':    self.syscalls,
                             'graphname':   self.graphname,
                             'write_t':     0
                             },
                        'file':
                        {
                            'open': [],
                            'write':[],
                            'read': []
                        },
                        'perms':
                        {
                            'sudo': [],
                            'sudo_fail': []
                        }

                    }

    #Runs strace on the program
    def run(self):
        self.cmd = "strace " + " ".join(self.program)

        FNULL = open(os.devnull, 'w')                             #subprocess DEVNULL is implemented in python 3.0
        proc = subprocess.Popen(self.cmd, shell=True, stdout=FNULL, stderr=subprocess.PIPE)

        line_buffer = ""
        #process strace lines
        for line in iter(proc.stderr.readline, ''):
            if re.match(r'\w+\(.*?\)\s+=\s+-?[0-9]+', line_buffer):
                line = line_buffer
                self.parse(line)
                line_buffer = ""
            else:
                line_buffer += line
                continue

        #display graph and information in browser
        if self.graphname:
            self.graph()

        self.data['metadata']['end_t'] = time.time()



    #add the line information to the data base and prints real time infomraiton to the console
    def parse(self, line):
        if re.match('^open\(', line) and "open" in self.syscalls:
            return self.parseOpen(line)
        elif re.match('^close\(', line) and "open" in self.syscalls:
            return self.parseClose(line)
        elif re.match('^write\(', line) and "write" in self.syscalls:
            return self.parseWrite(line)
        elif re.match('^read\(', line) and "read" in self.syscalls:
            return self.parseRead(line)


    #TODO the following functions have reused code and can almost cetainly be refactored.
    def parseRead(self, line):
        fp = re.findall(r'(?:read\()([0-9]+)', line)[0]
        buf = re.findall(r'(?:read\([0-9]+\s?,\s?\")(.*)(?:\")', line)[0]
        count = re.findall(r'([0-9]+)(?:\))', line)[0]
        rtn = re.findall(r'(?:\= )(-?[0-9]+)', line)[0]

        try:
            filename = self.runtimeData['o_filepointers'][fp]['file']

        except KeyError:
            filename = "Non open file"

        comment = {}

        if rtn > count:
            comment['msg'] = "ERROR: Tried to read " + count + " bytes but only read " + rtn


        elif rtn == -1:
            comment['msg'] = "Could not read from " + filename

        else:
            comment['msg'] = "Read " + count + " bytes from " + filename

        self.data['file']['read'].append({
            "r_time": time.time(),
            "filename": filename,
            "buffer": buf,
            "count": count,
            "comment": comment,
        })

        if rtn != "-1":
            self.runtimeData["read_data"][fp] = {'file': filename, 'r_time': time.time(), 'desc': count}

    def parseWrite(self, line):

        fp = re.findall(r'(?:write\()([0-9]+)', line)[0]

        if re.match(r'write\([0-9],\s\"sudo",', line):
            self.data['perms']['sudo_fail'].append(time.time())
            self.runtimeData["sudo_filepointer"].append(fp)
            self.parseClose("close("+fp+")")
            return

        elif fp in self.runtimeData["sudo_filepointer"]:
            return

        elif fp not in self.runtimeData['o_filepointers']:
            return
        rtn = re.findall(r'(?:\= )(-?[0-9]+)', line)[0]
        count = re.findall(r'([0-9]+)(?:\))', line)[0]

        buf = re.findall(r'(?:write\([0-9]+,\s?\")(.*?)(?:\", )', line)[0]

        try:
            filename = self.runtimeData['o_filepointers'][fp]['file']

        except KeyError:
            filename = "Non open file"

        comment = {}

        if rtn > count:
            comment['msg'] = "ERROR: Tried to write " + count + " bytes but only wrote " + rtn


        elif rtn == -1:
            comment['msg'] = "Could not write to " + filename

        else:
            comment['msg'] = "Wrote "+count +" bytes to " + filename

        self.data['file']['write'].append({
            "w_time": time.time(),
            "filename": filename,
            "buffer": buf,
            "count": count,
            "comment": comment,
                    })

        if rtn != "-1":
            self.runtimeData["write_data"][fp] = {'file': filename, 'w_time':time.time(), 'desc': count}


    def parseClose(self, line):
        fp = re.findall('[0-9]+', line)[0]
        #try handles when a close is called for a fp on a syscall that is not being monitored
        try:
            #add close time and the filepointer used
            self.runtimeData["o_filepointers"][fp]['c_time'] = time.time()
            self.runtimeData["o_filepointers"][fp]['fp'] = fp
            #pop complete entry to all file pointers data
            self.runtimeData["c_filepointers"].append(self.runtimeData["o_filepointers"].pop(fp))

        except KeyError:
            pass


    def parseOpen(self, line):
        file = re.findall( '"([A-Za-z0-9_\./\\-]*)"', line)[0]
        rline = re.sub('"([A-Za-z0-9_\./\\-]*)",', '',line)             #remove file name
        args = re.findall('O_\w+', rline)                               #capture ofile access type
        mode = re.findall('[0-6]{4}', rline)                            #check permissions on file/folder creation
        #lline = re.findall('[\w]+', rline)
        rtn = re.findall(r'(?:\= )(-?[0-9]+)', rline)[0]                #extract return number to process permission and open files


        #process mode
        if len(mode) > 0:
            if mode[0][0] is not "0":
                print "Mode: "+ mode[0]+" Suid bit set, potentially dangerous!"


        #depencecy check
        # Could pass "args" tp set for quicker comprehension O(n) -> O(1)
        if len(args) == 2 and ("O_RDONLY" in args and "O_CLOEXEC" in args):
            comment = "Performing dependency check on \"" + file +"\"\n"
            desc = "Depen Chk. / read only"

        ##TODO replace with a function to create these strings

        elif len(args) == 1 and "O_RDONLY" in args:
            comment = "Reading from " +file + " (fopen flag 'r')\n"
            desc = "read only"

        elif len(args) == 1 and "O_RDWR" in args:
            comment = "Reading and Writing to " +file + " (fopen flag 'r+')\n"
            desc = "read write"

        elif len(args) == 3 and ("O_WRONLY" in args and "O_CREAT" in args and "O_TRUNC" in args ):
            comment = "Writing into truncated or Created file: "+ file + " with permissions: "+mode[0]+" (fopen flag 'w')\n"
            desc = "write only (trucanted or create)"

        elif len(args) == 3 and ("O_RDWR" in args and "O_CREAT" in args and "O_TRUNC" in args ):
            comment = "Reading from and Writing into new or Creating file: " + file + " (fopen flag 'w+')\n"
            desc = "read write (trucanted or create)"

        elif len(args) == 3 and ("O_WRONLY" in args and "O_CREAT" in args and "O_APPEND" in args ):
            comment = "Appending to " + file + " (fopen flag 'a')\n"
            desc = "write (append or create)"

        elif len(args) == 3 and ("O_RDWR" in args and "O_CREAT" in args and "O_APPEND" in args ):
            comment = "Reading from and Appending to " + file + " (fopen flag 'a+')\n"
            desc = "read write (append or create)"

        elif len(args) == 4 and ("O_RDONLY" in args and "O_NONBLOCK" in args and "O_DIRECTORY" in args and "O_CLOEXEC" in args ):
            comment = "Getting a directorry listing of: " + file
            desc = "Dir listing"

        else:
            comment = "Didn't recognise this combo! File: " + file + " O_Mode: " + ''.join(args)
            desc = "unknown"

        self.data['file']['open'].append({
            "o_time": time.time(),
            "filename": file,
            "permissions": args,
            "comment" : comment,
            "desc": desc,
        })

        if rtn != "-1":
            self.runtimeData["o_filepointers"][rtn] = {'file': file, 'o_time':time.time(), 'desc': desc}

        if self.verbose:
            self.printData(comment)
        return comment

    def termAnalyse(self):
        cTermDisplay(self.runtimeData, self.data)

    def printData(self, line):
        print "[VSTRACE] "+ line


    def saveFiles(self):
        with open('runtime-data.json', 'w') as runtime:
            json.dump(self.runtimeData, runtime)

        self.data['metadata']['write_t'] = time.time()
        with open('meta-data.json', 'w') as meta:
            json.dump(self.data, meta)

if __name__ == '__main__':


    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--syscalls", help="Syscalls to monitor , currently supported syscalls: Open, Write, Close or 'all' for all supported",                         nargs='+', required = True)
    parser.add_argument("-p", "--program",  help="The program and arguments you wish to run",   nargs='+', required = True)
    parser.add_argument("-v", "--verbose",  help="Display realtime verbose messaging",          action = 'store_true')
    parser.add_argument("-d", "--display",  help="Display info to stdout",                      action='store_true')
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-ng", "--no-graph", help="Do not display a graph",                      action="store_true")
    group.add_argument("-g", "--graph-name")


    args, unknown = parser.parse_known_args()

    if not unknown:
        program = args.program
    else:
        program = args.program + unknown

    if args.syscalls[0] == "all":
        args.syscalls = ALL_SUPPORTED_ARGS

    print "Stracing the following syscalls: " + str(args.syscalls)
    print "Against the running of: " + str(program)


    if args.display:
        print args.display
        print "Dispalying data to stdout"
    if args.verbose:
        print "Verbosit enabled!\nDisplaying live syscall information..."


    if args.no_graph:

        vstrace = visualStrace(args.syscalls, program, args.verbose, args.display)
    else:
        vstrace = visualStrace(args.syscalls, program, args.verbose, args.display, args.graph_name)

    try:
        vstrace.run()
        vstrace.saveFiles()
        vstrace.termAnalyse()

    except KeyboardInterrupt:
        vstrace.saveFiles()
        print "Stopping"
