from curses import wrapper
import time
import sys
import json
from copy import copy


class cTermDisplay():
    def __init__(self, runtimeData, data):
        self.runtimeData = runtimeData
        self.data = data


        while True:
            wrapper(self.curseswrapper)

    def curseswrapper(self, stdscr):

        # Clear screen
        stdscr.clear()
        # y offset
        y = 0
        #####################################
        #               Info                #
        #####################################
        stdscr.addstr(y, 0, "Program Information")
        y += 1
        stdscr.addstr(y, 0, "Program: \""+" ".join(self.data['metadata']['program'])+"\"")
        y += 1
        stdscr.addstr(y, 0, "Syscalls Checked: " + " ".join(self.data['metadata']['syscalls']) )
        y += 1
        rTime = '%(time).7f' % {'time': self.data['metadata']['end_t'] - self.data['metadata']['start_t']}
        stdscr.addstr(y, 0, "Run time: " + rTime + " seconds")
        y += 1

        #####################################
        #               ISSUES              #
        #####################################

        if len(self.data['perms']['sudo_fail']) > 0:
            for fail in self.data['perms']['sudo_fail']:
                t = '+%(time).7f' % {'time': fail - self.data['metadata']['start_t']}
                stdscr.addstr(y, 0, "Sudo Failed at: " + t)
                y += 1

        y += 3

        #####################################
        #               Open()              #
        #####################################
        if "write" in self.data['metadata']['syscalls']:
            stored_y = copy(y)
            y += 2
            stdscr.refresh()
            o_data = [["Open@","Time(s)", "Mode", "File"]]

            for element in self.runtimeData["c_filepointers"]:
                mtime = '%(time).5f' % {'time' :element["c_time"]- element["o_time"]}
                openTime = '+%(time).5f' % {'time': element["o_time"] - self.data['metadata']['start_t']}
                o_data.append([openTime,mtime, element['desc'], element['file']])

            longestRow = []
            for col in zip(*o_data):
                longestRow.append(max((map(len, col))))

            test = zip(o_data[0], longestRow)

            hdr = "  ".join((' ' + val.rjust(Max) + ' |' for val, Max in zip(o_data[0], longestRow)))[:-1]

            stdscr.addstr(y, 0, hdr)
            y += 1
            stdscr.addstr(y, 0, '=' * (len(hdr)-1))
            y += 1
            # delete the header and output the remaining table
            del o_data[0]
            # finish table

            for row in o_data:
                tbl = "  ".join((' ' + val.rjust(Max) + ' |' for val, Max in zip(row, longestRow)))[:-1]
                stdscr.addstr(y, 0, tbl)
                y += 1

            y += 4
            # Print title with correct spacing
            title_text = " File Access "
            pad_size = len(hdr) / 2 - len(title_text) / 2 - 1
            title_pad = '=' * pad_size
            title = title_pad + title_text + title_pad
            stdscr.addstr(stored_y, 0, title)
        #####################################
        #               Write()             #
        #####################################
        if ("write" or 'read') in self.data['metadata']['syscalls']:

            #disaply write infomration

            stored_y = copy(y)
            y += 2


            o_data = [["Time", "Mode", "Bytes Written", "File"]]

            for element in self.data['file']['write']:

                writeTime = '+%(time).5f' % {'time': element["w_time"] - self.data['metadata']['start_t']}
                o_data.append([writeTime, "write", element['count'], element['filename']])

            for element in self.data['file']['read']:

                readTime = '+%(time).5f' % {'time': element["r_time"] - self.data['metadata']['start_t']}
                o_data.append([readTime, "read", element['count'], element['filename']])

            longestRow = []
            for col in zip(*o_data):
                longestRow.append(max((map(len, col))))

            test = zip(o_data[0], longestRow)

            hdr = "  ".join((' ' + val.rjust(Max) + ' |' for val, Max in zip(o_data[0], longestRow)))[:-1]

            stdscr.addstr(y, 0, hdr)
            y += 1
            stdscr.addstr(y, 0, '=' * (len(hdr)-1))
            y += 1
            # delete the header and output the remaining table
            del o_data[0]
            # finish table
            for row in o_data:
                tbl = "  ".join((' ' + val.rjust(Max) + ' |' for val, Max in zip(row, longestRow)))[:-1]
                stdscr.addstr(y, 0, tbl)
                y += 1

            title_text = " File I/O "
            pad_size = len(hdr) / 2 - len(title_text) / 2
            title_pad = '=' * pad_size
            title = title_pad + title_text + title_pad
            stdscr.addstr(stored_y, 0, title)
            y += 1

        stdscr.refresh()
        time.sleep(1)



if __name__ == '__main__':


    try:

        if sys.argv[1] == "-h":
            print "Usage: python termDisaply.py runtime.json meta.json"
            exit(0)

        with open(sys.argv[1], 'r') as runtime:
            json_runtime = json.load(runtime)

        with open(sys.argv[2], 'r') as meta:
            json_meta = json.load(meta)

        cTermDisplay(json_runtime, json_meta)

    except IndexError:
        print "Incorrect Usage: Usage: python termDisaply.py runtime.json meta.json"

