# Copyright (c) 2022 EEMBC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# #!/usr/bin/env python3

import sys
import re
import pprint

class CStackFlattener:
    def __init__(self):
        self.call_tree = { "_root": {} }

    def xadd(self, stack, tree_node):
        if len(stack) == 0:
            return
        for entry in stack:
            name = entry[1]
            if name in tree_node:
                pass
            else:
                tree_node[name] = {}
            tree_node = tree_node[name]

    def add(self, stack):
        self.xadd(list(reversed(stack)), self.call_tree['_root'])

class CTraceProcessor:
    def __init__(self):
        self.current_stack = []
        self.processor = CStackFlattener()
        self.lines = 0

    def process_file(self, file_name):
        with open(file_name, 'r') as file:
            for line in file:
                self.process_line(line.strip())
        # Since we assemble after parse, make sure we are done!
        self.processor.add(self.current_stack)

    def process_line(self, text):
        if not text:
            return

        # After this point we only care about backtraces
        if text[0] != '#':
            return

        # Assemble the call stack for each `rbreak` expression
        parts = re.split(r'[#\s\(\),]+', text)

        if len(parts) < 3:
            return
        depth = int(parts[1])
        if depth == 0:
            fname = parts[2]
        else:
            fname = parts[4]
        argv = {}
        for part in parts:
            arg = re.split('=', part)
            if len(arg) == 2:
                argv[arg[0]] = arg[1]
        if depth == 0 and len(self.current_stack) > 0:
            self.processor.add(self.current_stack)
            self.current_stack = []

        # Since we process-then-assemble, check for tail condition (above)
        self.current_stack.append([depth, fname])
        self.lines += 1

def main ():
    trace_processor = CTraceProcessor()
    trace_processor.process_file(sys.argv[1])
    pp = pprint.PrettyPrinter(compact=True, width=40, indent=1)
    pp.pprint(trace_processor.processor.call_tree)

if __name__ == '__main__':
    main()
