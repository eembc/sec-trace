#!/usr/bin/env python3
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

# Note: the backtrace info comes from FRIDA Accuracy.FUZZY, so above a certain
# level it might be bogus. There is a regex at the end to purge everything
# above my_debug+ and main+, but be aware of this!

import sys
import re
import pprint
import argparse

# enum HandShakeType {#
#     hello_request           0,#
#     client_hello            1,#
#     server_hello            2,#
#     hello_verify_request    3,    /* DTLS addition */#
#     session_ticket          4,#
#     end_of_early_data       5,#
#     hello_retry_request     6,#
#     encrypted_extensions    8,#
#     certificate            11,#
#     server_key_exchange    12,#
#     certificate_request    13,#
#     server_hello_done      14,#
#     certificate_verify     15,#
#     client_key_exchange    16,#
#     finished               20,#
#     certificate_status     22,#
#     key_update             24,#
#     change_cipher_hs       55,    /* simulate unique handshake type for sanity#
#                                       checks.  record layer change_cipher#
#                                       conflicts with handshake finished */#
#     message_hash         = 254,    /* synthetic message type for TLS v1.3 */#
#     no_shake             = 255     /* used to initialize the DtlsMsg record */#
# };#
handshake_states = [-1, 0, 2, 8, 13, 11, 15, 20]

wolf_state_names = {
     0: 'hello_request',
     1: 'client_hello',
     2: 'server_hello',
     3: 'hello_verify_request',
     4: 'session_ticket',
     5: 'end_of_early_data',
     6: 'hello_retry_request',
     8: 'encrypted_extensions',
    11: 'certificate',
    12: 'server_key_exchange',
    13: 'certificate_request',
    14: 'server_hello_done',
    15: 'certificate_verify',
    16: 'client_key_exchange',
    20: 'finished',
    22: 'certificate_status',
    24: 'key_update',
    55: 'change_cipher_hs',
    254: 'message_hash',
    255: 'no_shake'
}

class CAliasTable:
    """ Provides context to alias mapping """
    
    def __init__ (self):
        self.current_alias = 0
        # This table is constantly refreshed by add/remove
        self.context_alias_cache = {}
        # This aliases in this table remain
        self.alias_context_history = {}

    def base_add (self, key):
        self.context_alias_cache[key] = self.current_alias
        self.alias_context_history[self.current_alias] = key
        self.current_alias = self.current_alias + 1

    def add (self, ctx):
        if ctx in self.context_alias_cache:
            raise Exception("Context already in use: %s" % ctx)
        self.base_add(ctx)

    def remove (self, ctx):
        if ctx in self.context_alias_cache:
            del self.context_alias_cache[ctx]
        else:
            print("Warning: freeing context without clone/init: %s" % ctx)

    def clone (self, src, dst):
        #print("Cloning existing context %s into %s" % (src, dst))
        self.base_add(dst)

    def get_alias (self, context):
        if context in self.context_alias_cache:
            return self.context_alias_cache[context]
        return None

    def get_context (self, alias):
        if alias in self.alias_context_history:
            return self.alias_context_history[alias]
        return None

# TODO: Need a "validate payload" function

class CParserLibrary:
    def __init__(self, trace_processor):
        self.trace_processor = trace_processor
        self.block_sha = False
        self.seen_missing = {}
        self.seen_hooked = {}

    def parse(self, frame):
        stack_top = frame[0]
        function_name = stack_top[1]

        # Attempt to find the function as a self attribute
        function = None
        try:
            function = getattr(self, function_name)
            if function_name in self.seen_hooked:
                pass
            else:
                self.seen_hooked[function_name] = 1
                print("Hooked function '%s'" % function_name)
            #print(function_name)
        except AttributeError as e:
            if function_name in self.seen_missing:
                pass
            else:
                self.seen_missing[function_name] = 1
                print("No hook for '%s'" % function_name)
        except Exception as e:
            print("Some other error", function_name, e)
    
        if function:
            function(frame)

    def is_self_nested (self, stack):
        #us = stack[0][1]
        rest = stack[1:]
        nest = None
        for check in rest:
            name = check[1]
            try:
                getattr(self, name)
                #print("Us (%s) has nested (%s)" % (us, name))
                nest = name
                # Don't break, we're finding the HIGHEST level name
            except:
                pass
            #if re.match(r'^DoTls13', name):
            #    if name == 'DoTls13HandShakeMsg' or name == 'DoTls13HandShakeMsgType':
            #        pass
            #    else:
            #        nest = name
        return nest

    def wc_AesGcmEncrypt(self, stack):
        ctx = stack[0][2]['aes']
        n = int(stack[0][2]['sz'])
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(stack, alias, n, "gcm/E")

    def wc_AesGcmDecrypt(self, stack):
        ctx = stack[0][2]['aes']
        n = int(stack[0][2]['sz'])
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(stack, alias, n, "gcm/D")

    def wc_AesCcmEncrypt(self, stack):
        ctx = stack[0][2]['aes']
        n = int(stack[0][2]['inSz'])
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(stack, alias, n, "ccm/E")

    def wc_AesCcmDecrypt(self, stack):
        ctx = stack[0][2]['aes']
        n = int(stack[0][2]['inSz'])
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(stack, alias, n, "ccm/D")

    def wc_AesInit(self, stack):
        ctx = stack[0][2]['aes']
        self.trace_processor.aliases.add(ctx)

    def wc_AesFree(self, stack):
        ctx = stack[0][2]['aes']
        self.trace_processor.aliases.remove(ctx)

    def wc_ed25519_init_ex(self, stack):
        ctx = stack[0][2]['key']
        self.trace_processor.aliases.add(ctx)

    def wc_ed25519_free(self, stack):
        ctx = stack[0][2]['key']
        self.trace_processor.aliases.remove(ctx)

    def wc_ed25519_sign_msg (self, stack):
        ctx = stack[0][2]['key']
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(stack, alias, 1, 'ed25519/s')

    def wc_ed25519_verify_msg (self, stack):
        ctx = stack[0][2]['key']
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(stack, alias, 1, 'ed25519/v')

    def wc_curve25519_init_ex(self, stack):
        ctx = stack[0][2]['key']
        self.trace_processor.aliases.add(ctx)

    def wc_curve25519_free(self, stack):
        ctx = stack[0][2]['key']
        self.trace_processor.aliases.remove(ctx)

    def wc_curve25519_shared_secret_ex(self, stack):
        ctx = stack[0][2]['private_key']
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(stack, alias, 1, 'x25519')

    def wc_ecc_init_ex(self, stack):
        ctx = stack[0][2]['key']
        self.trace_processor.aliases.add(ctx)

    def wc_ecc_free(self, stack):
        ctx = stack[0][2]['key']
        self.trace_processor.aliases.remove(ctx)

    def wc_ecc_shared_secret(self, stack):
        ctx = stack[0][2]['private_key']
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(stack, alias, 1, 'ecdh')

    def wc_ecc_sign_hash (self, stack):
        ctx = stack[0][2]['key']
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(stack, alias, 1, 'ecdsa/s')

    def wc_ecc_verify_hash (self, stack):
        ctx = stack[0][2]['key']
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(stack, alias, 1, 'ecdsa/v')

    def wc_InitSha256_ex(self, stack):
        ctx = stack[0][2]['sha256']
        self.trace_processor.aliases.add(ctx)
   
    def wc_InitSha384_ex(self, stack):
        ctx = stack[0][2]['sha384']
        self.trace_processor.aliases.add(ctx)

    def wc_InitSha512_ex(self, stack):
        ctx = stack[0][2]['sha512']
        self.trace_processor.aliases.add(ctx)

    def wc_Sha256Free(self, stack):
        ctx = stack[0][2]['sha256']
        self.trace_processor.aliases.remove(ctx)
   
    def wc_Sha384Free(self, stack):
        ctx = stack[0][2]['sha384']
        self.trace_processor.aliases.remove(ctx)

    def wc_Sha512Free(self, stack):
        ctx = stack[0][2]['sha512']
        self.trace_processor.aliases.remove(ctx)

    def wc_Sha256Update(self, stack):
        ctx = stack[0][2]['sha256']
        len = int(stack[0][2]['len'])
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(stack, alias, len, "sha256")
   
    def wc_Sha384Update(self, stack):
        ctx = stack[0][2]['sha384']
        len = int(stack[0][2]['len'])
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(stack, alias, len, "sha384")

    def wc_Sha512Update(self, stack):
        ctx = stack[0][2]['sha512']
        len = int(stack[0][2]['len'])
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(stack, alias, len, "sha512")

    # CC20P1305 doesn't have an init/free, so we must infer/bypass checks
    def ChaCha20Poly1305_Encrypt(self, stack):
        ctx = stack[0][2]['ssl']
        self.trace_processor.aliases.add(ctx)
        alias = self.trace_processor.aliases.get_alias(ctx)
        n = int(stack[0][2]['sz'])
        self.trace_processor.post_event(stack, alias, n, "cc20p1305/E")
        self.trace_processor.aliases.remove(ctx)

    # CC20P1305 doesn't have an init/free, so we must infer/bypass checks
    def ChaCha20Poly1305_Decrypt(self, stack):
        ctx = stack[0][2]['ssl']
        self.trace_processor.aliases.add(ctx)
        alias = self.trace_processor.aliases.get_alias(ctx)
        n = int(stack[0][2]['sz'])
        self.trace_processor.post_event(stack, alias, n, "cc20p1305/D")
        self.trace_processor.aliases.remove(ctx)

    # Other important high-level functions dummy attributes for nesting

    def EccSign():
        pass
    
    def DeriveMasterSecret():
        pass

    def HashOutput():
        pass

    def BuildTls13HandshakeHmac():
        pass

    def CreateECCEncodedSig():
        pass

    def HashForSignature():
        pass

    def HashRaw():
        pass

    def Hash_DRBG_Generate():
        pass

    def Hash_DRBG_Instantiate():
        pass

    def DhGenKeyPair():
        pass

    def EccMakeKey():
        pass

    def Tls13DeriveKey():
        pass

    def Tls13_HKDF_Expand():
        pass

    def Tls13_HKDF_Extract():
        pass
    
    def DeriveHandshakeSecret():
        pass

    def ConfirmSignature():
        pass

    def EccVerify():
        pass

    def ed25519_hash():
        pass

    def wc_InitRng_ex():
        pass

    def DeriveEarlySecret():
        pass

class CTraceProcessor:
    def __init__(self):
        self.aliases = CAliasTable()
        self.parsers = CParserLibrary(self)
        self.current_state = -1
        self.scoreboard = {}
        self.last_depth = -1
        self.current_stack = []

    def process_file(self, file_name):
        with open(file_name, 'r') as file:
            for line in file:
                self.process_line(line.strip())
        # Since we assemble after parse, make sure we are done!
        if len(self.current_stack) > 0:
            self.parsers.parse(self.current_stack)

    def process_line(self, text):
        if not text:
            return

        # This is the "print ssl->state" command in the GDB script.
        if text[0] == '$':
            # If the state is changing, purge the current stack,
            # otherwise it will be charged to the wrong state.
            if len(self.current_stack) > 0:
                self.parsers.parse(self.current_stack)
                self.current_stack = []
            parts = re.split(r'[\s=]+', text)
            self.current_state = int(parts[1])
            return

        # After this point we only care about backtraces
        if text[0] != '#':
            return

        # Remove really long quotes that screw up the splitter
        # Fortunately GDB hex-escapes embedded quotes!
        #text = re.sub(r'".*?"', '', text)

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
            self.parsers.parse(self.current_stack)
            #print(self.current_stack)
            self.current_stack = []

        # Since we process-then-assemble, check for tail condition (above)
        self.current_stack.append([ depth, fname, argv])

    def post_event (self, stack, alias, n, tag):
        """ Add an event to the scoreboard, incrementing its 'n' value. """

        # Only post events to states we care about (see handshake_states)
        if self.current_state in handshake_states:
            pass
        else:
            print("Ignoring handshake state %d" % self.current_state)
            return
            
        nest = self.parsers.is_self_nested(stack)
        if alias is None:
            raise Exception("Alias is none")
        if alias not in self.scoreboard:
            self.scoreboard[alias] = {}
        slot = self.scoreboard[alias]

        # Slot needs to have depth
        left = 7
        max = 45
        right = max - left - 3
        if nest is not None:
            shortnest = nest
            if len(shortnest) > max:
                front = shortnest[0:left]
                back = shortnest[-right:]
                shortnest = front + '...' + back
            name_nest = "%s (in %s)" % (tag, shortnest)
        else:
            name_nest = tag 

        if name_nest in slot:
            pass
        else:
            slot[name_nest] = {}

        if self.current_state in slot[name_nest]:
            pass
        else:
            slot[name_nest][self.current_state] = {
                'bytes' : 0,
                'bt': []
            }
        slot[name_nest][self.current_state]['bytes'] += n
        slot[name_nest][self.current_state]['bt'].append(stack)

def main ():
    detail = None

    if len(sys.argv) < 2:
        raise Exception("Please specify the input file to process.")

    if len(sys.argv) == 3:
        detail = sys.argv[2]

    trace_processor = CTraceProcessor()
    trace_processor.process_file(sys.argv[1])

    print()
    print("Results Table")
    print("-------------")
    print()
    print("NOTE: Only these mbedTLS state codes are counted:")
    for state in handshake_states:
        if state < 0:
            print(" . % 2s %s" % (state, "PRE-HANDSHAKE"))
        else:
            print(" . % 2s %s" % (state, wolf_state_names[state]))
    print()

    print("% 5s,  %- 55s,% 15s:," % ("alias", "type", "context"), end="")
    for i in handshake_states:
        print("% 6d," % i, end="")
    print("")
    #pprint.pprint(trace_processor.scoreboard, depth=3)
    # If there are skips in the alias #s, it means there were no events on it!
    for alias in sorted(trace_processor.scoreboard):
        for name_nest in trace_processor.scoreboard[alias]:
            print("%05d,  %- 55s,% 16s," % (
                int(alias),
                name_nest,
                trace_processor.aliases.get_context(alias)),
                end="")
            for i in handshake_states:
                if i in trace_processor.scoreboard[alias][name_nest]:
                    print("% 6s," % str(
                        trace_processor.scoreboard[alias][name_nest][i]['bytes']), end="")
                else:
                    print("% 6s," % " ", end="")
            print()
            if detail and int(alias) == int(detail):
                for i in handshake_states:
                    if i in trace_processor.scoreboard[alias][name_nest]:
                        for call in trace_processor.scoreboard[alias][name_nest][i]['bt']:
                            for subcall in call:
                                if subcall[0] == 0:
                                    print('\t\t%03d # %02d - %s' % (i, subcall[0], subcall[1]), subcall[2:])
                                else:
                                    print('\t\t%03d # %02d - %s' % (i, subcall[0], subcall[1]))
                            print()

    for ctx in trace_processor.aliases.context_alias_cache:
        print("Warning: the context '%s' used by alias '%s' was not freed:" % (ctx, trace_processor.aliases.context_alias_cache[ctx]))

if __name__ == '__main__':
    main()
