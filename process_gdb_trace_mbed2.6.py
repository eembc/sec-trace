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

# MbedTLS Handshake V2.x - states we see in our traces, in temporal order
handshake_states = range(-1, 17) #[-1, 0, 1, 2, 3, 4, 5, 14, 6, 7, 8, 9, 11, 12, 13, 15, 16]
# Take from `ssl.h`
mbedtls2_state_names = [
    'MBEDTLS_SSL_HELLO_REQUEST',
    'MBEDTLS_SSL_CLIENT_HELLO',
    'MBEDTLS_SSL_SERVER_HELLO',
    'MBEDTLS_SSL_SERVER_CERTIFICATE',
    'MBEDTLS_SSL_SERVER_KEY_EXCHANGE',
    'MBEDTLS_SSL_CERTIFICATE_REQUEST',
    'MBEDTLS_SSL_SERVER_HELLO_DONE',
    'MBEDTLS_SSL_CLIENT_CERTIFICATE',
    'MBEDTLS_SSL_CLIENT_KEY_EXCHANGE',
    'MBEDTLS_SSL_CERTIFICATE_VERIFY',
    'MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC',
    'MBEDTLS_SSL_CLIENT_FINISHED',
    'MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC',
    'MBEDTLS_SSL_SERVER_FINISHED',
    'MBEDTLS_SSL_FLUSH_BUFFERS',
    'MBEDTLS_SSL_HANDSHAKE_WRAPUP',
    'MBEDTLS_SSL_HANDSHAKE_OVER',
    'MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET',
    'MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT',
    '?1',
    '?2',
    '?3',
    '?4',
    '?5',
    '?6',
    '?7',
    '?8',
]

import sys
import re
import pprint
import argparse

class CAliasTable:
    """ Provides context to alias mapping """
    
    def __init__ (self):
        self.current_alias = 0
        self.context_to_alias = {}
        self.alias_to_context = {}
        self.alias_description = {}

    def base_add (self, key):
        self.context_to_alias[key] = self.current_alias
        self.alias_to_context[self.current_alias] = key
        self.alias_description[self.current_alias] = "unknown"
        self.current_alias = self.current_alias + 1

    def add (self, pointer_string):
        if pointer_string in self.context_to_alias:
            raise Exception("Context already in use, cannot alias: %s" % pointer_string)
        self.base_add(pointer_string)

    def remove (self, pointer_string):
        if pointer_string in self.context_to_alias:
            del self.context_to_alias[pointer_string]
        else:
            print("Warning: freeing context without clone/init: %s" % pointer_string)

    def clone (self, source_pointer, dest_pointer):
        #if dest_pointer in self.context_to_alias:
        #    print("Warning: cloning existing context: %s into %s" % (source_pointer, dest_pointer))
        #print("Cloning existing context: %s into %s" % (source_pointer, dest_pointer))
        self.base_add(dest_pointer)

    def get_alias (self, context):
        if context in self.context_to_alias:
            return self.context_to_alias[context]
        return None

    def get_context (self, alias):
        if alias in self.alias_to_context:
            return self.alias_to_context[alias]
        return None

    def description (self, alias, description=None):
        if description:
            self.alias_description[alias] = description
        elif alias in self.alias_description:
            return self.alias_description[alias]
        return None

# TODO: Need a "validate payload" function

class CParserLibrary:
    def __init__(self, trace_processor):
        self.trace_processor = trace_processor
        self.block_sha = False
        self.seen_missing = {}

    def parse(self, frame):
        stack_top = frame[0]
        function_name = stack_top[1]
        try:
            function = getattr(self, function_name)
            function(frame)
            #print(function_name)
        except AttributeError as e:
            if function_name in self.seen_missing:
                pass
            else:
                self.seen_missing[function_name] = 1
                print("No hook for '%s'" % function_name)
        except Exception as e:
            print("Some other error", function_name, e)

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
        return nest

    # AES ECB Functions

    def mbedtls_aes_init(self, stack):
        ctx = stack[0][2]['ctx']
        self.trace_processor.aliases.add(ctx)

    def mbedtls_aes_free(self, stack):
        ctx = stack[0][2]['ctx']
        self.trace_processor.aliases.remove(ctx)
    
    def mbedtls_aes_crypt_ecb(self, stack):
        ctx = stack[0][2]['ctx']
        mode = int(stack[0][2]['mode'])
        alias = self.trace_processor.aliases.get_alias(ctx)
        if mode == 1:
            mode = 'e'
        else:
            mode = 'd'
        self.trace_processor.post_event(stack, alias, 16, ("ecb/%s" % mode))

    # AES/CCM functions

    def mbedtls_ccm_init(self, stack):
        ctx = stack[0][2]['ctx']
        self.trace_processor.aliases.add(ctx)

    def mbedtls_ccm_free(self, stack):
        ctx = stack[0][2]['ctx']
        self.trace_processor.aliases.remove(ctx)

    def mbedtls_ccm_star_encrypt_and_tag(self, stack):
        ctx = stack[0][2]['ctx']
        length = int(stack[0][2]['length'])
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(stack, alias, length, "ccm/E")

    def mbedtls_ccm_star_auth_decrypt(self, stack):
        ctx = stack[0][2]['ctx']
        length = int(stack[0][2]['length'])
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(stack, alias, length, "ccm/D")

    # AES/GCM functions

    def mbedtls_gcm_init(self, stack):
        ctx = stack[0][2]['ctx']
        self.trace_processor.aliases.add(ctx)

    def mbedtls_gcm_free(self, stack):
        ctx = stack[0][2]['ctx']
        self.trace_processor.aliases.remove(ctx)

    def mbedtls_gcm_crypt_and_tag(self, stack):
        ctx = stack[0][2]['ctx']
        mode = int(stack[0][2]['mode'])
        n = int(stack[0][2]['length'])
        alias = self.trace_processor.aliases.get_alias(ctx)
        if mode == 1:
            mode = 'e'
        else:
            mode = 'd'
        self.trace_processor.post_event(stack, alias, n, ("gcm/%s" % mode))

    def mbedtls_ecdh_init(self, stack):
        ctx = stack[0][2]['ctx']
        self.trace_processor.aliases.add(ctx)

    def mbedtls_ecdh_free(self, stack):
        ctx = stack[0][2]['ctx']
        self.trace_processor.aliases.remove(ctx)

    def mbedtls_ecdh_calc_secret(self, stack):
        ctx = stack[0][2]['ctx']
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(stack, alias, 1, 'ecdh')

    # ECDSA functions

    def mbedtls_ecdsa_init(self, stack):
        ctx = stack[0][2]['ctx']
        self.trace_processor.aliases.add(ctx)

    def mbedtls_ecdsa_free(self, stack):
        ctx = stack[0][2]['ctx']
        self.trace_processor.aliases.remove(ctx)

    def mbedtls_ecdsa_write_signature(self, stack):
        ctx = stack[0][2]['ctx']
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(stack, alias, 1, 'ecdsa/s')

    def mbedtls_ecdsa_write_signature_det(self, payload):
        # Ignore all SHAs that occur in read/write ECDSA
        if payload['dir'] == 'enter':
            self.block_sha = True
            ctx = payload['arg0']
            alias = self.trace_processor.aliases.get_alias(ctx)
            self.trace_processor.post_event(stack, payload, alias, 1, 'ecdsa/s')
        else:
            self.block_sha = False

    def mbedtls_ecdsa_read_signature(self, stack):
        ctx = stack[0][2]['ctx']
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(stack, alias, 1, 'ecdsa/v')

    # SHA256
    def mbedtls_sha256_init(self, stack):
        ctx = stack[0][2]['ctx']
        self.trace_processor.aliases.add(ctx)

    def mbedtls_sha256_free(self, stack):
        ctx = stack[0][2]['ctx']
        self.trace_processor.aliases.remove(ctx)

    def mbedtls_sha256_clone(self, stack):
        src = stack[0][2]['src']
        dst = stack[0][2]['dst']
        self.trace_processor.aliases.clone(src, dst)

    def mbedtls_sha256_update(self, stack):
        ctx = stack[0][2]['ctx']
        ilen = int(stack[0][2]['ilen'])
        alias = self.trace_processor.aliases.get_alias(ctx)
        if alias is None:
            raise Exception("Why is sha256 exception context missing %s" % ctx)
        shortname = "sha256"
        #if self.does_backtrace_contain_text('ecdsa', payload):
        #    shortname += '.ecdsa'
        self.trace_processor.post_event(stack, alias, ilen, shortname)

    def mbedtls_sha256_update_ret(self, stack):
        ctx = stack[0][2]['ctx']
        ilen = int(stack[0][2]['ilen'])
        alias = self.trace_processor.aliases.get_alias(ctx)
        if alias is None:
            raise Exception("Why is sha256 exception context missing %s" % ctx)
        shortname = "sha256"
        #if self.does_backtrace_contain_text('ecdsa', payload):
        #    shortname += '.ecdsa'
        self.trace_processor.post_event(stack, alias, ilen, shortname)

    # SHA512 (&384, they share contexts, oy!)

    def mbedtls_sha512_init(self, stack):
        ctx = stack[0][2]['ctx']
        self.trace_processor.aliases.add(ctx)

    def mbedtls_sha512_free(self, stack):
        ctx = stack[0][2]['ctx']
        self.trace_processor.aliases.remove(ctx)

    def mbedtls_sha512_update(self, stack):
        ctx = stack[0][2]['ctx']
        ilen = int(stack[0][2]['ilen'])
        alias = self.trace_processor.aliases.get_alias(ctx)
        if alias is None:
            raise Exception("Alias is none for context %s" % ctx)
        shortname = "sha512"
        self.trace_processor.post_event(stack, alias, ilen, shortname)

    # Other important high-level functions
"""
    # Just here as attributes for nesting naming
    def mbedtls_ctr_drbg_seed(self, stack):
        pass

    def mbedtls_ctr_drbg_random(self, stack):
        pass

    def ssl_update_checksum_sha256(self, stack):
        pass

    def ssl_update_checksum_start(self, stack):
        pass

    def mbedtls_hkdf_extract(self, stack):
        pass

    def mbedtls_hkdf_expand(self, stack):
        pass

    def mbedtls_md(self, stack):
        pass

    def mbedtls_md_hmac(self, stack):
        pass

    def mbedtls_md_hmac_update(self, stack):
        pass

    def mbedtls_md_hmac_finish(self, stack):
        pass

    def ecp_drbg_random(self, stack):
        pass

    def ecp_drbg_seed(self, stack):
        pass

    def ssl_calc_verify_tls_sha256(self, stack):
        pass

    def mbedtls_ecdsa_write_signature_restartable(self, stack):
        pass

    def ecdsa_sign_det_restartable(self, stack):
        pass

    def mbedtls_ssl_tls1_3_make_traffic_keys():
        pass

    def mbedtls_ssl_tls1_3_derive_secret():
        pass

    #def mbedtls_ssl_key_derivation():
    #    pass
"""
class CTraceProcessor:
    """ Processes an mbedTLS TRACE file. """
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

    def process_line(self, text):
        if not text:
            return

        # This is the "print ssl->state" command in the GDB script.
        if text[0] == '$':
            # Stage changes can only happen in between rbreaks. If we defer
            # parsing a state until the next stack resets, we will accidentally
            # post the event to the WRONG state (the n+1 state)!
            if len(self.current_stack) > 0:
                self.parsers.parse(self.current_stack)
                #print(self.current_stack)
                self.current_stack = []
            # NOW it is safe to update the state! Pernicious little bug!
            parts = re.split(r'[\s=]+', text)
            self.current_state = int(parts[1])
            return

        text = re.sub(r'".*?"', '', text)
        if text and text[0] != '#':
            return
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

        self.current_stack.append([ depth, fname, argv])
        # DONT FORGET LAST BUILT STACK!!!

    def post_event (self, stack, alias, n, tag):
        """ Add an event to the scoreboard, incrementing its 'n' value. """

        # Only post events to states we care about (see handshake_states)
        if self.current_state in handshake_states:
            pass
        else:
            print("Ignoring handshake state %d" % self.current_state)
            return
            
        nest = self.parsers.is_self_nested(stack)
        self.aliases.description(alias, tag)
        if alias is None:
            raise Exception("Alias is none")
        if alias not in self.scoreboard:
            self.scoreboard[alias] = {}
        slot = self.scoreboard[alias]

        # Slot needs to have depth
        if nest is not None:
            name_nest = "%s (in %s)" % (tag, nest)
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
            print(" . % 2s %s" % (state, mbedtls2_state_names[state]))
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
                                print('\t\t', i, subcall)
                            print()

if __name__ == '__main__':
    main()
