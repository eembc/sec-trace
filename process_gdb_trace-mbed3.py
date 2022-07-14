#!/usr/bin/env python3

# Note: the backtrace info comes from FRIDA Accuracy.FUZZY, so above a certain
# level it might be bogus. There is a regex at the end to purge everything
# above my_debug+ and main+, but be aware of this!

import sys
import re
import pprint
import argparse

# MbedTLS Handshake V3.x
# MBEDTLS_SSL_HELLO_REQUEST                  0
# MBEDTLS_SSL_CLIENT_HELLO                   1
# MBEDTLS_SSL_SERVER_HELLO                   2
# MBEDTLS_SSL_ENCRYPTED_EXTENSIONS          20
# MBEDTLS_SSL_CERTIFICATE_REQUEST            5
# MBEDTLS_SSL_SERVER_CERTIFICATE             3
# MBEDTLS_SSL_CERTIFICATE_VERIFY             9
# MBEDTLS_SSL_SERVER_FINISHED               13
# MBEDTLS_SSL_CLIENT_CERTIFICATE             7
# MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY     21
# MBEDTLS_SSL_CLIENT_FINISHED               11
# MBEDTLS_SSL_FLUSH_BUFFERS                 14 * PJT Dropped this, never seen it
# MBEDTLS_SSL_HANDSHAKE_WRAPUP              15
# Unused
# MBEDTLS_SSL_SERVER_KEY_EXCHANGE            4
# MBEDTLS_SSL_SERVER_HELLO_DONE              6
# MBEDTLS_SSL_CLIENT_KEY_EXCHANGE            8
# MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC     10
# MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC     12
# MBEDTLS_SSL_HANDSHAKE_OVER                16
handshake_states = [0, 1, 2, 20, 5, 3, 9, 13, 7, 21, 11, 15]
# Take from `ssl.h`
mbedtls3_state_names = [
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
    'MBEDTLS_SSL_HELLO_RETRY_REQUEST',
    'MBEDTLS_SSL_ENCRYPTED_EXTENSIONS',
    'MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY',
    'MBEDTLS_SSL_CLIENT_CCS_AFTER_SERVER_FINISHED',
    'MBEDTLS_SSL_CLIENT_CCS_BEFORE_2ND_CLIENT_HELLO',
    'MBEDTLS_SSL_SERVER_CCS_AFTER_SERVER_HELLO',
    'MBEDTLS_SSL_SERVER_CCS_AFTER_HELLO_RETRY_REQUEST'
]

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
            mode = "E"
        else:
            mode = "D"
        shorty = "ecb/%s" % mode
        self.trace_processor.post_event(stack, alias, 16, shorty) 

    def mbedtls_aesni_crypt_ecb(self, stack):
        ctx = stack[0][2]['ctx']
        mode = int(stack[0][2]['mode'])
        alias = self.trace_processor.aliases.get_alias(ctx)
        if mode == 1:
            mode = "E"
        else:
            mode = "D"
        shorty = "ecb/%s" % mode
        self.trace_processor.post_event(stack, alias, 16, shorty) 

    # AES/CCM functions

    def mbedtls_ccm_init(self, stack):
        ctx = stack[0][2]['ctx']
        self.trace_processor.aliases.add(ctx)

    def mbedtls_ccm_free(self, stack):
        ctx = stack[0][2]['ctx']
        self.trace_processor.aliases.remove(ctx)

    def mbedtls_ccm_encrypt_and_tag(self, stack):
        ctx = stack[0][2]['ctx']
        length = int(stack[0][2]['length'])
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(stack, alias, length, "ccm/E")

    def mbedtls_ccm_auth_decrypt(self, stack):
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
        if int(stack[0][2]['mode']) == 0:
            mode = "D"
        else:
            mode = "E"
        n = int(stack[0][2]['length'])
        alias = self.trace_processor.aliases.get_alias(ctx)
        self.trace_processor.post_event(stack, alias, n, ("gcm/%s" % mode))

    # ECDH Functions

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

    # SHA512 (&384, they share contexts, oy!)

    def mbedtls_sha512_init(self, stack):
        ctx = stack[0][2]['ctx']
        self.trace_processor.aliases.add(ctx)

    def mbedtls_sha512_free(self, stack):
        ctx = stack[0][2]['ctx']
        self.trace_processor.aliases.remove(ctx)

    def mbedtls_sha512_clone(self, stack):
        src = stack[0][2]['src']
        dst = stack[0][2]['dst']
        self.trace_processor.aliases.clone(src, dst)

    # mbedTLS 3.x
    
    def mbedtls_sha512_update(self, stack):
        ctx = stack[0][2]['ctx']
        ilen = int(stack[0][2]['ilen'])
        alias = self.trace_processor.aliases.get_alias(ctx)
        shortname = "sha512"
        #if self.does_backtrace_contain_text('ecdsa', payload):
        #    shortname += '.ecdsa'
        self.trace_processor.post_event(stack, alias, ilen, shortname)

    # Other important high-level functions dummy attributes for nesting

    def psa_hkdf_input():
        pass
    def psa_key_derivation_input_internal():
        pass
    def psa_key_derivation_hkdf_read():
        pass
    def psa_mac_compute():
        pass
    def psa_hash_compute():
        pass
    def mbedtls_ecp_gen_privkey():
        pass
    def gcm_aes_setkey_wrap():
        pass
    def ssl_update_checksum_sha384():
        pass
    def ssl_update_checksum_sha256():
        pass
    def ssl_update_checksum_start():
        pass
    def ecp_mul_comb_core():
        pass
    def ecp_mul_comb():
        pass
    def ecp_mul_comb_after_precomp():
        pass
    def mbedtls_ecp_gen_privkey_sw():
        pass
    def ecp_randomize_jac():
        pass
    def mbedtls_md():
        pass

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
        # Since we assemble after parse, make sure we are done!
        if len(self.current_stack) > 0:
            self.parsers.parse(self.current_stack)

    def process_line(self, text):
        if not text:
            return

        # This is the "print ssl->state" command in the GDB script.
        if text[0] == '$':
            parts = re.split(r'[\s=]+', text)
            self.current_state = int(parts[1])
            return

        # After this point we only care about backtraces
        if text[0] != '#':
            return

        # Remove really long quotes that screw up the splitter
        # Fortunately GDB hex-escapes embedded quotes!
        text = re.sub(r'".*?"', '', text)

        # Assemble the call stack for each `rbreak` expression
        parts = re.split(r'[#\s\(\),]', text)
        if len(parts) < 3:
            return
        depth = int(parts[1])
        if depth == 0:
            fname = parts[3]
        else:
            fname = parts[5]
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
            if self.current_state >= 0:
                print("Ignoring handshake state %d" % self.current_state)
            return
            
        nest = self.parsers.is_self_nested(stack)
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
        print(" . % 2s %s" % (state, mbedtls3_state_names[state]))
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

    for ctx in trace_processor.aliases.context_alias_cache:
        print("Warning: the context '%s' used by alias '%s' was not freed:" % (ctx, trace_processor.aliases.context_alias_cache[ctx]))

if __name__ == '__main__':
    main()
