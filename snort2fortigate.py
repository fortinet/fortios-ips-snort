#!/usr/bin/env python
# This script is being provided by the copyright holders under the following
# license. By obtaining, using and/or copying this work, you (the licensee)
# agree that you have read, understood, and will comply with the following terms
# and conditions
#
# Permission to copy, modify, and distribute this software and its documentation
# with or without modification, for any purpose and without fee or royalty is
# hereby granted, provided that you include the following on ALL copies of the
# software and documentation or portions thereof, including modifications:
#
#   1. The full text of this NOTICE in a location viewable to users of the
#      redistributed or derivative work.
#   2. Notice of any changes or modifications to the files, including the date
#      changes were made.
#
# THIS SOFTWARE AND DOCUMENTATION IS PROVIDED "AS IS," AND COPYRIGHT HOLDERS
# MAKE NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT
# LIMITED TO, WARRANTIES OF MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR
# PURPOSE OR THAT THE USE OF THE SOFTWARE OR DOCUMENTATION WILL NOT INFRINGE ANY
# THIRD PARTY PATENTS, COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS.
#
# COPYRIGHT HOLDERS WILL NOT BE LIABLE FOR ANY DIRECT, INDIRECT, SPECIAL OR
# CONSEQUENTIAL DAMAGES ARISING OUT OF ANY USE OF THE SOFTWARE OR DOCUMENTATION.
#
# Title to copyright in this software and any associated documentation will at
# all times remain with copyright holders.
#
# Copyright 2019 Fortinet, Inc. All Rights Reserved.

import os
import sys
import re
import argparse
import logging
import json
import time

try:
    from cStringIO import StringIO  # Python 2
except ImportError:
    from io import StringIO

# Declare the globals
version = '3.0'
print_err_warning = False
debug_log = False
input_file = None
output_file = 'fortirules.txt'
snort_count = 0
disabled_snort_count = 0
fgt_rule_count = 0
rule_maxlen = 1024
log_stream = StringIO()
json_stream = StringIO()

# Keeping state for Snort3 syntax
content_seen_flag = False  # has encountered content: or pcre: in this rule
sticky_buffer_flag = False  # sticky buffer encountered
alert_file_flag = False  # alert file is found in rule header

# Keeping state for Snort2 syntax
open_context_flag = False
added_context_flag = False
context_modifier_flag = False
bi_direction_flag = False
force_snort_2 = False

# Distinguish Snort2/3 at the end for edge case where a rule begins with file_data
# and swaps to another context. Default parsed as Snort3 rule but cannot tell
# until we see whether we end in a context option (S2) or a content option (S3)
# set to last seen key (content/pcre/file_data/http_uri/http_raw_...etc)
last_seen_option = ''

context_flags = None
regs = None
service_priority = None
keywordhandler = None

'''

Declare all the constants related to common Snort keywords

'''
#map all the different keywords related to context for easy conversion later
context_header = {'http_cookie':'H', 'http_raw_cookie':'H', 'http_header':'H', 'http_raw_header':'H', 'sip_header':'H'}
context_banner = {'http_stat_code':'R', 'http_stat_msg':'R', 'sip_method':'R', 'sip_stat_code':'R', 'http_raw_status':'R'}
context_body = {'sip_body':'B', 'http_client_body':'B', 'http_raw_body':'B'}
context_uri = {'http_method':'U', 'http_uri':'U', 'http_raw_uri':'U', 'http_raw_request':'U'}
context_packet = {'pkt_data':'P'}
context_file = {'file_data':'F'}
context_raw_packet = {'raw_data':'O', 'rawbytes':'O'}

keyword_dict = {}
for i in (context_header, context_banner, context_body, context_uri, context_packet,\
context_file, context_raw_packet): keyword_dict.update(i)

#keyword that we can omit without any impact on the signature detection
key_drop = {'msg', 'reference', 'rev', 'classtype', 'priority', 'sid', 'gid',
            'fast_pattern', 'http_encode', 'service', 'rem'}
			
unsupported_fatal = {'md5', 'sha256', 'sha512', 'so', 'soid'}

direct_trans = {
    'icmp_id': 'icmp_id',
    'icmp_seq': 'icmp_seq',
    'id': 'ip_id',
    'sameip': 'same_ip',
    'ack': 'ack',
    'seq': 'seq',
    'ipopts': 'ip_option',
    'dsize': 'data_size',
    'icode': 'icmp.code',
    'itype': 'icmp.type',
    'window': 'window_size',
    'tos': 'ip_tos',
    'flags': 'tcp_flags'
}

content_modifier = {'depth', 'offset', 'distance', 'within', 'nocase'}
content_pattern = {'content', 'pcre', 'uricontent'}
	
class Registers:
    ''' This class holds the mapping for Snort variables to registers'''

    def __init__(self):
        self.reg = []

    def set_reg(self, var, value):
        if len(self.reg) == 8:
            logging.error("Too many registers set. Signature failed to convert.")
            return False
        else:
            self.reg.append((var, value))
            return len(self.reg) - 1

    def get_var_frm_reg(self, i):
        return self.reg[i]

    def get_reg_frm_var(self, var):
        for i, val in enumerate(self.reg):
            if val[0] == var:
                return i
        return -1

    def clear_regs(self):
        self.reg = []


class ContextFlags:
    ''' This class holds context flags for encountering Snort modifiers '''
    ''' and sticky buffers and returns the appropriate IPS pattern      '''
    ''' context. (body [B], file [F], header [H], uri [U], packet [P],  '''
    ''' banner [R], packet_origin [O] )                                 '''
    ''' context_cursor holds boolean for encountering cursors file_data
        or pkt_data which require special handling to distinguish in
        Snort2 vs Snort3. True only if cursor is in a Snort2 rule '''

    def __init__(self):
        self.context = None
        self.context_cursor = False

    def set_flag(self, flag):
        if flag in ['B', 'F', 'H', 'P', 'U', 'R', 'O']:
            self.context = flag

    def reset(self):
        self.context = None
        self.context_cursor = False

    def get_flag(self):
        return self.context

    def set_cursor(self):
        self.context_cursor = True

    def unset_cursor(self):
        self.context_cursor = False

    def is_context_cursor(self):
        return self.context_cursor

    def get_context_rule(self):
        if self.context == 'B':
            return ' --context body;'
        elif self.context == 'F':
            return ' --context file;'
        elif self.context == 'H':
            return ' --context header;'
        elif self.context == 'U':
            return ' --context uri;'
        elif self.context == 'R':
            return ' --context banner;'
        elif self.context == 'O':
            return ' --context packet_origin;'
        else:
            return ' --context packet;'


class ServicePriority:
    ''' This class holds --service option to add that is priority, when
    encountering a context option that should refer to a specific service
    overriding the service options added from the default ports in the
    header.
    eg. encountering sip_body, we should set --service sip;
    If there is priority set, the service option is added in __single_option_check
    '''
    supported_services = {
        'http': ' --service http;',
        'sip': ' --service sip;',
        'modbus': ' --service modbus;',
        'ssl': ' --service ssl;',
        'ftp': ' --service ftp;',
        'telnet': ' --service telnet;',
        'smtp': ' --service smtp;',
        'ssh': ' --service ssh;',
        'dcerpc': ' --service dcerpc;',
        'netbios': ' --service nbss;',
        'nntp': ' --service nntp;',
        'sunrpc': ' --service rpc;',
        'dns': ' --service dns;',
        'imap': ' --service imap;',
        'pop3': ' --service pop3;',
        'snmp': ' --service snmp;',
        'ldap': ' --service ldap;',
        'radius': ' --service radius;',
        'rtsp': ' --service rtsp;'
    }

    def __init__(self):
        self.reset_service()

    def set_service(self, service):
        self.service = self.supported_services.get(service)

    def set_high_service(self, service):
        self.high_service = self.supported_services.get(service)

    def get_service(self):
        # Either returns the --service <service_name>; or None if not set
        if self.high_service is None:
            return self.service
        return self.high_service

    def reset_service(self):
        self.service = None
        self.high_service = None

class FunctionSwitch: 
    '''
    To avoid rebuilding the dictionary for the function calls each time a keyword is examined, 
    this class will create a map per instance to optimize the code. 
    '''
    def __init__(self):
	    self.__map = {  # all other keywords that are not pcre: or content:or its suboptions
        'flowbits': _handle_flowbits,
        'flow': _handle_flow,
        'byte_jump': _handle_byte_jump,
        'byte_test': _handle_byte_test,
        'byte_extract': _handle_byte_extract,
        'ip_proto': _handle_ip_proto,
        'ssl_version': _handle_ssl_version,
        'bufferlen': _handle_bufferlen,
        'urilen': _handle_urilen,
        'detection_filter': _handle_detection_filter,
        'icmp_id': _handle_direct_trans,
        'icmp_seq': _handle_direct_trans,
        'id': _handle_direct_trans,
        'sameip': _handle_direct_trans,
        'ack': _handle_direct_trans,
        'seq': _handle_direct_trans,
        'ipopts': _handle_direct_trans,
        'dsize': _handle_min_max_convert,
        'icode': _handle_min_max_convert,
        'itype': _handle_min_max_convert,
        'window': _handle_direct_trans,
        'isdataat': _handle_isdataat,
        'flags': _handle_direct_trans,
        'tos': _handle_direct_trans,
        'ttl': _handle_ttl,
        'service': _handle_service,
        'metadata': _handle_metadata
    }
	
    '''From key, call appropriate function to handle from switch. '''
    def get_handler(self, key):
	    return self.__map.get(key)			

def keyword_handler(key, value):
    ''' Snort option keys are organized in the following groups:
        key_drop: metadata related or keywords that we drop WITHOUT warning
        context_<name>: groups keys that translate into some --context <name>;
        content_modifier: Snort content modifiers (if it's a separate keyword
            entering this function, this is Snort2)
        content_pattern: the 'content' and 'pcre' keys that are handled
            separately outside of the switch statement
        direct_trans: subset of switch that can be handled with a 1:1
            translation substituting the option name (_handle_direct_trans)
        unsupported_fatal: skip the signature if encountering this option
    '''
    ''' returns from handler functions called are:
        - the converted rule if it is successful
        - False (literal False, '', or None) if it is not successful
            - is None if we are just omitting but continuing with rest of
              rule
    '''
    ''' Return (validity_boolean,converted_rule) '''
    global open_context_flag
    global last_seen_option
    rule = ''
    valid = False

	
    ##########################################
    # Begin parsing keyword:

    __keyword_handler = keywordhandler.get_handler(key)
    if key in content_pattern:
        last_seen_option = key
        if key == 'pcre':
            handled_opt = _handle_pcre(value)
        elif key == 'content':
            handled_opt = _handle_content(value)
        else:
            handled_opt = _handle_uri_content(value)
        if handled_opt:
            rule += handled_opt
            valid = True
        elif handled_opt is None:
            valid = True
    elif __keyword_handler != None:
        rule += __check_and_add_context_packet()
        open_context_flag = False
        if key in direct_trans.keys():
            handled_opt = __keyword_handler(direct_trans[key], value)
        else:
            handled_opt = __keyword_handler(value)
        if handled_opt:
            rule += handled_opt
            valid = True
        elif handled_opt is None:
            valid = True
    elif key in key_drop:
        valid = True
        pass
    elif key in keyword_dict.keys():
        last_seen_option = key
        handled_opt = _handle_context(key, keyword_dict[key])
        if handled_opt:
            rule += handled_opt
            valid = True
        elif handled_opt is None:  # This occurs with Snort3 sticky buffers, None returned
            valid = True
        service_priority.set_service(key.split('_')[0])
    elif key in content_modifier:
        handled_opt = _handle_content_modifier(key, value)
        if handled_opt:
            rule += handled_opt
            valid = True
        elif handled_opt is None:
            valid = True
    elif key in unsupported_fatal:
        logging.error('Unsupported Snort option "%s" found. Skipping rule.' % key)
    else:
        # unsupported keywords.
        logging.warning('Unsupported Snort option "%s" found. Omitting' % key)
        valid = True
    return (valid, rule)


def _handle_content_modifier(key, value):
    ''' Content modifiers: nocase, offset, depth, distance, within. '''
    ''' Supports registers from byte_extract.                       '''
    logging.debug('inside _handle_content_modifier')
    global context_modifier_flag
    value = value.strip()
    rule = ''
    if value and re.match('^\-?\d+$', value) is None:
        # convert to a register , must be previously extracted w/ byte_extract
        reg_val = regs.get_reg_frm_var(value)
        if reg_val == -1:
            logging.warning('Register not found for extracted content modifier variable %s. Omitting modifier.' % value)
            return None
        else:
            value = '$%s' % reg_val

    if open_context_flag:
        if key == 'nocase':
            rule = ' --no_case;'
        elif key == 'depth':
            rule = ' --distance %s,context;' % value
            if not sticky_buffer_flag:
                context_modifier_flag = True
        elif key == 'distance':
            rule = ' --distance %s;' % value
        elif key == 'offset':
            rule = ' --within %s,context;' % value
            if not sticky_buffer_flag:
                context_modifier_flag = True
        elif key == 'within':
            rule = ' --within %s;' % value
    return rule


def _handle_context(key, context):
    ''' Handle receiving a context related keyword      '''
    ''' Snort 2 and 3 syntax results in different state '''
    logging.debug('inside _handle_context with context %s' % context)
    global sticky_buffer_flag
    global added_context_flag
    cursor_keys = ['file_data', 'pkt_data']

    if context_flags.is_context_cursor():
        # is currently in a S2 cursor move
        if key in cursor_keys:
            # got another cursor set, eg. from file_data; to pkt_data
            context_flags.set_flag(context)
        else:
            # remove cursor flag and set back to being Snort 2 to parse rest of rule properly
            context_flags.unset_cursor()
            sticky_buffer_flag = False
            context_flags.set_flag(context)
            return context_flags.get_context_rule()
    if content_seen_flag == False:
        # Snort3 Rule
        sticky_buffer_flag = True
        context_flags.set_flag(context)
    elif sticky_buffer_flag == True:
        context_flags.set_flag(context)
    else:
        # Snort2 Rule
        if open_context_flag:
            if not added_context_flag:
                # parsed content: earlier, need to add context now
                context_flags.set_flag(context)
                added_context_flag = True
                return context_flags.get_context_rule()
            else:
                # this is probably pkt_data or something that goes first
                # despite the other content modifiers going after in Snort 2
                context_flags.set_flag(context)
                context_flags.set_cursor()
                # treat this section of rule as Snort 3 since it comes before content
                sticky_buffer_flag = True
                return None
        else:
            if force_snort_2:
                # REPARSING AS SNORT 2 when beginning with file_data/pkt_data
                context_flags.set_flag(context)
                context_flags.set_cursor()
                # treat this section of rule as Snort 3 since it comes before content
                sticky_buffer_flag = True

                return None

            # don't know what this context is doing here
            logging.warning("Syntax error at Snort option %s. Skipping" % key)
            return None
    return None


def __normalize_pattern(p):
    p = p.replace('\\;', '|3B|')
    p = p.replace('\\:', '|3A|')
    return p


def __check_and_add_context_packet():
    ''' Snort2: having written --pattern or --pcre without context yet  '''
    ''' while having distance/within with ,context; requiring a         '''
    ''' --context packet; at the end.                                   '''
    pattern = ''
    if open_context_flag:
        if context_modifier_flag and not added_context_flag:
            pattern += ' --context packet;'
    return pattern


def _handle_content(value):
    ''' When receiving content value, it can be Snort2 or Snort3 style  '''
    ''' Snort2: content:"/Home/"; depth:6; would only give pattern and  '''
    ''' require handling content modifier 'depth' in keyword_handler as '''
    ''' its own key.                                                    '''
    ''' Snort3: content:"/Home/",depth 6; provides the modifiers as     '''
    ''' suboptions and can be added immediately. Context is also known  '''
    ''' for Snort3 rules to be added based on global flags.             '''
    logging.debug('inside _handle_content')
    global content_seen_flag
    global open_context_flag
    global added_context_flag
    content_seen_flag = True
    pattern = __check_and_add_context_packet()
    open_context_flag = True
    added_context = False

    pattern += ' --pattern ' + __normalize_pattern(value.strip())
    if pattern[-1] != '"': # options after end of pattern string
        s3_opts = pattern.rsplit('",', 1)
        if len(s3_opts) > 1:
            # Snort3 content suboptions found
            # currently parses distance/within/offset/depth/nocase
            pattern = s3_opts[0] + '";'
            added_context = True
            for s in s3_opts[1].split(','):
                subkey = s.strip().split(' ')
                if subkey[0] in ['nocase', 'offset', 'depth', 'distance', 'within']:
                    if len(subkey) < 2:
                        subkey_val = ''
                    else:
                        subkey_val = subkey[1]
                    content_mod = _handle_content_modifier(subkey[0], subkey_val)
                    if content_mod:
                        pattern += content_mod
                else:  # unknown? skip (eg. fast_pattern)
                    continue
    if not added_context:
        pattern += ';'

    if sticky_buffer_flag:
        # Snort3: already know context, add it in:
        pattern += context_flags.get_context_rule()
    else:
        added_context_flag = False
    return pattern


def _handle_flow(value):
    ''' Converts option flow -> --flow dir;                                   '''
    ''' Snort flow syntax: [(established|not_established|stateless)]          '''
    '''                    [,(to_client|to_server| from_client| from_server)] '''
    '''                    [,(no_stream|only stream)]                         '''
    '''                    [,(no_frag|only_frag)]                             '''
    ''' FGT engine does not differentiate between established/not/stateless   '''
    ''' FGT engine does not support no_stream/only_stream/no_frag/only_frag   '''
    logging.debug('inside _handle_flow')
    global bi_direction_flag
    if bi_direction_flag:
        return None

    opts = value.replace(' ', '').split(',')
    pattern = ''

    for o in opts:
        if o in ['to_client', 'from_server']:
            pattern = "".join((pattern, ' --flow from_server;'))
        elif o in ['to_server', 'from_client']:
            pattern = "".join((pattern, ' --flow from_client;'))
        elif o in ['established', 'not_established', 'stateless']:
            if len(opts) == 1:
                logging.warning('"flow" cannot convert "%s". Option not supported. Omitting option.' % o)
                return None
            continue
        else:
            logging.warning('"flow" cannot convert "%s". Option not supported. Omitting option.' % o)
            return None
    return pattern


def _handle_flowbits(value):
    ''' Converts option flowbits -> --tag test,set              '''
    ''' flowbits:<cmd>,<tag_name(s)>,<group_name>;              '''
    ''' FGT keyword does not accept group_name option           '''
    logging.debug('inside _handle_flowbits')
    tag_keys = {
        'set': 'set',
        'unset': 'clear',
        'isnotset': 'test,!',
        'isset': 'test',
        'noalert': 'quiet',
        'toggle': 'toggle'
    }

    opts = value.replace(' ', '').split(',')
    pattern = ''

    cmd = tag_keys.get(opts[0])
    if cmd is None:
        logging.error('"flowbits" cannot convert "%s". cmd is not supported. Omitting option.' % cmd)
        return False
    if len(opts) == 3:
        logging.warning('"flowbits" cannot convert "%s". Group names are not supported. Omitting option.' % opts[2])

    if len(opts) == 1:
        pattern += ' --tag %s;' % cmd
        return pattern

    tags = [opts[1]]
    if "&" in opts[1]:
        tags = opts[1].split("&")
    for t in tags:
        pattern += ' --tag %s,%s;' % (cmd, t)
    return pattern


def _handle_pcre(value):
    ''' PCRE option in Snort2 can have Snort specific modifiers:
        'R': Match relative to the end of the last pattern match.
            (Similar to distance:0;)
            -> --distance 0;
        'I', 'U': URI buffer (ignore decoded or unnormalized)
            -> --context uri;
        'C', 'D', 'H', 'K', 'M': cookie/http_raw_header/http_header/
            /raw cookie/http_method, all of which is just..
            -> -- context header;
        'S', 'Y': http_stat_code/http_stat_msg
            -> --context banner;
        'P': http_client_body
            -> --context body;
        'B': rawbytes --> --context packet; (possibly packet,origin)
    '''
    '''
        Meanwhile, Snort3 removes this in favour of sticky buffers.
        Similar to content option.
        Check sticky_buffer_flag and add context if it already is known.
    '''
    logging.debug('inside _handle_pcre')
    global content_seen_flag
    global open_context_flag
    global added_context_flag
    content_seen_flag = True  # Since Snort3 uses buffers for PCRE too
    rule = __check_and_add_context_packet()
    open_context_flag = True

    mod_uri = ['I', 'U']
    mod_header = ['C', 'D', 'H', 'K', 'M']
    mod_banner = ['S', 'Y']
    mod_packet = ['B']
    mod_body = ['P']
    mod_distance = ['R']  # I think this still exists in Snort 3
    mod_unsupported = ['O']

    rule_mod = ''
    pcre = re.compile(r'!?\"(?P<exp>\/.*\/)(?P<mod>[\w]*)\"')
    m = pcre.match(value)
    if not m:
        logging.error('Syntax error in PCRE option: %s. Skipping rule.' % value)
        return False
    else:
        expr = m.group('exp')
        mods = m.group('mod')
        expr.replace('"', '\x22')
        expr.replace("'", '\x27')

        # Handle PCRE modifiers, removing each Snort specific modifier found
        mod_list = list(mods)
        mod_i = 0
        del_mod = False
        while len(mod_list) > 0:
            mod = mod_list[mod_i]
            if mod in mod_uri:
                rule_mod += ' --context uri;'
                # update list to delete this modifier since we are done with it.
                # Same context ones are deleted at the same time to not duplicate.
                mod_list = [x for x in mod_list if x not in mod_uri]
                added_context_flag = True
                del_mod = True
            elif mod in mod_header:
                rule_mod = "".join((rule_mod, ' --context header;'))
                mod_list = [x for x in mod_list if x not in mod_header]
                added_context_flag = True
                del_mod = True
            elif mod in mod_body:
                rule_mod = "".join((rule_mod, ' --context body;'))
                mod_list = [x for x in mod_list if x not in mod_body]
                added_context_flag = True
                del_mod = True
            elif mod in mod_banner:
                rule_mod = "".join((rule_mod, ' --context banner;'))
                mod_list = [x for x in mod_list if x not in mod_banner]
                added_context_flag = True
                del_mod = True
            elif mod in mod_packet:
                rule_mod = "".join((rule_mod, ' --context packet;'))
                mod_list = [x for x in mod_list if x not in mod_packet]
                added_context_flag = True
                del_mod = True
            elif mod in mod_distance:
                rule_mod = "".join((rule_mod, ' --distance 0;'))
                mod_list = [x for x in mod_list if x not in mod_distance]
                del_mod = True
            elif mod in mod_unsupported:
                logging.warning("Snort PCRE option %s not supported." % mod)
                mod_list = [x for x in mod_list if x not in mod_unsupported]
                del_mod = True
            if del_mod:
                if len(mod_list) <= mod_i:
                    # Have removed all Snort specific modifiers
                    break
            else:
                # Move iterator to next position in mod_list since nothing was deleted
                if len(mod_list) > mod_i + 1:
                    mod_i += 1
                else:
                    # Have removed all Snort specific modifiers
                    break
            del_mod = False

        # If multiple different contexts are added from above.. remove
        if len(rule_mod.split('--context')) > 2:
            logging.warning(
                'Cannot support multiple Snort HTTP modifiers in PCRE expression "%s%s". Omitting context' % (
                    expr, mods))
            rule_mod = ''

        # Remaining in mod_list is either a regular Perl/PCRE modifier
        # or an invalid one. We are keeping it in the PCRE expression "/<exp>/<mod>"
        expr += ''.join(mod_list)

        # Snort3:
        if sticky_buffer_flag:
            # Just in case someone writes a sig with the PCRE modifier anyways
            # even in a Snort3 sig, don't duplicate it.
            if '--context' not in rule_mod:
                rule_mod += context_flags.get_context_rule()

        rule += ' --pcre "' + expr + '";' + rule_mod

    return rule


def _handle_byte_jump(value):
    ''' Converts byte_jump option to --byte_jump                      '''
    ''' Syntax: byte_jump: <bytes>, <offset> [,modifiers]              '''
    ''' Do not support keywords: dce, bitmask, from_end, post_offset  '''
    logging.debug('inside _handle_byte_jump')
    frm_beg_flag = False
    opts = [x.strip() for x in value.split(',')]
    mult_num = ''
    add_opts = []
    pattern = ' --byte_jump %s,%s' % (opts[0], opts[1])
    if len(opts) > 2:
        for o in opts[2:]:
            if o == 'from_beginning':
                frm_beg_flag = True
            elif 'multiplier' in o:
                mult_num = o.split(' ')[1]
            elif (o in ['dce', 'from_end']) or ('bitmask' in o) or ('post_offset' in o):
                logging.error('"byte_jump" cannot convert "%s". Modifier not supported.' % o)
                return False
            else:
                add_opts.append(o)

        if mult_num != '':
            pattern += ',%s' % mult_num
        if len(add_opts) > 0:
            pattern += ',%s' % ','.join(add_opts)
    pattern += ';'
    if frm_beg_flag:
        pattern = pattern.replace('relative', '')
        pattern = pattern.replace(',,', ',')
        pattern = pattern.replace(',;', ';')
    return pattern


def __get_val(value):
    ''' Converts string variable from byte_test to int or retrieves   '''
    ''' register from variable name. returns tuple (value, data_type) '''
    if '0x' == value[:2]:
        val = int(value, 16)
        val_type = 'hex'
    elif re.match('^\-?\d+$', value):
        val = int(value)
        val_type = 'int'
    else:
        val = regs.get_reg_frm_var(value)
        if val == -1:
            return False
        val = '$%s' % val
        val_type = 'reg'
    return (val, val_type)


def __arith(value, op):
    ''' Performs arithmetic operations on the extracted values '''
    ''' from byte_test. Also performs overflow check. returns  '''
    ''' False if overflow occurs.                              '''
    ''' value = (value, type). type can be int/hex/register    '''
    ''' op = +/-. May add more in the future.                  '''
    if value[1] == 'reg':
        return value[0] + op + '1'

    # currently only support + and -
    if op == '+':
        ret_val = value[0] + 1
    elif op == '-':
        ret_val = value[0] - 1

    # checks overflow
    if ret_val > 4294967295:
        return False

    if value[1] == 'hex':
        return hex(ret_val)
    return ret_val


def _handle_byte_test(value):
    ''' Converts byte_test to -> --byte_test                            '''
    ''' Syntax: byte_test <bytes>,<op>,<value>,<offset>[,modifiers]     '''
    ''' 1. Do not support operators: !&, !^                             '''
    ''' 2. Snort allows byte test of 1-10 bytes. FGT only allows 1,2,4  '''
    ''' 3. Do not support keywords: bitmask, dce                        '''
    logging.debug('inside _handle_byte_test')

    opts = [x.strip() for x in value.split(',')]
    op = opts[1]

    # handle bytes:
    if opts[0] not in ['1', '2', '4']:
        logging.error('"byte_test" cannot convert "%s". Option only allow testing against 1,2,4 bytes.' % value)
        return False
    pattern = ' --byte_test %s' % opts[0]

    # handles values
    val = __get_val(opts[2])
    if not val:
        logging.error('"byte_test" cannot convert "%s". Cannot map register to variable.' % value)
        return False
    else:
        ret_val = val[0]

    # handles operator
    if '!' in op:
        if '!=' == op:
            pattern += ',!,'
        elif '>' in op:
            pattern += ',<,'
            if '!>' == op:
                ret_val = __arith(val, '-')
                if not ret_val:
                    logging.error('"byte_test" cannot convert "%s". Operator not supported.' % value)
                    return False
        elif '<' in op:
            pattern += ',>,'
            if '!<' == op:
                ret_val = __arith(val, '+')
                if not ret_val:
                    logging.error('"byte_test" cannot convert "%s". Operator not supported.' % value)
                    return False
        else:
            logging.error('"byte_test" cannot convert "%s". Operator not supported.' % value)
            return False
    elif '>=' == op:
        ret_val = __arith(val, '-')
        if not ret_val:
            logging.error('"byte_test" cannot convert "%s". Operator not supported.' % value)
            return False
        pattern += ',>,'
    elif '<=' == op:
        ret_val = __arith(val, '+')
        if not ret_val:
            logging.error('"byte_test" cannot convert "%s". Operator not supported.' % value)
            return False
        pattern += ',<,'
    else:
        pattern += ',%s,' % op

    # add offset
    pattern += '%s,' % ret_val
    pattern += opts[3]

    # parse options
    if len(opts) > 4:
        for o in opts[4:]:
            if o == 'dce' or 'bitmask' in o:
                logging.error('"byte_test" cannot convert "%s". Modifier not supported.' % o)
                return False
            pattern += ',%s' % o
    pattern += ';'
    return pattern


def _handle_byte_extract(value):
    ''' Converts byte_extract option to --extract           '''
    ''' byte_extract: <bytes>, <offset>, <name>, [options]  '''
    ''' Do not support keywords: dce, bitmask, multiplier   '''
    '''                          align                      '''
    logging.debug('inside _handle_byte_extract')
    opts = [x.strip() for x in value.split(',')]
    pattern = ' --extract %s,%s,' % (opts[0], opts[1])
    reg = regs.set_reg(opts[2], 0)
    pattern += '$%s' % reg
    mult_num = ''

    add_opts = []
    if len(opts) > 3:
        for o in opts[3:]:
            if 'multiplier' in o:
                mult_num = o.split(' ')[1]
            elif o == 'dce' or 'bitmask' in o or 'align' in o:
                logging.error('"byte_extract" cannot convert "%s". Modifier not supported.' % o)
                return False
            else:
                add_opts.append(o)

        if mult_num != '':
            pattern += ',%s' % mult_num
        if len(add_opts) > 0:
            pattern += ',%s' % ','.join(add_opts)
    pattern += ';'
    return pattern


def _handle_ip_proto(value):
    ''' Convert ip_proto -> --protocol <protocol>;             '''
    ''' If ip_proto contains operator, use ip[offset] instead. '''
    logging.debug('inside _handle_ip_proto')
    ip_protocols = {
        'icmp': 1, 'igmp': 2, 'ggp': 3, 'ipip': 4, 'st': 5, 'tcp': 6, 'cbt': 7, 'egp': 8, 'igp': 9, 'bbnrcc': 10,
        'nvp': 11, 'pup': 12, 'argus': 13, 'emcon': 14, 'xnet': 15, 'chaos': 16, 'udp': 17, 'mux': 18, 'dcnmeas': 19,
        'hmp': 20, 'prm': 21, 'idp': 22, 'trunk1': 23, 'trunk2': 24, 'leaf1': 25, 'leaf2': 26, 'rdp': 27, 'irtp': 28,
        'tp': 29, 'netblt': 30, 'mfpnsp': 31, 'meritinp': 32, 'sep': 33, '3pc': 34, 'idpr': 35, 'xtp': 36, 'ddp': 37,
        'cmtp': 38, 'tppp': 39, 'il': 40, 'ip6': 41, 'sdrp': 42, 'routing': 43, 'fragment': 44, 'rsvp': 46, 'gre': 47,
        'mhrp': 48, 'ena': 49, 'esp': 50, 'ah': 51, 'inlsp': 52, 'swipe': 53, 'narp': 54, 'mobile': 55, 'tlsp': 56,
        'skip': 57, 'icmp6': 58, 'none': 59, 'dstopts': 60, 'anyhost': 61, 'cftp': 62, 'anynet': 63, 'expak': 64,
        'kryptolan': 65, 'rvd': 66, 'ippc': 67, 'distfs': 68, 'satmon': 69, 'visa': 70, 'ipcv': 71, 'cpnx': 72,
        'cphb': 73,
        'wsn': 74, 'pvp': 75, 'brsatmon': 76, 'sunnd': 77, 'wbmon': 78, 'wbexpak': 79, 'eon': 80, 'vmtp': 81,
        'svmtp': 82,
        'vines': 83, 'ttp': 84, 'nsfigp': 85, 'dgp': 86, 'tcf': 87, 'eigrp': 88, 'ospf': 89, 'spriterpc': 90,
        'larp': 91,
        'mtp': 92, 'ax25': 93, 'ipipencap': 94, 'micp': 95, 'sccsp': 96, 'etherip': 97, 'encap': 98, 'anyenc': 99,
        'gmtp': 100, 'ifmp': 101, 'pnni': 102, 'pim': 103, 'aris': 104, 'scps': 105, 'qnx': 106, 'an': 107,
        'ipcomp': 108,
        'snp': 109, 'compaqpeer': 110, 'ipxip': 111, 'vrrp': 112, 'pgm': 113, 'any0hop': 114, 'l2tp': 115, 'ddx': 116,
        'iatp': 117,
        'stp': 118, 'srp': 119, 'uti': 120, 'smp': 121, 'sm': 122, 'ptp': 123, 'isis': 124, 'fire': 125, 'crtp': 126,
        'crudp': 127, 'sscopmce': 128, 'iplt': 129, 'sps': 130, 'pipe': 131, 'sctp': 132, 'fc': 133, 'rsvpign': 134
    }
    pattern = ''
    value = value.replace(' ', '')
    if '!' not in value and '<' not in value and '>' not in value:
        if not value.isdigit():
            value = ip_protocols.get(value)
        if value is None:
            logging.warning('"ip_proto" cannot convert "%s". Protocol cannot be converted. Omitting option.' % value)
            return None
        pattern += ' --protocol %s;' % value
    elif '<>' in value or '<=>' in value:
        pattern += _handle_min_max_convert('ip[9]', value)
    else:
        op = value[0]
        proto_num = value[1:]
        if not proto_num.isdigit():
            proto_num = ip_protocols.get(proto_num)
        if proto_num is None:
            logging.warning('"ip_proto" cannot convert "%s". Protocol cannot be converted. Omitting option.' % value)
            return None
        pattern += ' --ip[9] %s%s;' % (op, proto_num)
    return pattern


def _handle_ssl_version(value):
    ''' Convert ssl_version -> --parsed_type <ssl_version>. '''
    ''' One rule can have multiple --parsed_type options.   '''
    logging.debug('inside _handle_ssl_version')
    service_priority.set_service('ssl')
    pattern = ''
    dict = {'tls1.0':'TLS_V1', 'tls1.1':'TLS_V2', 'tls1.2':'TLS_V3', 'sslv2':'SSL_V2', 'sslv3':'SSL_V3'}
    opts = value.replace(' ', '').split(',')
    for o in opts:
        o = o.strip()
        try:
		    pattern = "".join((' --parsed_type ', dict.get(o), ';'))			
        except:
            logging.warning('"ssl_version" cannot convert "%s". SSL Version unknown. Omitting option.' % o)
            continue
    if pattern == '':
        return None
    return pattern


def _handle_uri_content(value):
    ''' Handle Snort 2 'uricontent' (removed in favour of sticky buffers in
        Snort 3). uricontent is like content:"hdjsd"; http_uri; and modifiers
        like offset and distance can still be applied
        eg. uricontent:"hdjsd"; offset:4;
    '''
    logging.debug('inside _handle_uri_content')
    global content_seen_flag
    global open_context_flag
    global added_context_flag
    content_seen_flag = True
    pattern = __check_and_add_context_packet()
    open_context_flag = True
    added_context_flag = True

    pattern += ' --pattern ' + __normalize_pattern(value.strip()) + '; --context uri;'

    return pattern


def _handle_bufferlen(value):
    ''' We only handle the case where bufferlen is part of a sticky buffer. '''
    ''' Currently only supports bufferlen for uri, ie. the equivalent of    '''
    ''' urilen.                                                             '''
    logging.debug('inside _handle_bufferlen')
    uri_bufferlen = ''
    if sticky_buffer_flag:
        if context_flags.get_flag() == 'U':
            uri_bufferlen = _handle_urilen(value)
        else:
            logging.warning('Snort option "bufferlen" only supported with URI sticky buffer. Omitting.')
            return None
    else:
        logging.warning('Snort option "bufferlen" only supported with URI sticky buffer. Omitting.')
        return None
    return uri_bufferlen


def _handle_min_max_convert(key, value, opt=None):
    ''' Converts options where it has the <> conversion.         '''
    ''' Assumes num1<=>num2 is equivalent to '<=num2 and >=num1' '''
    logging.debug('inside _handle_min_max_convert')
    pattern = ''
    value = value.replace(' ', '')
    if ('<=>' not in value) and ('<>' not in value):
        if value.isdigit() or value[0] == '-':
            pattern += ' --%s =%s' % (key, value)
        else:
            pattern += ' --%s %s' % (key, value)
        if opt:
            pattern += ',%s' % opt
        pattern += ';'
        return pattern

    if '<=>' in value:
        nums = value.split('<=>')

    elif '<>' in value:
        nums = value.split('<>')

    num_1 = __get_val(nums[0])
    num_2 = __get_val(nums[1])
    num_1 = __arith(num_1, '-')
    num_2 = __arith(num_2, '+')
    if not num_1 or not num_2:
        logging.warning('"%s" cannot convert "%s". Numbers are invalid. Omitting option.' % (key, value))
        return pattern

    if opt:
        pattern += ' --%s >%s,%s; --%s <%s,%s;' % (key, num_1, opt, key, num_2, opt)
    else:
        pattern += ' --%s >%s; --%s <%s;' % (key, num_1, key, num_2)
    return pattern


def _handle_urilen(value):
    ''' Converts urilen -> --data_size <condition>,uri; '''
    ''' Only handles raw uri, not norm option.          '''
    logging.debug('inside _handle_urilen')
    opts = value.split(',')
    if len(opts) > 1:
        if opts[1] == 'norm':
            logging.warning('"urilen" cannot convert "%s". "norm" option not supported. Omitting option.' % value)
            return None
    pattern = _handle_min_max_convert('data_size', value, 'uri')
    return pattern


def _handle_detection_filter(value):
    ''' Converts detection_filter -> --rate and --track   '''
    ''' Syntax: detection_filter: <track>, <count>, <sec> '''
    logging.debug('inside _handle_detection_filter')
    pattern = ''
    opts = re.compile('track (?P<track>.+),\s*count (?P<count>.+),\s*seconds (?P<sec>.+)')
    match = opts.match(value)
    track = match.group('track')
    count = match.group('count')
    sec = match.group('sec')

    if track == 'by_src':
        track = 'src_ip'
    elif track == 'by_dst':
        track = 'dst_ip'
    pattern += ' --rate %s,%s; --track %s;' % (count, sec, track)
    return pattern


def _handle_direct_trans(key, value):
    ''' Handles direct translations where no handling is needed '''
    logging.debug('inside _handle_direct_trans')
    if key == 'ip_option' and value == 'esec':
        logging.warning('"ip_option" cannot convert "%s". Option not supported.' % value)
        return ''
    if key == 'tos' and '!' in value:
        logging.warning('"tos" cannot convert "%s". Operator not supported.' % value)
        return ''
    if key == 'flags':
        value = value.replace('C', '1').replace('E', '2')
    if value == '':
        return ' --%s;' % key
    return ' --%s %s;' % (key, value)


def _handle_isdataat(value):
    ''' Converts isdataat -> --data_at <num>;                            '''
    ''' For negative option, can use --data_size < <value>               '''
    ''' 1. Cannot convert negative option if 'relative' modifier is set. '''
    ''' 2. Cannot handle non-rawbytes. warn?                             '''
    logging.debug('inside _handle_isdataat')
    opts = value.replace('rawbytes', '')
    opts = opts.replace(' ', '').split(',')
    val = opts[0]
    neg = False
    if '!' in val:
        neg = True
        val = opts[0][1:]

    ret_val = __get_val(val)
    if not ret_val:
        logging.error('"isdataat" cannot convert register %s. No register found.' % value)
        return False

    if neg:
        if len(opts) > 1:
            logging.error('"isdataat" cannot convert negative check. Option not supported.')
            return False
        if ret_val[1] == 'reg':
            logging.error(
                '"isdataat" cannot convert negative check. Registers cannot be used for "--data_size" option.')
            return False
        if ret_val[0] == 1:
            return ' --data size 0;'
        return ' --data_size <%s;' % ret_val[0]

    pattern = ' --data_at %s' % ret_val[0]
    if len(opts) > 1:
        pattern += ',%s' % opts[1]
    pattern += ';'
    return pattern


def _handle_service(value):
    ''' Convert service -> --service <service>;  (snort3 only)  '''
    ''' Syntax: service: <service_1>, <service_2>...;           '''
    ''' Must override all services found.                       '''
    ''' Cannot handle multiple services.                        '''
    logging.debug('inside _handle_service')
    if ',' in value:
        logging.warning('"service" cannot convert %s. Too many services. Omitting option.' % value)
        return None
    value = value.replace(' ', '')
    service_priority.set_high_service(value)
    return None


def _handle_metadata(value):
    ''' Extracts service from metadata (snort 2 only)  '''
    ''' Must override all services found.              '''
    ''' Cannot handle multiple services.               '''
    logging.debug('inside _handle_metadata')
    if 'service ' not in value:
        # do not need to further parse metadata, just return None
        return None
    opts = re.findall(r'service ([^ ,;]+)', value)
    if len(opts) > 1:
        logging.warning('"service" cannot convert %s. Too many services. Omitting option.' % opts)
        return None
    service_priority.set_high_service(opts[0])
    return None


def _handle_ttl(value):
    ''' Converts ttl -> ip.ttl                    '''
    ''' Syntax: ttl: [<, >, =, <=, >=] <number>;  '''
    ''' Syntax: ttl: [number]-[number];  (range)  '''
    logging.debug('inside _handle_ttl')
    value = value.replace(' ', '')
    if '-' in value:
        if '-' == value[0]:
            pattern = ' --ip.ttl <=%s;' % value[1:]
        elif '-' == value[-1]:
            pattern = ' --ip.ttl >=%s;' % value[:-1]
        else:
            nums = value.split('-')
            pattern = ' --ip.ttl >=%s; --ip.ttl <=%s;' % (nums[0], nums[1])
        return pattern
    pattern = _handle_min_max_convert('ip.ttl', value)
    return pattern


def _handle_header_opt_list(opt_list, opt_type):
    ''' Parses rule header ports and ip addresses list and extracts policy variable. '''
    ''' Converts possible policy variables to --service if possible.                 '''
    ''' Removes policy variables from list. (FGT does not handle)                    '''
    f_services = []
    known_policy_vars = []
    if opt_type == 'addr':
        known_policy_vars = ['$DNS_SERVERS', '$TELNET_SERVERS', '$HTTP_SERVERS', '$SMTP_SERVERS']
    elif opt_type == 'port':
        known_policy_vars = ['$HTTP_PORTS', '$FTP_PORTS', '$SIP_PORTS', '$SMTP_PORTS']

    if opt_list == 'any':
        return (-1, -1)

    # if only one element in opt_list, remove brackets
    if ',' not in opt_list:
        opt_list = opt_list.replace('[', '')
        opt_list = opt_list.replace(']', '')
    elif opt_type == 'port':
        opt_list = opt_list.replace(']', '}')
        opt_list = opt_list.replace('[', '{')

    opt_policy_vars = re.findall(r'(\$\w+)', opt_list)

    # If no policy vars found, just return as is and remove brackets if necessary
    if len(opt_policy_vars) == 0:
        return (opt_list, -1)

    # If only one element in opt_list and it is a policy var
    if ',' not in opt_list and len(opt_policy_vars) == 1:
        if opt_policy_vars[0] in known_policy_vars:
            f_services.append(opt_policy_vars[0].split('_')[0][1:].lower())
        return (-1, f_services)

    for policy_var in opt_policy_vars:
            opt_list = re.sub('(,\\%s|\\%s,)' % (policy_var, policy_var), '', opt_list)
            if policy_var in known_policy_vars:
                f_services.append(policy_var.split("_")[0][1:].lower())

    if opt_list in set(['[]', '{}']):
        return (-1, f_services)

    return (opt_list, f_services)


def _handle_header(header):
    ''' Handles the header of a Snort rule                                  '''
    ''' alert protocol src_network src_port direction dst_network dst_port  '''
    ''' and returns the converted IPS keywords for the body.                '''
    global bi_direction_flag
    global alert_file_flag
    header = re.sub(r' +', ' ', header)
    m = re.findall(r'(\[ ?[^\]]+ [^\]]+ ?\])', header)
    if m:
        for i in m:
            header = re.sub(r'(\[ ?[^\]]+ [^\]]+ ?\])', i.replace(' ', ''), header, count=1)
    s_header = header.strip().split(' ')
    f_header = {'service': []}
    key = ['protocol', 'src_addr', 'src_port', 'flow', 'dst_addr', 'dst_port']
    if (len(s_header) > 6) or (len(s_header) == 0):
        logging.error('Invalid header!')
        return (False, header)

    for i, entry in enumerate(s_header):
        # handle protocol:
        if i == 0:
            if entry == 'file':
                f_header[key[i]] = 'tcp'
                alert_file_flag = True
            elif entry == 'http':
                f_header[key[i]] = 'tcp'
                f_header['service'] = 'http'
            elif entry in ['tcp', 'udp', 'icmp']:
                f_header[key[i]] = s_header[i]
            elif entry in ['any', 'ip']:
                logging.warning('Snort protocol "%s": "--protocol" option is omitted.' % entry)
            else:
                logging.warning('Protocol "%s" cannot be converted' % entry)

        # handle direction and check first sign of incorrect parsing:
        elif i == 3:
            if entry == '<>':
                f_header[key[i]] = 'bi_direction'
                bi_direction_flag = True
            elif entry != '->':
                logging.error('Header is parsed wrong!')
                return (False, header)

        # handle addresses and ports:
        else:
            (parsed_opt, services) = _handle_header_opt_list(entry, key[i].split("_")[1])
            if parsed_opt != -1:
                if '{' in parsed_opt:
                    logging.warning('Cannot convert list of ports. Option not supported.')
                    # tcp.dst_port/src_port is not supported for now. Uncomment after it is supported.
                    # f_header['tcp.%s in' % key[i]] = parsed_opt
                else:
                    f_header[key[i]] = parsed_opt
            if services != -1:
                f_header['service'] += services

    rule = ''
    for key, value in f_header.items():
        if key == 'service':
            if len(value) == 0:
                continue
            for serv in value:
                rule += " --%s %s;" % (key, serv)
        else:
            rule += " --%s %s;" % (key, value)
    return (True, rule)


def __reset_flags():
    ''' Reset saved state to parse next rule '''
    global content_seen_flag
    global sticky_buffer_flag
    global open_context_flag
    global context_modifier_flag
    global bi_direction_flag
    global alert_file_flag
    global added_context_flag
    global last_seen_option

    content_seen_flag = False
    sticky_buffer_flag = False
    open_context_flag = False
    context_modifier_flag = False
    bi_direction_flag = False
    alert_file_flag = False
    added_context_flag = False
    last_seen_option = ''
    context_flags.reset()
    regs.clear_regs()
    service_priority.reset_service()
    return


def _handle_body(body):
    ''' Handles the body of a Snort rule ( abcd:defg; hijk:lmn,opq; )   '''
    ''' Uses keyword_handler to handle each option keyword parsed       '''
    ''' and returns the converted IPS keywords for the body.            '''
    ''' eg. key = 'hijk', value = 'lmn,opq'                             '''
	
    rule = ''
    snort_body = body
	
    # Semicolon fix: if '; ' is in content or PCRE, this will break the
    # partition early
    # replace '; ' with equivalent ';\x20' if pcre:"something; "; is found
    # ';|20|' if in content, eg. content:"test=ddd; "
    # This may have side effects on something like content:"pcre:\; "
    pcre_semicolon_fix = re.compile('(pcre\:\s*\"[^\"]*)\; (.*)')
    content_semicolon_fix = re.compile('(content\:\s*\"[^\"]*)\; (.*)')
    snort_body_m = pcre_semicolon_fix.search(snort_body)
    while snort_body_m:
        snort_body = pcre_semicolon_fix.sub(r'\1;\x20\2', snort_body)
        snort_body_m = pcre_semicolon_fix.search(snort_body)
    snort_body_m = content_semicolon_fix.search(snort_body)
    while snort_body_m:
        snort_body = content_semicolon_fix.sub(r'\1;|20|\2', snort_body)
        snort_body_m = content_semicolon_fix.search(snort_body)

    # Begin tokenizing snort_body.
    while len(snort_body) > 0:
        # extract each token delimited by ;
        token = snort_body.partition('; ')
        option = token[0].partition(':')
        key = option[0].strip()  # option name, eg. content
        value = option[2].strip()  # value for keyword ( ie. stuff after content: )

        (valid, new_rule) = keyword_handler(key, value)
        if valid:
            rule += new_rule
        else:
            return (False, rule)
        # continue
        snort_body = token[2]

    # if context hasn't been added yet and there was a distance/within that needed it:
    if open_context_flag:
        rule += __check_and_add_context_packet()
    return (True, rule)


def __get_sig_name(rule):
    ''' Automatically generate custom signature name from SID and MSG '''
    msg_re = re.compile(r'msg:\s?"([^;"]+)";')
    sid_re = re.compile(r'sid:\s?(\d+);')
    m = msg_re.search(rule)
    if m:
        msg = m.group(1)
    else:
        msg = ''
    m = sid_re.search(rule)
    if m:
        sid = m.group(1)
    else:
        sid = ''

    invalid_chars_in_name = re.compile(r'[^a-zA-Z0-9 _-]')
    msg = re.sub(invalid_chars_in_name, '', msg)
    sig_name = 'SID' + sid + '-' + msg
    sig_name = sig_name[:63].strip().replace(' ', '.')  # truncate sig name
    return sig_name


def process_snort(rule):
    ''' Process each rule divided into header and body portions    '''
    ''' If any errors lead to signature conversion error,          '''
    ''' returns False, ''                                          '''
    ''' Else returns True, converted_fgt_sig                       '''
    global sticky_buffer_flag
    snort_sig = re.compile('(?P<header>.+?)\((?P<body>.+);\s*\)')
    m = snort_sig.match(rule)
    fgt_sig = ''
    sig_name = ''
    if m:
        (valid, fgt_sig_head) = _handle_header(m.group('header'))
        if not valid:
            return (False, fgt_sig, sig_name)
        if alert_file_flag:
            # Snort3 - add --context file; to all content/pcre found
            context_flags.set_flag('F')
            sticky_buffer_flag = True
        sig_name = __get_sig_name(m.group('body'))
        (valid, fgt_sig_body) = _handle_body(m.group('body'))
        if not valid:
            return (False, fgt_sig, sig_name)

        fgt_sig = __single_option_check('F-SBID( --name "' + sig_name + '";' + fgt_sig_head + fgt_sig_body + ' )')

        return (True, fgt_sig, sig_name)
    else:
        logging.error('Error parsing Snort rule format.')
        return (False, fgt_sig, sig_name)


def __single_option_check(rule):
    ''' Possibly added multiple options that cannot be duplicated in a sig
    when parsing Snort rule. For these keywords where only 1 can exist in a
    sig, check and remove duplicates.
    If they are different , eg. --service http; --service smtp;
      then remove the service option
    If they are the same, eg, --service sip; --service sip; only keep 1.

    Additionally, check for global service priority and add it if it exists.
    '''
    single_options = ['protocol', 'service']
    serv = service_priority.get_service()
    if serv:
        # service priority: delete all service and add the saved priority
        pcre_del_option = re.compile('(\s--service\s[a-z]+\;)')
        rule = pcre_del_option.sub('', rule)
        single_options.remove('service')
        pcre_add_service = re.compile('(.*\;)\s*(\s+\))')
        rule = pcre_add_service.sub('\\1' + serv + '\\2', rule)

    for option in single_options:
        pcre_match_option = re.compile('\s--' + option + '\s([a-z]+)\;')
        option_match = pcre_match_option.findall(rule)
        if option_match:
            if len(set(option_match)) > 1:
                # different - remove all occurrences of this keyword from created sig
                pcre_del_option = re.compile('(\s--' + option + '\s[a-z]+\;)')
                rule = pcre_del_option.sub('', rule)
                logging.debug('Duplicate option %s. Deleting.', option)
            elif len(option_match) > 1:
                # duplicate but they are the same, just remove the extras
                pcre_del_option = re.compile('(\s--' + option + '\s[a-z]+\;)')
                remove_count = len(option_match) - 1
                rule = pcre_del_option.sub('', rule, count=remove_count)

    return rule


def __optimize_post_processing(rule, fgt_sig):
    ''' After process_snort, some rules cannot be parsed correctly in the 1st go in cases
    where Snort2/Snort3 difference is not encountered until later in the sig when the
    assumption has been made.
    The biggest chunk here handles file_data; and pkt_data; misordering in certain Snort2
    rules. See file_data test cases in Unit Test. '''
    ''' Further optimize for 'parsed_type' IPS keyword (equivalent of http_method with
    content:"GET" or "POST") '''
    if 'file_data;' in rule or 'pkt_data;' in rule:
        if last_seen_option not in ['content', 'pcre', 'file_data', 'pkt_data', 'uricontent']:
            # the remainder being last seen means it was a Snort2 rule
            # if --context file or packet is the first context in rule, and another context is seen:
            first_context = re.compile('\s--context\s([a-z_]+)\;')
            m_context = first_context.search(fgt_sig)
            if m_context:
                if m_context.group(1) in ['file', 'packet']:
                    # First context was a file_data; or pkt_data; and this was Snort2, incorrectly parsed
                    # Fix by re-parsing as Snort2
                    logging.debug('Abnormal rule found. Reparsing as Snort2')
                    global content_seen_flag
                    global force_snort_2
                    __reset_flags()
                    # Force to parse as Snort2
                    content_seen_flag = True
                    force_snort_2 = True
                    (valid, fgt_sig, sig_name) = process_snort(rule)
                    force_snort_2 = False
        # Remove extra --context if there are 2 for a pattern
        # - caused by file_data/pkt_data in Snort 2 syntax in the following case:
        #   content:"insideuri"; http_uri; file_data; content:"insidefile"; content:"insidebody"; nocase; http_raw_body;
        # (going back and forth from contexts where file_data precedes and the other contexts follow previous content)
        multiple_contexts = re.compile('(\s--context\s(?:file|packet)\;)((?!--pattern|--pcre).)*(--context\s)')
        m_contexts = multiple_contexts.findall(fgt_sig)
        if m_contexts:
            m_contexts_replace = re.compile(
                '(.*)(\s--context\s(?:file|packet)\;)((?:(?!--pattern|--pcre).)*)(--context\s.*)')
            fgt_sig = m_contexts_replace.sub('\\1\\3\\4', fgt_sig)

    if 'http_method;' in rule:  # Sanity check in case someone wanted "GET" in actual URI
        parsed_type = re.compile('(\s--pattern\s\"(?:GET|POST)\"\; --context uri;)(?!\s*--(?:distance|within))')
        method = parsed_type.findall(fgt_sig)
        if len(method) == 1:  # only change sig when only one occurrence is found, just in case
            if 'GET' in method[0]:
                http_type = 'GET'
            else:
                http_type = 'POST'
            fgt_sig = parsed_type.sub(' --parsed_type HTTP_' + http_type + ';', fgt_sig, count=1)

    return fgt_sig


def output_json(outfile, fgt_count, snort_count):
    ''' JSON has been written to json_stream iteratively
    Load as JSON and write out to file '''
    out_json = {}
    stats = {}
    stats.update({'success': fgt_count})
    stats.update({'failure': snort_count - fgt_count})
    out_json.update({'statistics': stats})
    results = json.loads(json_stream.getvalue()[:-3] + ']')  # Remove trailing , from stream to close properly
    out_json.update({'results': results})
    json.dump(out_json, outfile, ensure_ascii=False, indent=4, sort_keys=True)


def write_sig(rule, sig, sig_name, out_file, gui, j):
    try:
        if not gui:
            sig = sig.replace('"', '\\"')
        if not j:
            if sig:
                out_file.write(sig + '\n')
        else:
            current_sig_log = log_stream.getvalue()
            log_stream.truncate(0)
            # Write to stream first, encoded in JSON formatting
            if sig:
                success = True
            else:
                success = False
            messages = []
            log_msgs = current_sig_log.rstrip('\n ').split('\n')
            if log_msgs != ['']:
                for msg in log_msgs:
                    msg_obj = {}
                    (level, c, message) = msg.partition(':')
                    msg_obj.update({"level": level})
                    msg_obj.update({"message": message})
                    messages.append(msg_obj)
            rule_obj = {}
            rule_obj.update({"original": rule})
            rule_obj.update({"converted": sig})
            rule_obj.update({"name": sig_name})
            rule_obj.update({"messages": messages})
            rule_obj.update({"success": success})
            json_obj = json.dumps(rule_obj)
            json_stream.write(json_obj + " , \n")

        return True
    except IOError:
        logging.error("I/O ERROR - Failed writing to output file.")
        return False


def open_files(infile, outfile):
    in_f = None
    out_f = None
    try:
        in_f = open(infile, 'r')
        out_f = open(outfile, 'w')
    except IOError as e:
        print "I/O error({0}): {1}".format(e.errno, e.strerror)
    except TypeError:
        if in_f == None:
            logging.critical("Please provide a valid input file.")
        else:
            logging.critical("Please provide a valid output file.")
    finally:
        return (in_f, out_f)


def __set_logging(debug=False, quiet=False, j=False):
    format = logging.Formatter('%(levelname)s:%(message)s')
    log_level = logging.WARNING
    if debug:  # debug option overrides quiet
        logging.basicConfig(filename='Snort2Fortigate.log', filemode='w', format='%(levelname)s: %(message)s',
                            level=logging.DEBUG)
    elif quiet:
        logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.CRITICAL)
        log_level = logging.CRITICAL
    else:
        logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.WARNING)

    if j:  # Add additional logging handler to write warnings/errors to stream
        string_handler = logging.StreamHandler(stream=log_stream)
        string_handler.setFormatter(format)
        string_handler.setLevel(log_level)
        logging.getLogger().addHandler(string_handler)
        json_stream.write('[')
		
		
'''
The four classes will have to be instantiated here for unit testing to work as 
the process_snort function requires them to work. 
'''		
context_flags = ContextFlags()
regs = Registers()
service_priority = ServicePriority()
keywordhandler = FunctionSwitch()

def test_convert(snort_rule):
    ''' Loop for testing purpose only. 
	''' 
    snort_tag = re.compile('\s*(?P<disabled>#?)\s*alert\s+(?P<rule>.*)')
    m = snort_tag.match(snort_rule)
    if m:
        (valid, fgt_sig, sig_name) = process_snort(m.group('rule'))
        fgt_sig = __optimize_post_processing(m.group('rule'), fgt_sig)
    __reset_flags()
    return valid, fgt_sig

def usage():
    return '''
    -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
    Usage: convert Snort rule into fortinet IPS signature format
    -i <input Snort rule txt>
    -o <output IPS rule txt>, default fortirules.txt
    -h or --help - This Usage
    -q quiet
    -j output rule txt in a json format
    -g output suitable for GUI entry
    -e only convert enabled signatures

    Version : %s
    For all issues regarding the script, please email:
    vulnwatch@fortinet.com
    -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
    ''' % (version)
	
def main():
    ''' Main loop '''
    global snort_count
    global fgt_rule_count
    global disabled_snort_count
    #global service_priority
    #global context_flags
    #global keywordhandler
    #global regs

    parser = argparse.ArgumentParser(description=usage(), formatter_class=argparse.RawTextHelpFormatter, add_help=True)
    parser.add_argument('-i', '--input', dest='input', required=True)
    parser.add_argument('-o', '--output', dest='output', default=output_file)
    parser.add_argument('-q', '--quiet', dest='quiet', action='store_const', const=True, default=print_err_warning)
    parser.add_argument('-j', '--json', dest='json', action='store_const', const=True, default=False)
    parser.add_argument('-g', '--gui', dest='gui', action='store_const', const=True, default=False)
    parser.add_argument('-e', '--enabled-only', dest='ignore_disabled', action='store_const', const=True, default=False)
    parser.add_argument('--debug', dest='debug', action='store_const', const=True, default=debug_log,
                        help=argparse.SUPPRESS)

    args = parser.parse_args()
    __set_logging(debug=args.debug, quiet=args.quiet, j=args.json)

    logging.debug(args)
    in_f, out_f = open_files(args.input, args.output)
    if in_f == None or out_f == None:
        sys.exit(-1)

    #context_flags = ContextFlags()
    #regs = Registers()
    #service_priority = ServicePriority()
    #keywordhandler = FunctionSwitch()
	
    # Do basic check for alert and send to process_snort
    snort_tag = re.compile('\s*(?P<disabled>#?)\s*alert\s+(?P<rule>.*)')
    for line in in_f:
        m = snort_tag.match(line)
        if m:
            logging.debug("Snort sig %d" % snort_count)
            rule = m.group('rule')

            if args.ignore_disabled:
                if len(m.group('disabled')) > 0:
                    logging.debug("Disabled sig (# alert ...)")
                    disabled_snort_count += 1
                    continue

            snort_count += 1
            (valid, fgt_sig, sig_name) = process_snort(rule)
            fgt_sig = __optimize_post_processing(rule, fgt_sig)

            logging.debug(fgt_sig)
            __reset_flags()

            if len(fgt_sig) > rule_maxlen:
                logging.error("Signature max length 1024 exceeded.")
                valid = False

            if not valid:
                write_sig(rule, '', '', out_f, args.gui, args.json)
                continue
            else:
                ok = write_sig(rule, fgt_sig, sig_name, out_f, args.gui, args.json)
                if ok:
                    fgt_rule_count += 1

    if args.json:
        output_json(out_f, fgt_rule_count, snort_count)

    # Final print and cleanup.
    print "\n%s:\nTotal %d from %d Snort rules are converted" \
          % (sys.argv[0], fgt_rule_count, snort_count)
    if args.ignore_disabled:
        print "(%s disabled)\n" % disabled_snort_count
    else:
        print ''
    in_f.close()
    out_f.close()
    json_stream.close()
    log_stream.close()

if __name__ == "__main__":
    main()
