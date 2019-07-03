#!/usr/bin/env python

import os
import sys
import getopt
import re

# Declare the globals
Version = '2.3'
print_err_warning = False
FGTRuleMaxLen = 4096

pcreOpt = ['i', 's', 'm', 'x', 'A', 'E', 'G']
keyDrop = ['msg', 'reference', 'rev', 'classtype', 'priority', 'sid', 'gid',
           'metadata', 'fast_pattern', 'http_encode']
keyNotSupport = ['protected_content', 'hash', 'length', 'ftpbounce',
                 'fragbits', 'fragoffset', 'asn1', 'cvs', 'dce_iface',
                 'dce_opnum', 'dce_stub_data', 'gtp_type', 'gtp_info',
                 'gtp_version', 'ssl_state', 'base64_decode',
                 'base64_data', 'sip_method', 'sip_stat_code',
                 'stream_reassemble', 'stream_size', 'logto', 'session',
                 'resp', 'react', 'tag', 'activites', 'activites_by', 'count',
                 'replace', 'modbus_func', 'dnp3_ind']
keyMap = {'content': 'pattern',
          'nocase': 'no_case',
          'isdataat': 'data_at',
          'ttl': 'ip_ttl',
          'tos': 'ip_tos',
          'id': 'ip_id',
          'ipopts': 'ip_option',
          'dsize': 'data_size',
          'flags': 'tcp_flags',
          'window': 'window_size',
          'itype': 'icmp_type',
          'icode': 'icmp_code',
          'icmp_id': 'icmp_id',
          'icmp_seq': 'icmp_seq',
          'rpc': 'rpc_num',
          'sameip': 'same_ip'
          }
protoMap = {'igmp': '2',
            'sctp': '132'}
offsetMap = {'depth': 'within',
             'offset': 'distance'}
tagMap = {'set': 'set',
          'unset': 'clear',
          'isset': 'test',
          'isnotset': 'test,!',
          'toggle': 'toggle',
          'noalert': 'quiet'}
contextH = ['http_cookie', 'http_raw_cookie', 'http_header', 'http_raw_header']
contextB = ['http_stat_code', 'http_stat_msg']
contextU = ['http_method', 'http_uri', 'http_raw_uri']

snortTag = ['alert', '# alert']

snortSig = re.compile('''(\#\s)?alert\s+
                            (?P<proto>[^\s]+)\s+
                            (?P<src>[^\s]+)\s+
                            (?P<srcport>[^\s]+)\s+
                            (?P<dir>[^\s]+)\s+
                            (?P<dst>[^\s]+)\s+
                            (?P<dstport>[^\s]+)\s+
                        \(
                            (?P<body>.+)
                        ;\s*\)''', re.IGNORECASE | re.VERBOSE)

removeKey = lambda l, reg: reg.sub('', l)

def usage():
    print sys.argv[0]
    print """
    -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
    Usage: convert Snort rule into fortinet IPS signature format
    -i <input_filename>
        Input file containing snort rules
        '-' will read from stdin
    -o <output IPS rule txt>
        Output file for foritaget rules
        defaults to fortirules.txt
        '-' will write to stdout
    -h or --help - This Usage text.
    -q quiet
        Suppresses error messages and warnings

    Version : %s
    -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
    """ % (Version)
    sys.exit(1)


def open_file(file, flag):
    try:
        fh = open(file, flag)
    except IOError as e:
        print "I/O error({0}): {1}".format(e.errno, e.strerror)
        usage()
    except TypeError:
        if flag == 'r':
            print "Please provide a valid input file."
        elif flag == 'w':
            print "Please provide a valid output file."
        usage()
    except:
        print "Unexpected error:", sys.exc_info()[0]
        raise
    return fh


# even we convert some --service, better review them with converted ports
def convHeader(proto, src, srcport, Dir, dst, dstport):
    rule = ' --protocol ' + proto + ';'

    if any(i == '$DNS_SERVERS' for i in [src, dst]):
        rule += ' --service DNS;'
    elif any(i == '$TELNET_SERVERS' for i in [src, dst]):
        rule += ' --service TELNET;'
    elif any(i == '$HTTP_PORTS' for i in [srcport, dstport]):
        rule += ' --service HTTP;'
    elif any(i == '$SMTP_PORTS' for i in [srcport, dstport]):
        rule += ' --service SMTP;'
    elif any(i == '$SIP_PORTS' for i in [srcport, dstport]):
        rule += ' --service SIP;'
    elif any(i == '$FTP_PORTS' for i in [srcport, dstport]):
        rule += ' --service FTP;'

    else:
        if ('$' not in src and src.lower() != 'any'):
            rule += ' --src_addr ' + src + ';'
        if ('$' not in dst and dst.lower() != 'any'):
            rule += ' --dst_addr ' + dst + ';'
        if (Dir == '<>' and proto in ['tcp', 'udp']):
            rule += ' --flow bi_direction;'
        (err, tmp) = __handle_portlist(srcport, 'src_port', proto)
        if err:
            if not print_err_warning:
                print "Warning: %s is not supported in port list!"\
                    % (tmp)
            return (True, rule)
        rule += tmp
        (err, tmp) = __handle_portlist(dstport, 'dst_port', proto)
        if err:
            if not print_err_warning:
                print "Warning: %s is not supported in port list!"\
                    % (tmp)
            return (True, rule)
        rule += tmp
    return (False, rule)


def __handle_portlist(p, t, proto):
    rule = ''
    if ('$' not in p and p.lower() != 'any'):
        if any(i in p for i in ['[', ']']):
            p = p.strip('[]')
            if ',' in p:
                if proto not in ['tcp', 'udp']:
                    return (True, proto)
                elif ':' in p:
                    return (True, 'port range')
                else:
                    rule = ' --' + proto + \
                        '.' + t + ' in {' + p + '};'
            else:
                rule = ' --' + t + ' ' + p + ';'
        else:
            rule = ' --' + t + ' ' + p + ';'
    return (False, rule)


def convBody(body, ref):

    rule = ref
    (lastkey, extract) = ('', {})
    (Bflag, Fflag, Hflag, Pflag, Uflag) = (False, False, False, False, False)

    digit = re.compile(r'-?\d+')
    pcrefix = re.compile(r'pcre:\".*?;\s')
    m = pcrefix.search(body)
    if m:
        body = body.replace('\\; ', '\\;\\s')

    sid = obtain_sid(body)
    msg = obtain_msg(body)
    if ('--protocol ip;' in ref and not 'ip_proto' in body):
        if not print_err_warning:
            debug_print('protocol', 'ip')
        return (1, rule, sid, msg)

    for s in body.split('; '):
        r = s.partition(':')
        key = r[0].strip()
        if key in keyDrop:
            continue
        elif key in keyNotSupport:
            if not print_err_warning:
                debug_print('snort option', key)
            return (1, rule, sid, msg)
        elif key in keyMap.keys():
            (err, tmp) = __handle_keyMap(key, r[2], extract)
            if err:
                if not print_err_warning:
                    debug_print(tmp, r[2].strip())
                return (1, rule, sid, msg)

            rule += tmp

            if key == 'content':
                if Bflag:
                    rule += ' --context body;'
                elif Fflag:
                    rule += ' --context file;'
                elif Hflag:
                    rule += ' --context header;'
                elif Pflag:
                    rule += ' --context packet;'
                elif Uflag:
                    rule += ' --context uri;'
        elif key == 'flowbits':
            (err, tmp) = __handle_flowbits(r[2])
            if err:
                if not print_err_warning:
                    debug_print('flowbits option', tmp)
                return (1, rule, sid, msg)
            rule += tmp
        elif key == 'flow':
            (err, rule) = __handle_flow(rule, r[2], ref)
            if err:
                if not print_err_warning:
                    debug_print('flow option', rule)
                return (1, rule, sid, msg)
        elif key in ['ack', 'seq']:
            rule += ' --' + key + ' ' + r[2].strip() + ';'
        elif key == 'pcre':
            (err, tmp) = __handle_pcre(r[2].strip())
            if err:
                if not print_err_warning:
                    debug_print('pcre', tmp)
                return (1, rule, sid, msg)
            rule += tmp
            element = rule.split('; ')
            if '--context' not in element[-1]:
                if Bflag:
                    rule += ' --context body;'
                elif Fflag:
                    rule += ' --context file;'
                elif Hflag:
                    rule += ' --context header;'
                elif Pflag:
                    rule += ' --context packet;'
                elif Uflag:
                    rule += ' --context uri;'
        elif key == 'byte_jump':
            (err, tmp) = __handle_byte_jump(r[2], extract)
            if err:
                if not print_err_warning:
                    debug_print('byte_jump', tmp)
                return (1, rule, sid, msg)
            rule += tmp
        elif key == 'byte_test':
            (err, tmp) = __handle_byte_test(r[2], extract)
            if err:
                if not print_err_warning:
                    debug_print('byte_test', tmp)
                return (1, rule, sid, msg)
            rule += tmp
        elif key == 'byte_extract':
            (err, tmp, extract) = __handle_byte_extract(r[2], extract)
            if err:
                if not print_err_warning:
                    debug_print('byte_extract', tmp)
                return (1, rule, sid, msg)
            rule += tmp
        elif key == 'ip_proto':
            (err, rule) = __handle_ip_proto(rule, r[2].strip())
            if err:
                if not print_err_warning:
                    debug_print('protocol name', r[2].strip())
                return (1, rule, sid, msg)
        elif key == 'ssl_version':
            (err, tmp) = __handle_ssl_type(rule, r[2].strip())
            if err:
                if not print_err_warning:
                    debug_print('SSL Type', r[2].strip())
                return (1, rule, sid, msg)
            rule += tmp
        elif key == 'uricontent':
            rule += ' --pattern ' + NormalizePattern(r[2]) + '; --context uri;'
        elif key in contextB:
            if is_single_pattern(rule):
                rule = rule.replace(',packet;', ',context;')
            if Hflag:
                rule = unify_context(rule)
            rule += ' --context banner;'
        elif key in contextH:
            if is_single_pattern(rule):
                rule = rule.replace(',packet;', ',context;')
            if any([Fflag, Uflag, Hflag, Bflag]):
                rule = unify_context(rule)
                (Bflag, Fflag, Uflag) = (False, False, False)
            rule += ' --context header;'
            Hflag = True
        elif key in contextU:
            if is_single_pattern(rule):
                rule = rule.replace(',packet;', ',context;')
            if any([Fflag, Uflag, Hflag, Bflag]):
                rule = unify_context(rule)
                (Bflag, Fflag, Uflag) = (False, False, False)
            rule += ' --context uri;'
            Uflag = True
        elif key == 'http_client_body':
            if is_single_pattern(rule):
                rule = rule.replace(',packet;', ',context;')
            if any([Hflag, Uflag, Bflag]):
                rule = unify_context(rule)
                (Hflag, Uflag) = (False, False)
            rule += ' --context body;'
            Bflag = True
        elif key == 'rawbytes':
            if is_single_pattern(rule):
                rule = rule.replace(',packet;', ',context;')
            if any([Fflag, Hflag]):
                rule = unify_context(rule)
            rule += ' --context packet_origin;'
        elif key in ['depth', 'offset', 'distance', 'within']:
            if key in offsetMap:
                k = offsetMap[key]
            else:
                k = key

            m = digit.match(r[2].strip())
            if m:
                v = r[2].strip()
            else:
                if r[2].strip() in extract:
                    v = extract[r[2].strip()]
                else:
                    debug_print(k, r[2].strip())
                    return (1, rule, sid, msg)
            if is_single_pattern(rule):
                if any([Bflag, Fflag, Hflag, Pflag, Uflag]):
                    rule += ' --' + k + ' ' + v + ',context;'
                else:
                    rule += ' --' + k + ' ' + v + ',packet;'
            else:
                rule += ' --' + k + ' ' + v + ';'
        elif key == 'urilen':
            if '<>' in r[2]:
                debug_print('urilen', r[2].strip())
                return (1, rule, sid, msg)
            rule += ' --data_size ' + r[2].strip(',norm') + ',uri;'
        elif key == 'detection_filter':
            rule += __handle_detection_filter(r[2])
        elif key == 'pkt_data':
            Pflag = True
        elif key == 'file_data':
            Fflag = True
        elif key == 'sip_header':
            Hflag = True
        elif key == 'sip_body':
            Bflag = True
        elif key == 'threshold':
            rule += __handle_threshold(r[2])
        else:
            print "Error: unknown snort option '%s'" % (key)
            return (2, rule, sid, msg)
        lastkey = key

    if any(k == lastkey for k in ['content', 'pcre', 'http_header']):
        element = rule.split('; ')
        if Bflag and not '--context' in element[-1]:
            rule += ' --context body;'
        elif Fflag and not '--context' in element[-1]:
            rule += ' --context file;'
        elif Hflag and not '--context' in element[-1]:
            rule += ' --context header;'
        elif Pflag and not '--context' in element[-1]:
            rule += ' --context packet;'
        elif Uflag and not '--context' in element[-1]:
            rule += ' --context uri;'

    '''
    if rule.count(' --context '):
        if (rule.count(' --pattern ') + rule.count(' --pcre ')) != \
                rule.count(' --context '):
            print "SID%s: unexpected unmatched context error." % (sid)'''
    return (0, rule, sid, msg)


def unify_context(ref):
    element = ref.split('; ')
    if '--context' in element[-1]:
        element.pop()
        rule = '; '.join(element) + ';'
    elif '--context' in element[-2] and \
            any(k not in element[-1] for k in ['--pcre', '--pattern']):
        element.pop(-2)
        rule = '; '.join(element)
    elif '--context' in element[-3] and \
            any(k not in element[-1] for k in ['--pcre', '--pattern']) and \
            any(k not in element[-2] for k in ['--pcre', '--pattern']):
        element.pop(-3)
        rule = '; '.join(element)
    elif len(element) > 4 and '--context' in element[-4] and \
            any(k not in element[-1] for k in ['--pcre', '--pattern']) and \
            any(k not in element[-2] for k in ['--pcre', '--pattern']) and \
            any(k not in element[-3] for k in ['--pcre', '--pattern']):
        element.pop(-4)
        rule = '; '.join(element)
    else:
        return ref
    return rule


def is_single_pattern(rule):
    if (rule.count(' --pattern ') == 1 and
        rule.count(' --pcre ') == 0) \
        or (rule.count(' --pattern ') == 0 and
            rule.count(' --pcre ') == 1):
        return True
    return False


def NormalizePattern(p):
    p = p.replace('\\;', '|3B|')
    p = p.replace('\\:', '|3A|')
    return p


def debug_print(k, v):
    print "Warning: " + k + " '%s' is not supported" % (v)


def obtain_sid(s):
    Sid = re.compile(r'sid:(\d+);')
    m = Sid.search(s)
    if m:
        return m.group(1)
    else:
        return ""


def obtain_msg(s):
    Msg = re.compile(r'msg:"([^;"]+)";')
    m = Msg.search(s)
    if m:
        return m.group(1)
    else:
        return ""


def __handle_keyMap(k, V, ref):
    dataat = re.compile(r'\d+(,relative)?$')
    icmpcode = re.compile(r'\d+$')

    if k != 'content':
        v = V.strip()
    else:
        v = NormalizePattern(V)

    if k == 'isdataat':
        v = v.replace(',rawbytes', '')
        m = dataat.match(v)
        if not m:
            r = v.partition(',')
            if r[0] in ref:
                v = v.replace(r[0], ref[r[0]])
            else:
                return (True, k)
    elif k == 'icode':
        m = icmpcode.match(v)
        if not m:
            return(True, k)
    elif k == 'dsize':
        if '<>' in v:
            return(True, k)

    rule = ' --' + keyMap[k]
    if v != '':
        rule += ' ' + v
    rule += ';'
    return (False, rule)


def __handle_flow(r, v, ref):
    rule = r
    for f in v.split(','):
        f = f.strip()
        if (any(i == f for i in ['to_server', 'from_client'])
                and 'bi_direction' not in ref):
            rule += ' --flow from_client;'
        elif (any(i == f for i in ['to_client', 'from_server'])
                and 'bi_direction' not in ref):
            rule += ' --flow from_server;'
        elif f == 'established':
            continue
        elif f == 'stateless':
            rule = reduce(removeKey,
                          [re.compile(r'\s+--service\s+[^;]+;')], rule)
        else:
            if 'bi_direction' in ref:
                return (True, '<> and ' + f)
            return (True, f)
    return (False, rule)


def __handle_flowbits(v):
    tag = re.compile(r'[\w\.-]+')
    s = v.partition(',')
    if s[0].strip() not in tagMap.keys():
        return (True, s[0].strip())

    rule = ' --tag ' + tagMap[s[0].strip()]
    if s[1] == ',':
        m = tag.match(s[2].strip())
        if not m:
            return (True, s[2].strip())
        if s[0].strip() != 'isnotset':
            rule += ','
        rule += s[2].strip()
    rule += ';'
    return (False, rule)


def __handle_pcre(v):
    n = []
    (pcreU, pcreH, pcreB, pcreb, pcreP) = (False, False, False, False, False)

    pcre = re.compile(r'(!?\")(\/.*\/)([\w]*)\"')
    m = pcre.match(v)
    if not m:
        return (True, v)
    expr = m.group(2)
    expr = expr.replace('"', '|22|')

    if m.group(3) != '':
        for op in list(m.group(3)):
            if op not in pcreOpt:
                if op == 'B':
                    pcreP = True
                    continue
                elif any(k == op for k in ['C', 'D', 'H', 'K', 'M']):
                    pcreH = True
                    continue
                elif any(k == op for k in ['I', 'U']):
                    pcreU = True
                    continue
                elif op == 'P':
                    pcreB = True
                    continue
                elif any(k == op for k in ['S', 'Y']):
                    pcreb = True
                    continue
                elif op == 'R':
                    continue
                else:
                    return (True, op)
            n.append(op)
    rule = ' --pcre ' + m.group(1) + expr
    if m.group(3) != '':
        rule += ''.join(n)
    rule += '";'
    if pcreP:
        rule += ' --context packet_origin;'
    elif pcreH:
        rule += ' --context header;'
    elif pcreU:
        rule += ' --context uri;'
    elif pcreB:
        rule += ' --context body;'
    elif pcreb:
        rule += ' --context banner;'
    return (False, rule)


def __handle_byte_jump(v, ref):
    multiplier = re.compile(r'multiplier\s+(\d+)')
    offset = re.compile(r'-?\d+')
    string = re.compile(r',string(,|$|\s)')
    (isStr, n) = (False, [])

    m = string.search(v)
    if m:
        isStr = True

    for i, b in enumerate(v.split(',')):
        b = b.strip()
        if any(k in b for k in ['from_beginning', 'post_offset']):
            return (True, b)
        elif b == 'dce':
            continue
        if i == 0:
            if b not in ['1', '2', '4'] and not isStr:
                return (True, 'bytes value other than 1 2 4')
        elif i == 1:
            m = offset.match(b)
            if not m:
                if b in ref:
                    b = ref[b]
                else:
                    return (True, b)

        m = multiplier.match(b)
        if m:
            n.insert(2, m.group(1))
        else:
            n.append(b)
    return (False, ' --byte_jump ' + ','.join(n) + ';')


def __handle_byte_test(v, ref):
    value = re.compile(r'(0x\d+|-?\d+)')
    offset = re.compile(r'-?\d+')
    string = re.compile(r',string(,|$|\s)')
    (isStr, sign, n) = (False, False, [])

    m = string.search(v)
    if m:
        isStr = True

    for i, b in enumerate(v.split(',')):
        b = b.strip()
        if b == 'dce':
            continue
        if i == 0:
            if b not in ['1', '2', '4'] and not isStr:
                return (True, 'bytes value other than 1 2 4')
        elif i == 1:
            if b == '<=':
                b = '<'
                sign = True
            elif b == '>=':
                b = '>'
                sign = True
            elif b == '!=':
                b = '!'
            elif b == '!&':
                b = '~'
        elif i == 2:
            m = value.match(b)
            if m:
                if sign:
                    if '<=' in v:
                        if '0x' in v:
                            if int(b, 16) + 1 > 4294967295:
                                return (True, 'value too big')
                            b = hex(int(b, 16) + 1)
                        else:
                            if int(b) + 1 > 4294967295:
                                return (True, 'value too big')
                            b = "%s" % (int(b) + 1)
                    else:
                        if '0x' in v:
                            if int(b, 16) - 1 > 4294967295:
                                return (True, 'value too big')
                            b = hex(int(b, 16) - 1)
                        else:
                            if int(b) - 1 > 4294967295:
                                return (True, 'value too big')
                            b = "%s" % (int(b) - 1)
                else:
                    if '0x' in v:
                        if int(b, 16) > 4294967295:
                            return (True, 'value too big')
                    else:
                        if int(b) > 4294967295:
                            return (True, 'value too big')
            else:
                if b in ref:
                    b = ref[b]
                else:
                    return (True, b)
        elif i == 3:
            m = offset.match(b)
            if not m:
                if b in ref:
                    b = ref[b]
                else:
                    return (True, b)
        n.append(b)
    return (False, ' --byte_test ' + ','.join(n) + ';')


def __handle_byte_extract(v, ref):
    (name, n) = ('', [])

    for i, b in enumerate(v.split(',')):
        b = b.strip()
        if any(i in b for i in ['multiplier', 'align']):
            return (True, b, ref)
        if b == 'dce':
            continue
        if i == 2:
            name = b
            if name in ref:
                b = ref[name]
            else:
                b = '$%d' % len(ref)
                ref[name] = b

        n.append(b)
    return (False, ' --extract ' + ','.join(n) + ';', ref)


def __handle_ip_proto(r, v):
    ipproto = re.compile(r'(\w+)')
    strproto = re.compile(r'[a-zA-Z]+')
    numproto = re.compile(r'(\d+)')

    m = ipproto.match(v)
    if not m:
        return (True, r)

    rule = reduce(removeKey,
                  [re.compile(r'\s+--protocol\s+[^;]+;')], r)

    m = numproto.match(v)
    if not m:
        m = strproto.match(v)
        if m:
            v = protoMap[v]
        else:
            return (True, rule)
    rule = ' --protocol ' + v + ';' + rule
    return (False, rule)


def __handle_detection_filter(v):
    rule = ''
    rate = re.compile('''track\s+(?P<track>\w+),\s?
                     count\s+(?P<count>\d+),\s?
                     seconds\s+(?P<sec>\d+)''', re.IGNORECASE | re.VERBOSE)

    m = rate.match(v)
    if m:
        rule += ' --rate ' + \
            m.group('count') + ',' + m.group('sec') + ';'
        if m.group('track') == 'by_src':
            rule += ' --track SRC_IP;'
        else:
            rule += ' --track DST_IP;'
    return rule

def __handle_threshold(v):
    # threshold deprecated in Snort 2.8.5+ but add compatibility for older
    # rulesets
    rule = ''
    threshold = v.strip().split(', ',1);
    limit = 1 if 'limit' in threshold[0].lower() else 0;

    track = re.compile('track\s+(?P<track>\w+)', re.IGNORECASE)
    rate = re.compile('''count\s+(?P<count>\d+),\s?
                     seconds\s+(?P<sec>\d+)''', re.IGNORECASE | re.VERBOSE)

    m = rate.search(v)
    if m:
        rule += ' --rate ' + \
            m.group('count') + ',' + m.group('sec')
        if limit: rule += ',' + 'limit'
        rule += ';'
        t = track.search(v)
        if t:
            if t.group('track') == 'by_src':
                rule += ' --track SRC_IP;'
            else:
                rule += ' --track DST_IP;'
    return rule

def __handle_ssl_type(r,v):
    rule = r
    tmp = ''
    if ('--service ' not in rule):
	    tmp = '--service SSL;'
    for f in v.split(','):
        f = f.strip()
        if f == 'tls1.0':
            tmp =  tmp + ' --parsed_type TLS_V1;'
        elif f == 'tls1.1':
            tmp = tmp + ' --parsed_type TLS_V2;'
        elif f == 'tls1.2':
            tmp = tmp + ' --parsed_type TLS_V3;'
        elif f == 'sslv2':
            tmp = tmp + ' --parsed_type SSL_V2;'
        elif f == 'sslv3':
            tmp = tmp + ' --parsed_type SSL_V3;'
        else:
		    return (True, rule)
    return (False, tmp)

def main():

    if len(sys.argv) == 1:
        usage()

    try:
        cmd_opts = "hi:o:q"
        opts, args = getopt.getopt(sys.argv[1:], cmd_opts, ["help"])
    except getopt.GetoptError:
        usage()

    input_file = None
    output_file = 'fortirules.txt'

    for opt in opts:
        if opt[0] == "-i":
            input_file = opt[1]
        elif opt[0] == "-o":
            output_file = opt[1]
        elif opt[0] in ("-h", "--help"):
            usage()
        elif opt[0] == "-q":
            print_err_warning = True
        else:
            usage()

    ifh = open_file(input_file, 'r') if input_file != '-' else sys.stdin
    ofh = open_file(output_file, 'w') if output_file != '-' else sys.stdout
    convert(ifh, ofh)
    if ifh != sys.stdin:
        ifh.close()
    if ofh != sys.stdout:
        ofh.close()

def convert(ifh, ofh):
    SnortRuleCount = 0
    FGTRuleCount = 0
    for line in ifh:
        if any(map(line.startswith, snortTag)):
            SnortRuleCount += 1
            m = snortSig.match(line)
            if m:
                (err, fgtRule) = convHeader(m.group('proto'), m.group('src'),
                                            m.group('srcport'), m.group('dir'),
                                            m.group('dst'), m.group('dstport'))
                if err:
                    continue

                (err, fgtRule, sid, msg) = convBody(m.group('body'), fgtRule)

                if err == 0:
                    sigName = 'SID' + sid + '-' + msg.replace('"', '')
                    sigName = sigName[:64].strip().replace(' ','.')

                    fgtRule = 'F-SBID( --name "'+ sigName + '";' + fgtRule + ' )'

                    if len(fgtRule) >= FGTRuleMaxLen:
                        print "SID %s: converted FGT rule overflows" % (sid)
                    else:
                        FGTRuleCount += 1
                        ofh.write(fgtRule + '\n')
                elif err == 1:
                    if not print_err_warning:
                        print "SID %s: snort option not support, skipped" % (sid)
                else:
                    print "unexpected error in SID %s" % (sid)
    if ofh != sys.stdout:
        print "\nTotal %d from %d Snort rules are converted" \
            % (FGTRuleCount, SnortRuleCount)

if __name__ == '__main__':
    # Main program starts
    main()
