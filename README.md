# Snort 2 FortiGate
```
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
    Usage: convert Snort rule into fortinet IPS signature format
    -i <input Snort rule txt>
    -o <output IPS rule txt>, default fortirules.txt
    -h or --help - This Usage
    -q quiet
    -j output rule txt in a json format
    -g output suitable for GUI entry
    -e only convert enabled signatures
    --no-all skip result for invalid lines in file
    --sig-max-len maximum length of converted IPS sig
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
```
The Snort2Fortigate script provides a best-effort translation of Snort rules into FortiGate IPS Custom Signatures.

### Usage

#### Input
- `-i [file]` or `--input [file]` (Required)
A text file of Snort rules.
Snort2 and Snort3 syntax are both accepted. See [Supported Options](#Supported_Options) for the full list of options we can convert at this time.
Snort rules that are commented out (`# alert tcp...`) are also converted by default. This behaviour can be changed with option `--enabled-only` or `-e`.

#### Output
- `-o [file]` or `--output [file]`
Defaults to `fortirules.txt`.
A text file of IPS custom signatures, quotes-escaped to be usable in the CLI.
Alternatively, use the provided options to generate without escaped quotes (`-g`for use in GUI) and in JSON format with `-j`.
JSON output format, for each parsed rule:
```
"converted": "The converted IPS signature",
"messages": [
    {
        "level": "WARNING or ERROR",
        "message": "Reason for failure."
    }
],
"name": "Name of the converted signature (also present in the signature itself)",
"original": "The original Snort rule",
"success": true if a signature was converted at all, or false if there is an ERROR and the rule is skipped
```
Additionally, the JSON output aggregates count of converted signatures:
```
"statistics": {
    "failure": 1,
    "success": 3
}
```

#### Additional Options
- `-q` or `--quiet`
Suppress warnings and errors.
- `-e` or `--enabled-only`
By default, all Snort rules found in the file are converted.
Set this option to *not* convert Snort rules that are commented out with a single `#`, eg. rules beginning with `# alert ...`.
- `--no-all`
Set this option to ignore lines that do not begin with a rule action.
Current supported rule actions: `alert, log, pass, drop, reject, sdrop`.

### Logging
Unsupported or unrecognized options are logged as a warning and the rest of the signature is still generated. Use these signatures with discretion.
Unacceptable errors in parsing the Snort syntax are logged as ERROR and the rule is skipped.
The total number of converted IPS rules is printed:
`Total 6 from 7 Snort rules are converted.`
See [Known Issues](#Known_Issues) for common conversion issues.

### Supported Options

| Snort Option | FGT Conversion | Notes |
|---|---|---|
| `content` | `--pattern` | Snort3 content modifiers as suboptions accepted |
| `pcre` | `--pcre`| |
| `nocase` | `--no_case` | |
| `distance` | `--distance` | |
| `within` | `--within` | |
| `depth` | `--within num,context` | |
| `offset` | `--distance num,context` | |
| `file_data` | `--context file` | |
| `http_client_body` | `--context body` | |
| `http_cookie` | `--context header` | |
| `http_header` | `--context header` | |
| `http_method` | `--context uri` | When matching for "GET" or "POST" this is converted to `--parsed_type HTTP_GET` (or `_POST`) |
| `http_raw_cookie` | `--context header` | |
| `http_raw_header` | `--context header` | |
| `http_raw_request` | `--context uri` | |
| `http_raw_status` | `--context banner` | |
| `http_raw_uri` | `--context uri` | |
| `http_stat_code` | `--context banner` | |
| `http_stat_msg`| `--context banner` | |
| `http_uri` | `--context uri` | |
| `http_user_agent` | `--context header` | |
| `uricontent` | `--context uri` | |
| `pkt_data` | `--context packet` | |
| `raw_data` | `--context packet_origin` | |
| `rawbytes` | `--context packet_origin` | |
| `sip_body` | `--context body` | `--service sip` is added to the rule |
| `sip_header` | `--context header` | `--service sip` is added to the rule |
| `sip_method` | `--context banner` | `--service sip` is added to the rule |
| `sip_stat_code` | `--context banner` | `--service sip` is added to the rule  |
| `dsize` | `--data_size` | Does not support `norm` modifier |
| `bufferlen` | `--data_size num,uri` | Only when used inside `http_uri` sticky buffer (Snort 3)  |
| `urilen` | `--data_size num,uri` | |
| `isdataat` | `--data_at` | |
| `ssl_version` | `--parsed_type` | |
| `service` | `--service` | Only in Snort3. Can only handle **one** service <br> In Snort2, service is in `metadata` |
| `sameip` | `--same_ip` | |
| `id` | `ip_id` | |
| `ip proto` | `--protocol` or `--ip[offset]` | If no operators present, `--protocol` is used <br> If operators are present `--ip[offset]` is used. |
| `ipopts` | `--ip_option` | IP option `esec` is not supported |
| `tos` | `--ip_tos` | `!` operator is not supported |
| `ttl` | `--ip.ttl` | |
| `icmp_seq` | `--icmp_seq` | |
| `icmp_id` | `--icmp_id` | |
| `icode` | `--icmp.code` | |
| `itype` | `--icmp.type` | |
| `flow` | `--flow` | Only support `to_client`, `to_server`, `from_client`, `from_server`. |
| `seq` | `--seq` | |
| `ack` | `--ack` | |
| `flags` | `--tcp_flags` | |
| `window` | `--window_size` |
| `flowbits` | `--tag cmd,tag_name` | Support commands `set`, `isset`, `isnotset`, `noalert`, and `toggle` only. <Br>`group_name` is not supported |
| `byte_extract` | `--extract ` | Does not support `dce`, `bitmasks`, and `multiplier` modifiers. Extracts to a register instead of variables (see Issues). |
| `byte_jump` | `--byte_jump` | Does not support `dce`, `bitmasks`, `from_end`, and `post_offset` modifiers. |
| `byte_test` | `--byte_test` | Does not support `dce` and `bitmask` modifiers. <Br>Does not support `!&` and `!^` operators. <Br>Can only test against 1,2,4 bytes. |
| `detection_filter` | `--rate count,sec --track filter` | |


### Known Issues
- Option `fast_pattern` does not have an IPS signature equivalent. IPS signatures are optimized by the engine for fast matching. **This option is skipped silently.**
- Snort variables (extracted by byte_extract in the same rule) are converted to registers to use within IPS signatures. IPS engine supports up to 8 registers at this time ($0-$7).
- For rules applying to **more than one** 'service' (metadata service (Snort2) or the 'service' keyword in Snort3), the resulting IPS signature will not include the service option as IPS signatures do not support having more than one service keyword per signature.
- IPS signatures do not support matching by hashes `md5`, `sha256`, or `sha512`.
- Content modifiers `distance` and `within` in Snort are to be used *only* after a preceding match in the same buffer. Otherwise, `depth` and `offset` should be used from the beginning of the buffer if there is no previous match.
- Keywords `dsize`, `icode`, `itype`, `ip_proto`, `urilen`, and `byte_test` cannot directly convert `<=`, `>=` operators. To mitigate this issue, the value is added/subtracted by 1 to complete the translation. This may result in failed conversions when overflow occurs during the operation.
- In the Snort rule headers, policy variables (eg. $OFFICE_NET) cannot be translated to its IP address as each environment is different.
- Custom signatures currently do not support multiple ports, eg. `tcp any [80,8080]...`. The converted signature will omit the list of ports (with warning).

### Running Tests
Some test cases of sample Snort signatures and the equivalent valid IPS output are included.
To run unit tests, use:
`./test/test_snort2fortigate.py`

### Tested Versions
Python 3.10.12
Python 3.5.10
Python 3.4.10

### Support
Fortinet-provided scripts in this and other GitHub projects do not fall under the regular Fortinet technical support scope and are not supported by FortiCare Support Services. For direct issues, please refer to the Issues tab of this GitHub project. For other questions related to this project, contact github@fortinet.com.

### License
[License](https://github.com/fortinet/fortios-ips-snort/blob/master/LICENSE) © Fortinet Technologies. All rights reserved.
