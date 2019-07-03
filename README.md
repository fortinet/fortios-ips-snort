# Snort 2 Fortigate
A simple script to convert (Snort)[https://snort.org] IPS signatures to FortiGate custom IPS signature syntax.

# Usage
Convert Snort rule into fortinet IPS signature format

`-i <input_filename>`

* Input file containing snort rules
* `-` will read from stdin

`-o <output_filename>`

* Output file for fortigate rules
* defaults to fortirules.txt
* `-` will write to stdout

`-h` or `--help`

* Show usage

`-q` quiet

* suppresses error messages and warnings

# Running Tests

`./test/test_snort2fortigate.py` will run unit tests.
