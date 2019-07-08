# Snort 2 Fortigate
A simple script to convert [Snort](https://snort.org) IPS signatures to FortiGate custom IPS signature syntax.

# Usage
Convert Snort rules into Fortinet IPS signature format

`-i <input_filename>`

* Input file containing snort rules
* `-` will read from stdin

`-o <output_filename>`

* Output file for FortiGate rules
* Defaults to fortirules.txt
* `-` will write to stdout

`-h` or `--help`

* Show usage

`-q` quiet

* Suppresses error messages and warnings

# Running Tests

`./test/test_snort2fortigate.py` will run unit tests.

# Support
Fortinet-provided scripts in this and other GitHub projects do not fall under the regular Fortinet technical support scope and are not supported by FortiCare Support Services.
For direct issues, please refer to the [Issues](https://github.com/fortinet/fortios-ips-snort/issues) tab of this GitHub project.
For other questions related to this project, contact [github@fortinet.com](mailto:github@fortinet.com).

## License
[License](https://github.com/fortinet/fortios-ips-snort/blob/master/LICENSE) © Fortinet Technologies. All rights reserved.
