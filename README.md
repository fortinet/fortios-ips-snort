# Snort 2 FortiGate
A simple script to convert [Snort](https://snort.org) IPS signatures to FortiGate custom IPS signature syntax.

# Python Version
Tested with Python version 2.7.

# Usage
Convert Snort rules into Fortinet IPS signature format:

`python snort2fortigate.py -i snort_rules.txt -o fortigate_rules.txt`

**Arguments:**

`-i <input_filename>`

* Input file containing snort rules.
* `-` will read from `stdin`.

`-o <output_filename>`

* Output file for FortiGate rules.
* Defaults to fortirules.txt.
* `-` will write to `stdout`.

`-h` or `--help`

* Show usage.

`-q` or `--quiet`

* Suppress error messages and warnings.

# Running Tests

To run unit tests, use:

`./test/test_snort2fortigate.py`

# Support
Fortinet-provided scripts in this and other GitHub projects do not fall under the regular Fortinet technical support scope and are not supported by FortiCare Support Services.
For direct issues, please refer to the [Issues](https://github.com/fortinet/fortios-ips-snort/issues) tab of this GitHub project.
For other questions related to this project, contact [github@fortinet.com](mailto:github@fortinet.com).

## License
[License](https://github.com/fortinet/fortios-ips-snort/blob/master/LICENSE) © Fortinet Technologies. All rights reserved.
