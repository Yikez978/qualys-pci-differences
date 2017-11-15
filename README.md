# qualys-pci-differences
reports on the count of vulnerabilities discovered or remediated between 2 PCI scans based on CVSS Base scores

this might not work on any other Qualys scan beacuse the way I coded the row count (very lazy, but if I need to change it I will...eventually)

'-D', '--Debug', help='Debug Mode assists in determining issues being raised by the script.', action='store_true'
'-L', '--lastScan', help='last months scan'
'-N', '--newScan', help='new months scan'
'-M', '--metricsFile', help='name of new metrics file'
'-R', '--reportDate', help='month and year of the report
