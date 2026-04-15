import re

input_file = ".resolver_report.txt"
output_file = ".ips.txt"
ip_pattern = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

ips = set()

with open(input_file, "r") as infile:
    for line in infile:
        matches = ip_pattern.findall(line)
        ips.update(matches)

with open(output_file, "w") as outfile:
    for ip in sorted(ips):
        outfile.write(ip + "\n")
