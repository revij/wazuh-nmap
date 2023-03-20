################################
### Python Script to Run Network Scans and append results to Wazuh Active Responses Log
### Requirements:
###     NMAP installed in Agent
###     python-nmap (https://pypi.org/project/python-nmap/)
### Replace the Array "subnets" with the subnets to scan from this agent.
### Do NOT include subnets with a network firewall in the path of the agent and the subnet.
################################
import nmap
import time
import json

nm = nmap.PortScanner()
# Read subnets to scan from file
with open('subnets.txt') as f:
    subnets = [line.strip() for line in f.readlines()]
# Define the ports to scan
ports = [3389, 3390, 5985]

for subnet in subnets:
    print(f'Scanning subnet: {subnet}')
    nm.scan(subnet, arguments=f'-sS -p {",".join(str(port) for port in ports)}')
    for host in nm.all_hosts():
        print(f'Scanning host: {host}')
        json_output = {'nmap_host': host}
        for proto in nm[host].all_protocols():
            if proto != 'tcp':
                continue
            for port in nm[host][proto]:
                if int(port) not in ports:
                    continue
                print(f'Scanning port: {port}')
                hostname = ""
                json_output['nmap_protocol'] = proto
                json_output['nmap_port'] = port
                for h in nm[host]['hostnames']:
                    hostname = h['name']
                    json_output['nmap_hostname'] = hostname
                    hostname_type = h['type']
                    json_output['nmap_hostname_type'] = hostname_type
                json_output['nmap_port_name'] = nm[host][proto][port]['name']
                json_output['nmap_port_state'] = nm[host][proto][port]['state']
                json_output['nmap_port_product'] = nm[host][proto][port]['product']
                json_output['nmap_port_extrainfo'] = nm[host][proto][port]['extrainfo']
                json_output['nmap_port_reason'] = nm[host][proto][port]['reason']
                json_output['nmap_port_version'] = nm[host][proto][port]['version']
                json_output['nmap_port_conf'] = nm[host][proto][port]['conf']
                json_output['nmap_port_cpe'] = nm[host][proto][port]['cpe']
                with open('/var/ossec/logs/active-responses.log', 'a') as active_response_log:
                    active_response_log.write(json.dumps(json_output))
                    active_response_log.write('\n')
                time.sleep(2)
