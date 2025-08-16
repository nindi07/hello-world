import re
import ipaddress

def cidr_to_wildcard_mask(cidr_notation):
    """
    Converts a CIDR notation (e.g., 192.168.1.0/24) to IP address and wildcard mask.
    This function is currently not directly used by convert_junos_term_to_cisco_rules,
    which uses junos_cidr_to_cisco_wildcard. Kept for reference or future use.
    """
    try:
        network = ipaddress.ip_network(cidr_notation, strict=False)
        ip_address = str(network.network_address)
        
        # Calculate wildcard mask: hostmask is the inverse of the netmask
        hostmask_int = int(network.hostmask)
        wildcard_mask = str(ipaddress.ip_address(hostmask_int))
        
        return ip_address, wildcard_mask
    except ValueError:
        return None, None # Invalid CIDR notation

# Data structures to hold parsed config
class JunosTerm:
    def __init__(self, name):
        self.name = name
        self.from_conditions = {
            'source-address': [],
            'destination-address': [],
            'protocol': None, # Will store string like 'tcp', 'udp'
            'source-port': [], # List of ports (strings)
            'destination-port': [] # List of ports (strings)
        }
        self.then_actions = [] # List of actions (strings, e.g., ['accept', 'log'])

    def __repr__(self):
        return f"Term(name='{self.name}', from={self.from_conditions}, then={self.then_actions})"

class JunosFilter:
    def __init__(self, name):
        self.name = name
        self.terms = [] # CHANGED TO A LIST to preserve order
        self.term_map = {} # NEW: Map term name to the JunosTerm object for quick lookup/update

    def __repr__(self):
        # Modify repr to show term names from the list in order
        return f"Filter(name='{self.name}', terms={[term.name for term in self.terms]})"

def parse_junos_config(lines):
    """
    Parses Junos firewall filter configuration lines into structured Python objects,
    preserving the order of terms.
    """
    filters = {}
    current_filter_name = None
    current_term = None # Reference to the currently active JunosTerm object

    filter_start_re = re.compile(r'set\s+firewall\s+family\s+inet\s+filter\s+(\S+)')
    term_start_re = re.compile(r'set\s+firewall\s+family\s+inet\s+filter\s+\S+\s+term\s+(\S+)')
    
    # Regexes for 'from' and 'then' conditions, made more flexible to correctly capture parts
    # Using search instead of match for internal lines as they don't necessarily start at line beginning
    from_source_re = re.compile(r'.*from\s+source-address\s+(\S+)')
    from_dest_re = re.compile(r'.*from\s+destination-address\s+(\S+)')
    from_protocol_re = re.compile(r'.*from\s+protocol\s+(\S+)')
    from_dest_port_re = re.compile(r'.*from\s+destination-port\s+([\w\s\[\]]+)')
    from_source_port_re = re.compile(r'.*from\s+source-port\s+([\w\s\[\]]+)')
    then_action_re = re.compile(r'.*then\s+(\S+)')


    for line in lines:
        line = line.strip()
        if not line or not line.startswith("set"): continue

        # Check for filter start
        filter_match = filter_start_re.match(line)
        if filter_match:
            current_filter_name = filter_match.group(1)
            if current_filter_name not in filters:
                filters[current_filter_name] = JunosFilter(current_filter_name)
            current_term = None # Reset term context when a new filter is found

        # Check for term start/continuation
        # We need to correctly identify the term this line belongs to.
        term_match = term_start_re.match(line)
        if term_match and current_filter_name:
            term_name = term_match.group(1)
            current_filter = filters[current_filter_name]

            # If this term name has not been seen for this filter in this parsing pass,
            # it's a new term declaration. Append it.
            if term_name not in current_filter.term_map:
                new_term = JunosTerm(term_name)
                current_filter.terms.append(new_term)
                current_filter.term_map[term_name] = new_term
                current_term = new_term # Set this as the active term
            else:
                # If the term name has been seen, we're adding conditions to an existing term.
                # Ensure current_term is updated to point to the correct term object.
                current_term = current_filter.term_map[term_name]
        
        # Parse from conditions and then actions IF we are currently within a term context
        if current_term:
            # Use line.strip() to match the full line, not just from the start
            
            if from_source_re.search(line): # Using search instead of match for internal lines
                current_term.from_conditions['source-address'].append(from_source_re.search(line).group(1))
            elif from_dest_re.search(line):
                current_term.from_conditions['destination-address'].append(from_dest_re.search(line).group(1))
            elif from_protocol_re.search(line):
                # Only set protocol if it hasn't been set, or if you allow overwriting (current behavior)
                current_term.from_conditions['protocol'] = from_protocol_re.search(line).group(1).lower()
            elif from_dest_port_re.search(line):
                port_str = from_dest_port_re.search(line).group(1)
                if '[' in port_str and ']' in port_str:
                    ports = re.findall(r'\d+', port_str)
                    current_term.from_conditions['destination-port'].extend(ports)
                else:
                    current_term.from_conditions['destination-port'].append(port_str)
            elif from_source_port_re.search(line):
                port_str = from_source_port_re.search(line).group(1)
                if '[' in port_str and ']' in port_str:
                    ports = re.findall(r'\d+', port_str)
                    current_term.from_conditions['source-port'].extend(ports)
                else:
                    current_term.from_conditions['source-port'].append(port_str)
            
            elif then_action_re.search(line):
                current_term.then_actions.append(then_action_re.search(line).group(1).lower())
            else:
                # Warning for unhandled lines related to the current term
                # Ensure the line is actually part of the current filter/term hierarchy
                if line.startswith(f"set firewall family inet filter {current_filter_name} term {current_term.name}"):
                    print(f"Warning: Unhandled condition or action in term '{current_term.name}' for line: {line}")


    return filters

# Helper to convert Junos CIDR to Cisco IP and wildcard mask
def junos_cidr_to_cisco_wildcard(cidr):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        ip = str(network.network_address)
        netmask = network.netmask
        
        # Calculate wildcard mask: invert the netmask
        wildcard_parts = [str(255 - int(x)) for x in str(netmask).split('.')]
        wildcard = ".".join(wildcard_parts)
        
        # Cisco "host" keyword for /32 (single IP)
        if network.prefixlen == 32:
            return f"host {ip}", "" # Return "host IP" and an empty wildcard
        elif network.prefixlen == 0:
            return "any", "" # Return "any" for 0.0.0.0/0
        else:
            return ip, wildcard
    except ValueError:
        # Fallback for invalid CIDR or non-IP strings (e.g., 'any', 'unspecified-address', 'any/0')
        if cidr.lower() == 'any' or cidr.lower() == 'unspecified-address' or cidr.lower() == 'any/0':
            return "any", ""
        return cidr, "" # Return as is, possibly for keyword 'any' if not handled above


def convert_junos_term_to_cisco_rules(junos_term):
    cisco_rules = []

    action = "permit" if "accept" in junos_term.then_actions else "deny"
    
    # Default protocol to 'ip' if not specified in Junos term
    proto = junos_term.from_conditions.get('protocol', 'ip')
    
    # DEBUG LINE (keep for troubleshooting 'None' if needed)
    # print(f"--- DEBUG (inside convert_junos_term_to_cisco_rules): Protocol for '{junos_term.name}' is '{proto}' ---")
    
    # Process source and destination addresses
    src_ips = junos_term.from_conditions.get('source-address', [])
    dest_ips = junos_term.from_conditions.get('destination-address', [])

    src_ports = junos_term.from_conditions.get('source-port', [])
    dest_ports = junos_term.from_conditions.get('destination-port', [])

    # Determine if 'any' should be used for source/destination IP.
    effective_src_ips = src_ips if src_ips else ['any/0'] # Use a dummy 'any/0' for iteration
    effective_dest_ips = dest_ips if dest_ips else ['any/0'] # Use a dummy 'any/0' for iteration

    # Iterate through all combinations of source IPs, destination IPs, and ports
    for s_ip_cidr in effective_src_ips:
        current_src_ip_val, current_src_wc = junos_cidr_to_cisco_wildcard(s_ip_cidr)
        
        # Clean up 'any/0' to 'any'
        src_part = "any" if current_src_ip_val == "any" else (f"{current_src_ip_val} {current_src_wc}" if current_src_wc else current_src_ip_val)

        for d_ip_cidr in effective_dest_ips:
            current_dest_ip_val, current_dest_wc = junos_cidr_to_cisco_wildcard(d_ip_cidr)
            
            # Clean up 'any/0' to 'any'
            dest_part = "any" if current_dest_ip_val == "any" else (f"{current_dest_ip_val} {current_dest_wc}" if current_dest_wc else current_dest_ip_val)

            # Case 1: No specific ports
            if not src_ports and not dest_ports:
                rule_str = f"{action} {proto} {src_part} {dest_part}"
                cisco_rules.append(rule_str.strip())

            # Case 2: Destination ports specified (most common for Juniper 'port')
            elif dest_ports and not src_ports:
                for port in dest_ports:
                    rule_str = f"{action} {proto} {src_part} {dest_part} eq {port}"
                    cisco_rules.append(rule_str.strip())

            # Case 3: Source ports specified
            elif src_ports and not dest_ports:
                for port in src_ports:
                    rule_str = f"{action} {proto} {src_part} eq {port} {dest_part}"
                    cisco_rules.append(rule_str.strip())
            
            # Case 4: Both source and destination ports specified
            elif src_ports and dest_ports:
                for s_port in src_ports:
                    for d_port in dest_ports:
                        rule_str = f"{action} {proto} {src_part} eq {s_port} {dest_part} eq {d_port}"
                        cisco_rules.append(rule_str.strip())

    return cisco_rules

def convert_all_junos_to_cisco(junos_config_lines):
    """
    Parses all Juniper filter config and converts them to Cisco ACLs,
    preserving the original order of terms and adding remarks.
    """
    parsed_filters = parse_junos_config(junos_config_lines)
    output_lines = []

    # --- DEBUG: Parsed Filters Object (Updated to show ordered terms) ---
    print("\n--- DEBUG: Parsed Filters Object (Order Preserved) ---")
    for f_name, f_obj in parsed_filters.items():
        print(f"Filter: {f_name}")
        for term_obj in f_obj.terms: # Iterate through the list directly
            print(f"  Term: {term_obj.name}")
            print(f"    From Conditions: {term_obj.from_conditions}")
            print(f"    Then Actions: {term_obj.then_actions}")
    print("------------------------------------\n")
    # --- END DEBUG ---


    for filter_name in sorted(parsed_filters.keys()): # Process filters in sorted order (filter names)
        junos_filter_obj = parsed_filters[filter_name]
        output_lines.append(f"ip access-list extended {filter_name}")
        sequence_counter = 10 # Start sequence numbers

        # Iterate through terms in their PARSED ORDER (from the list)
        for junos_term_obj in junos_filter_obj.terms:
            # Add the remark line with the Junos term name
            output_lines.append(f" {sequence_counter} remark --- Junos Term: {junos_term_obj.name} ---")
            sequence_counter += 10 # Increment sequence for the remark line

            # --- DEBUG: Converting Term ---
            print(f"--- DEBUG: Converting Term '{junos_term_obj.name}' ---")
            print(f"  From Conditions: {junos_term_obj.from_conditions}")
            print(f"  Then Actions: {junos_term_obj.then_actions}")
            # --- END DEBUG ---
 
            cisco_rules_for_term = convert_junos_term_to_cisco_rules(junos_term_obj)
            
            for rule_body in cisco_rules_for_term:
                output_lines.append(f" {sequence_counter} {rule_body}")
                sequence_counter += 10
        
        # Add the implicit deny at the end for Cisco ACLs
        output_lines.append(f" {sequence_counter} deny ip any any log")
        output_lines.append("!")
        output_lines.append("")
    
    return "\n".join(output_lines)

def main():
    """
    Main function to handle file input/output and call the conversion.
    """
    input_filename = input("Enter the path to the input Juniper config file (e.g., juniper_config.txt): ")
    output_filename = input("Enter the desired output Cisco config file name (e.g., cisco_acl_output.txt): ")

    try:
        with open(input_filename, 'r') as f_in:
            junos_lines = f_in.readlines()
    except FileNotFoundError:
        print(f"Error: Input file '{input_filename}' not found.")
        return
    except Exception as e:
        print(f"An unexpected error occurred while reading the input file: {e}")
        return

    cisco_output = convert_all_junos_to_cisco(junos_lines)

    try:
        with open(output_filename, 'w') as f_out:
            f_out.write(cisco_output)
        print(f"\nConversion complete! Cisco configuration saved to '{output_filename}'")
    except Exception as e:
        print(f"An error occurred while writing to the output file: {e}")

if __name__ == "__main__":
    main()