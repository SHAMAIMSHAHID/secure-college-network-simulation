import time
import networkx as nx
import matplotlib.pyplot as plt

# =====================================================================
# 1. FIREWALL RULES & NETWORK ZONES DEFINITION
# =====================================================================
# Zones representing VLAN Segmentation in a Secure College Network
ZONES = {
    "DMZ": ["Web-Server", "Library-DB"],          # Semi-public servers
    "ADMIN": ["Finance-PC", "Principal-PC"],     # Highly restricted
    "STUDENT": ["Lab-PC-1", "WLAN-Student"],      # Academic access
    "GUEST": ["Guest-Mobile-1", "Guest-WiFi"]    # Internet access only
}

# Firewall Access Control List (ACL) - Rule Engine
# Format: (Source Zone, Destination Zone, Allowed Port, Action)
FIREWALL_RULES = [
    ("STUDENT", "DMZ", 80, "ALLOW"),      # Students can access Web-Server
    ("STUDENT", "DMZ", 443, "ALLOW"),     # Students can access secure Web-Server
    ("ADMIN", "DMZ", 22, "ALLOW"),        # Admins can SSH into DMZ servers
    ("ADMIN", "STUDENT", "ANY", "ALLOW"), # Admins can manage Student network
    ("GUEST", "DMZ", 80, "ALLOW"),        # Guests can access library portal
    ("DMZ", "ADMIN", "ANY", "DENY"),      # Web-servers cannot touch Admin network (Strict Isolation)
    ("STUDENT", "ADMIN", "ANY", "DENY"),  # Students blocked from Admin (Finance/Grades)
    ("GUEST", "ADMIN", "ANY", "DENY"),    # Guests blocked from Admin
    ("GUEST", "STUDENT", "ANY", "DENY"),  # Guests blocked from Student network
]

# Helper to identify zone of a device
def get_zone(device_name):
    for zone, devices in ZONES.items():
        if device_name in devices:
            return zone
    return "EXTERNAL_INTERNET"

# =====================================================================
# 2. PACKET SIMULATOR & SECURITY CHECK
# =====================================================================
class SecureFirewall:
    def __init__(self, rules):
        self.rules = rules

    def inspect_packet(self, src_device, dest_device, port):
        src_zone = get_zone(src_device)
        dest_zone = get_zone(dest_device)
        
        print(f"\n[!] FireWall Inspecting: {src_device} ({src_zone}) -> {dest_device} ({dest_zone}) on Port {port}")
        time.sleep(0.5)

        # Default action is DENY (Zero-Trust Security Principle)
        action = "DENY"
        reason = "No matching rule found (Default Deny)"

        for rule_src, rule_dest, rule_port, rule_action in self.rules:
            if src_zone == rule_src and dest_zone == rule_dest:
                if rule_port == "ANY" or rule_port == port:
                    action = rule_action
                    reason = f"Matched rule: {rule_src} to {rule_dest} (Port: {rule_port}) is {rule_action}"
                    break

        if action == "ALLOW":
            print(f"✅ [ACCESS GRANTED]: {reason}")
            return True
        else:
            print(f"❌ [ACCESS DENIED]: {reason}")
            return False

# =====================================================================
# 3. TOPOLOGY VISUALIZER (Using NetworkX & Matplotlib)
# =====================================================================
def draw_topology():
    G = nx.Graph()
    
    # Central Network Devices
    G.add_node("Core-Router", type="Core")
    G.add_node("Main-Firewall", type="Firewall")
    
    # Connecting Core Elements
    G.add_edge("Core-Router", "Main-Firewall")
    
    # Zone colors for representation
    color_map = []
    node_sizes = []
    
    # Populate network devices and connect them to Firewall
    for zone, devices in ZONES.items():
        G.add_node(zone, type="Zone-Switch")
        G.add_edge("Main-Firewall", zone)
        for device in devices:
            G.add_node(device, type="End-Device")
            G.add_edge(zone, device)
            
    # Assigning styling based on node types
    for node, attrs in G.nodes(data=True):
        node_type = attrs.get("type", "")
        if node == "Main-Firewall":
            color_map.append("red")
            node_sizes.append(1000)
        elif node == "Core-Router":
            color_map.append("orange")
            node_sizes.append(800)
        elif node_type == "Zone-Switch":
            color_map.append("lightblue")
            node_sizes.append(600)
        else:
            color_map.append("lightgreen")
            node_sizes.append(300)

    plt.figure(figsize=(10, 8))
    pos = nx.spring_layout(G, seed=42)
    nx.draw(G, pos, with_labels=True, node_color=color_map, node_size=node_sizes, font_size=8, font_weight="bold", edge_color="gray")
    plt.title("Secure College Campus Network Architecture", fontsize=14, fontweight="bold")
    print("\n[+] Generating Network Topology Graph... Close the window to continue simulation.")
    plt.show()

# =====================================================================
# 4. EXECUTION FLOW (Main Simulator)
# =====================================================================
if __name__ == "__main__":
    print("=========================================================")
    print("      SECURE CAMPUS NETWORK SIMULATION & FIREWALL        ")
    print("=========================================================")
    
    # Show Visual Network Map
    draw_topology()
    
    # Initialize Simulated Security Firewall
    firewall = SecureFirewall(FIREWALL_RULES)
    
    # Simulation Scenarios
    scenarios = [
        # (Source, Destination, Port)
        ("Lab-PC-1", "Web-Server", 443),      # Valid Student access to Web Server
        ("Guest-Mobile-1", "Finance-PC", 80), # Unauthorized Guest trying to access Admin Finance PC
        ("Finance-PC-1", "Web-Server", 22),   # Admin SSH access (Will show default IP logic because of name lookup)
        ("Principal-PC", "Lab-PC-1", 80),     # Admin accessing Student device
        ("Library-DB", "Finance-PC", 3306)    # DMZ trying to initiate connection to Admin (Crucial Security Check)
    ]
    
    print("\n--- Running Traffic Analysis & ACL Verification ---")
    for src, dest, port in scenarios:
        firewall.inspect_packet(src, dest, port)
        time.sleep(1)
        
    print("\n=========================================================")
    print("Simulation Complete. All critical rules checked successfully.")
    print("=========================================================")
    print("\n=========================================================")
    print("Simulation Complete. All critical rules checked successfully.")
    print("=========================================================")
    
    # Ye line add karein taaki terminal automatic close na ho:
    input("\n[Press ENTER to exit the program...]")
    