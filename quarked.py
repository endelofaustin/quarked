import subprocess
import logging
import socket
import speedtest
from scapy.all import sr, IP, TCP
import ipaddress

def get_router_ip():
    """Get the default gateway (router IP) for the internet connection on macOS."""
    try:
        # Determine the active network interface
        active_interface = subprocess.run(["route", "get", "default"], capture_output=True, text=True).stdout
        interface_name = next(line.split(": ")[1].strip() for line in active_interface.split("\n") if "interface: " in line)

        # Get the router IP using the active network interface
        result = subprocess.run(["ipconfig", "getoption", interface_name, "router"], capture_output=True, text=True)
        router_ip = result.stdout.strip()
        if not router_ip:
            raise ValueError("No router IP address found.")
        return router_ip
    except Exception as e:
        return f"Error retrieving router IP: {str(e)}"

def is_valid_ip(ip):
    """Check if the provided string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def run_speed_test():
    """Run a speed test to determine internet bandwidth speeds."""
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        download_speed = st.download()
        upload_speed = st.upload()
        return f"Download Speed: {download_speed / 1_000_000:.2f} Mbps, Upload Speed: {upload_speed / 1_000_000:.2f} Mbps"
    except speedtest.SpeedtestBestServerFailure:
        return "Error: Unable to connect to any speed test server."

def get_dns_servers():
    """Retrieve DNS server addresses on macOS and ensure no duplicates."""
    try:
        result = subprocess.run(['scutil', '--dns'], capture_output=True, text=True)
        lines = result.stdout.split('\n')
        dns_servers = set(line.split(' ')[-1] for line in lines if 'nameserver' in line)
        return list(dns_servers)
    except Exception as e:
        return f"Failed to get DNS servers: {str(e)}"

def traceroute_to(destination):
    """Perform a traceroute to a specified destination."""
    result = subprocess.run(['traceroute', destination], capture_output=True, text=True)
    return result.stdout

def ping_test():
    """Ping common servers to test network latency and packet loss."""
    servers = ['google.com', 'amazon.com', 'facebook.com']
    results = {}
    for server in servers:
        result = subprocess.run(['ping', '-c', '4', server], capture_output=True, text=True)
        if result.returncode == 0:
            results[server] = result.stdout.splitlines()[-2]
        else:
            results[server] = "Ping failed"
    return results

def scan_ports_on_router():
    """Scan for open TCP ports on the router."""
    router_ip = get_router_ip()
    if not is_valid_ip(router_ip):
        return f"Invalid router IP address: {router_ip}"
    ans, unans = sr(IP(dst=router_ip)/TCP(dport=(1,1024), flags="S"), timeout=2, verbose=0)
    open_ports = [s[TCP].dport for s, r in ans if r[TCP].flags & 18]
    return f"Open TCP Ports on Router ({router_ip}): {open_ports}"

def run_diagnostics():
    print("Starting diagnostics...")
    print("1. Checking router IP...")
    print(f"Router IP Address: {get_router_ip()}")

    print("2. Running speed test...")
    print(run_speed_test())

    print("3. Fetching DNS Servers...")
    print(f"DNS Servers: {get_dns_servers()}")

    print("4. Performing traceroute to 8.8.8.8...")
    print(traceroute_to("8.8.8.8"))

    print("5. Scanning open TCP ports on router...")
    print(scan_ports_on_router())

    print("6. Running ping tests to common servers...")
    for server, response in ping_test().items():
        print(f"Ping to {server}: {response}")

    print("Diagnostics complete.")

# Suppress Scapy and other unnecessary warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("speedtest").setLevel(logging.WARNING)

if __name__ == "__main__":
    run_diagnostics()

