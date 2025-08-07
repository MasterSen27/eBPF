from bcc import BPF
from ctypes import *

# Load the eBPF program
b = BPF(src_file="xdp_telemetry.c")
fn = b.load_func("xdp_prog", BPF.XDP)
b.attach_xdp("eth0", fn, 0)

# Define data structure (same as in your C code)
class Data_t(Structure):
    _fields_ = [
        ("src_ip", c_uint32),
        ("dst_ip", c_uint32),
        ("src_port", c_uint16),
        ("dst_port", c_uint16),
        ("protocol", c_uint8),
    ]

# Convert IP
def ip_to_str(ip):
    return ".".join(map(str, ip.to_bytes(4, "little")))

# Event handler
def handle_event(cpu, data, size):
    event = cast(data, POINTER(Data_t)).contents
    print(f"Src: {ip_to_str(event.src_ip)}:{event.src_port} → "
          f"Dst: {ip_to_str(event.dst_ip)}:{event.dst_port} | Proto: {event.protocol}")

# Attach ring buffer
rb = b["telemetry_events"]
rb.open_ring_buffer(handle_event)

print("🟢 Listening for telemetry packets... (Ctrl+C to stop)")
while True:
    rb.consume()
