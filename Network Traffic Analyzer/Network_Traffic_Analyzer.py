
import tkinter as tk
import threading
from scapy.all import sniff, IP, Raw, DNS
import re

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.packet_count = 0
        self.packet_queue = []
        self.stop_sniffing_event = threading.Event()
        self.port_scan_tracker = {}
        self.create_widgets()
        self.update_ui()

    def create_widgets(self):
        self.text_frame = tk.Frame(self.root)
        self.text_frame.pack(fill=tk.BOTH, expand=True)

        self.canvas = tk.Canvas(self.text_frame)
        self.scrollbar = tk.Scrollbar(self.text_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            )
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        self.stop_button = tk.Button(self.root, text="Stop", bg="red", command=self.stop_sniffing)
        self.stop_button.pack(side="bottom", fill="x")

    def add_packet_info(self, packet_info, packet_details, color):
        frame = tk.Frame(self.scrollable_frame, bg=color, padx=5, pady=2)
        frame.pack(fill="x", expand=True)
        
        button = tk.Button(frame, text=packet_info, bg=color, anchor="w", justify="left", command=lambda: self.toggle_details(details))
        button.pack(fill="x", expand=True)

        details = tk.Label(frame, text=packet_details, bg=color, anchor="w", justify="left", wraplength=self.canvas.winfo_width())
        details.pack(fill="x", expand=True)
        details.pack_forget()

    def toggle_details(self, widget):
        if widget.winfo_ismapped():
            widget.pack_forget()
        else:
            widget.pack(fill="x", expand=True)

    def analyze_packet(self, packet):
        if IP in packet:
            self.packet_count += 1
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_info = f"Packet {self.packet_count}: Source IP: {src_ip} --> Destination IP: {dst_ip}"
            packet_details = f"Full details of packet {self.packet_count}\n{packet.show(dump=True)}"
            color = "lavender" if self.packet_count % 2 == 1 else "white"
            self.packet_queue.append((packet_info, packet_details, color))
            
            if self.detect_threat(packet):
                self.trigger_alert(packet_info, color)

    def detect_threat(self, packet):
        src_ip = packet[IP].src
        payload = packet.getlayer(Raw).load if packet.haslayer(Raw) else ""
        dns_query = packet.getlayer(DNS).qd.qname.decode('utf-8') if packet.haslayer(DNS) else ""

        if self.check_port_scan(src_ip):
            return True

        if self.check_malicious_payload(payload):
            return True

        if self.check_dns_tunneling(dns_query):
            return True

        return False

    def trigger_alert(self, packet_info, color):
        alert_info = "Potential security threat detected!"
        alert_color = "red"
        self.add_packet_info(alert_info, "", alert_color)

    def check_port_scan(self, src_ip):
        if src_ip in self.port_scan_tracker:
            if len(self.port_scan_tracker[src_ip]) > 5:
                return True
        else:
            self.port_scan_tracker[src_ip] = []
            self.root.after(10000, self.clear_port_scan_tracker, src_ip)
        return False

    def check_malicious_payload(self, payload):
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8', errors='ignore')

        malicious_signatures = [
            "rm -rf /",
            "exec(cmd)"
        ]
        for signature in malicious_signatures:
            if re.search(signature, payload):
                return True
        return False

    def check_dns_tunneling(self, dns_query):
        if len(dns_query) > 50:
            return True
        return False

    def clear_port_scan_tracker(self, src_ip):
        del self.port_scan_tracker[src_ip]

    def start_sniffing(self):
        sniff(prn=self.analyze_packet, stop_filter=lambda x: self.stop_sniffing_event.is_set(), store=False)

    def stop_sniffing(self):
        self.stop_sniffing_event.set()

    def update_ui(self):
        while self.packet_queue:
            packet_info, packet_details, color = self.packet_queue.pop(0)
            self.add_packet_info(packet_info, packet_details, color)
        self.root.after(100, self.update_ui)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    threading.Thread(target=app.start_sniffing, daemon=True).start()
    root.mainloop()
