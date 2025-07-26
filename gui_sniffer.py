import sys
import threading
import time
import psutil
from PyQt5 import QtWidgets, QtCore, QtGui
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest, HTTPResponse
from collections import defaultdict
import ipinfo

from main import NetworkSniffer

class SplashScreen(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Snifflux")
        self.setFixedSize(600, 400)
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint | QtCore.Qt.WindowStaysOnTopHint)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)

        # Main layout
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Main widget with solid background (not gradient)
        main_widget = QtWidgets.QWidget()
        main_widget.setStyleSheet("""
            QWidget {
                background: #102542;
                border-radius: 20px;
            }
        """)
        main_widget.setLayout(QtWidgets.QVBoxLayout())
        main_widget.layout().setContentsMargins(0, 0, 0, 0)
        main_widget.layout().setSpacing(0)

        # Stack for logo and overlay
        stack = QtWidgets.QStackedLayout()
        stack.setStackingMode(QtWidgets.QStackedLayout.StackAll)

        # Logo label with opacity effect
        logo_label = QtWidgets.QLabel()
        pixmap = QtGui.QPixmap("ocean_icon.png").scaled(320, 320, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)
        logo_label.setPixmap(pixmap)
        logo_label.setAlignment(QtCore.Qt.AlignCenter)
        opacity_effect = QtWidgets.QGraphicsOpacityEffect()
        opacity_effect.setOpacity(0.18)
        logo_label.setGraphicsEffect(opacity_effect)
        stack.addWidget(logo_label)

        # Overlay widget for text
        overlay = QtWidgets.QWidget()
        overlay_layout = QtWidgets.QVBoxLayout(overlay)
        overlay_layout.setAlignment(QtCore.Qt.AlignCenter)
        overlay_layout.setContentsMargins(0, 60, 0, 0)
        # Title
        title_label = QtWidgets.QLabel("Snifflux")
        title_label.setStyleSheet("""
            QLabel {
                color: #ffffff;
                font-family: 'Segoe UI', 'Roboto', 'Arial', sans-serif;
                font-size: 48px;
                font-weight: bold;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
            }
        """)
        title_label.setAlignment(QtCore.Qt.AlignCenter)
        # Subtitle
        subtitle_label = QtWidgets.QLabel("Advanced Network Packet Sniffer")
        subtitle_label.setStyleSheet("""
            QLabel {
                color: #1b98e0;
                font-family: 'Segoe UI', 'Roboto', 'Arial', sans-serif;
                font-size: 18px;
                font-weight: normal;
            }
        """)
        subtitle_label.setAlignment(QtCore.Qt.AlignCenter)
        # Author
        author_label = QtWidgets.QLabel("by Oceancurrent")
        author_label.setStyleSheet("""
            QLabel {
                color: #e0e6ed;
                font-family: 'Segoe UI', 'Roboto', 'Arial', sans-serif;
                font-size: 13px;
                font-style: italic;
                margin-top: 10px; /* Reduced from 30px to 10px */
            }
        """)
        author_label.setAlignment(QtCore.Qt.AlignCenter)
        overlay_layout.addWidget(title_label)
        overlay_layout.addWidget(subtitle_label)
        overlay_layout.addStretch(1)
        overlay_layout.addWidget(author_label)
        overlay_layout.addStretch(1)  # Add stretch after author to keep it from hugging the bottom
        stack.addWidget(overlay)

        main_widget.layout().addLayout(stack)
        layout.addWidget(main_widget)

        # Timer to close splash screen
        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.close)
        self.timer.start(3000)  # 3 seconds

class SnifferThread(QtCore.QThread):
    packet_signal = QtCore.pyqtSignal(object)
    stats_signal = QtCore.pyqtSignal(dict)
    error_signal = QtCore.pyqtSignal(str)

    def __init__(self, interface, filter_exp=None, output_file=None):
        super().__init__()
        self.interface = interface
        self.filter_exp = filter_exp
        self.output_file = output_file
        self._stop_event = threading.Event()
        self.sniffer = NetworkSniffer()

    def run(self):
        def callback(packet):
            self.packet_signal.emit(packet)
        try:
            sniff_params = {
                'iface': self.interface,
                'prn': callback,
                'store': 0
            }
            if self.filter_exp:
                sniff_params['filter'] = self.filter_exp
            if self.output_file:
                sniff_params['offline'] = self.output_file
            sniff(**sniff_params, stop_filter=lambda x: self._stop_event.is_set())
        except Exception as e:
            self.error_signal.emit(str(e))

    def stop(self):
        self._stop_event.set()

class PacketSnifferGUI(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Snifflux - Oceancurrent")
        self.setGeometry(100, 100, 1000, 650)
        self.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0f2027, stop:0.5 #2c5364, stop:1 #00c6fb);
                color: #e0e6ed;
                font-family: 'Segoe UI', 'Roboto', 'Arial', sans-serif;
                font-size: 13px;
            }
            QLabel, QLineEdit, QComboBox, QPushButton {
                font-family: 'Segoe UI', 'Roboto', 'Arial', sans-serif;
            }
            QLineEdit, QComboBox {
                background-color: #274472;
                color: #e0e6ed;
                border-radius: 5px;
                padding: 2px 6px;
            }
            QPushButton {
                background-color: #1b98e0;
                color: #fff;
                border-radius: 6px;
                padding: 6px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00c6fb;
                color: #102542;
            }
            QTextEdit {
                background-color: #102542;
                color: #e0e6ed;
                font-family: 'Consolas', 'Fira Mono', monospace;
                border-radius: 6px;
            }
        """)
        # Set window icon if available
        self.setWindowIcon(QtGui.QIcon('ocean_icon.png'))
        self.sniffer_thread = None
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.start_time = None
        self.ipinfo_handler = ipinfo.getHandler()
        self._setup_ui()

    def _setup_ui(self):
        layout = QtWidgets.QVBoxLayout(self)
        # Top controls
        controls = QtWidgets.QHBoxLayout()
        controls_widget = QtWidgets.QWidget()
        controls_widget.setStyleSheet("background: rgba(16, 37, 66, 0.92); border-radius: 10px; padding: 8px 0px;")
        controls_layout = QtWidgets.QHBoxLayout(controls_widget)
        self.interface_combo = QtWidgets.QComboBox()
        self.interface_combo.setStyleSheet("background-color: #274472; color: #e0e6ed;")
        self._populate_interfaces()
        controls_layout.addWidget(QtWidgets.QLabel("Interface:"))
        controls_layout.addWidget(self.interface_combo)
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("BPF filter expression (e.g., tcp port 80)")
        self.filter_edit.setStyleSheet("background-color: #274472; color: #e0e6ed;")
        controls_layout.addWidget(QtWidgets.QLabel("Filter:"))
        controls_layout.addWidget(self.filter_edit)
        self.output_edit = QtWidgets.QLineEdit()
        self.output_edit.setPlaceholderText("Output file (.pcap)")
        self.output_edit.setStyleSheet("background-color: #274472; color: #e0e6ed;")
        controls_layout.addWidget(QtWidgets.QLabel("Output:"))
        controls_layout.addWidget(self.output_edit)
        self.browse_btn = QtWidgets.QPushButton("Browse")
        self.browse_btn.setStyleSheet("background-color: #4176a6; color: #fff;")
        self.browse_btn.clicked.connect(self._browse_file)
        controls_layout.addWidget(self.browse_btn)
        self.start_btn = QtWidgets.QPushButton("Start Sniffing")
        self.start_btn.setStyleSheet("background-color: #1b98e0; color: #fff;")
        self.start_btn.clicked.connect(self._toggle_sniffing)
        controls_layout.addWidget(self.start_btn)
        layout.addWidget(controls_widget)
        # Packet table (Wireshark style)
        self.packet_table = QtWidgets.QTableWidget(0, 7)
        self.packet_table.setHorizontalHeaderLabels(["No.", "Time", "Source", "Destination", "Protocol", "HTTP/HTTPS", "Info"])
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        self.packet_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.packet_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.packet_table.setStyleSheet("background-color: #102542; color: #e0e6ed; font-family: 'Consolas', 'Fira Mono', monospace; border-radius: 6px;")
        layout.addWidget(self.packet_table, 3)
        # Protocol stats
        stats_layout = QtWidgets.QHBoxLayout()
        self.stats_label = QtWidgets.QLabel("Protocol Stats: ")
        self.stats_label.setStyleSheet("background: #162a47; color: #1b98e0; font-weight: bold; padding: 6px 18px 6px 18px; border-radius: 8px;")
        stats_layout.addWidget(self.stats_label)
        self.stats_text = QtWidgets.QLabel("")
        self.stats_text.setStyleSheet("background: #162a47; color: #e0e6ed; padding: 6px 18px 6px 18px; border-radius: 8px;")
        stats_layout.addWidget(self.stats_text)
        layout.addLayout(stats_layout)
        # Status bar
        self.status_bar = QtWidgets.QLabel("")
        self.status_bar.setStyleSheet("background: #162a47; color: #1b98e0; padding: 6px 18px 6px 18px; border-radius: 8px;")
        layout.addWidget(self.status_bar)

    def _populate_interfaces(self):
        self.interface_combo.clear()
        for iface, addrs in psutil.net_if_addrs().items():
            self.interface_combo.addItem(iface)

    def _browse_file(self):
        fname, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Select Output File", "", "PCAP Files (*.pcap);;All Files (*)")
        if fname:
            self.output_edit.setText(fname)

    def _toggle_sniffing(self):
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self._stop_sniffing()
        else:
            self._start_sniffing()

    def _start_sniffing(self):
        interface = self.interface_combo.currentText()
        filter_exp = self.filter_edit.text() or None
        output_file = self.output_edit.text() or None
        self.packet_table.setRowCount(0) # Clear previous packets
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.start_time = time.time()
        self.sniffer_thread = SnifferThread(interface, filter_exp, output_file)
        self.sniffer_thread.packet_signal.connect(self._process_packet)
        self.sniffer_thread.error_signal.connect(self._show_error)
        self.sniffer_thread.start()
        self.start_btn.setText("Stop Sniffing")
        self.status_bar.setText(f"Sniffing on {interface}...")

    def _stop_sniffing(self):
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()
        self.start_btn.setText("Start Sniffing")
        self.status_bar.setText("Stopped.")
        self._update_stats(final=True)

    def _get_ip_location(self, ip):
        try:
            details = self.ipinfo_handler.getDetails(ip)
            city = details.city or ""
            region = details.region or ""
            country = details.country_name or details.country or ""
            location = ", ".join([x for x in [city, region, country] if x])
            return location if location else "Unknown"
        except Exception:
            return "Unknown"

    def _process_packet(self, packet):
        self.packet_count += 1
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)

        # Time
        time_str = time.strftime("%H:%M:%S", time.localtime())
        self.packet_table.setItem(row, 0, QtWidgets.QTableWidgetItem(str(self.packet_count)))
        self.packet_table.setItem(row, 1, QtWidgets.QTableWidgetItem(time_str))

        # Source and Destination
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            src_loc = self._get_ip_location(ip_src)
            dst_loc = self._get_ip_location(ip_dst)
            proto = packet[IP].proto
            proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
            proto_name = proto_map.get(proto, str(proto))
            protocol_label = proto_name
            http_label = ""
            # HTTP/HTTPS detection
            if packet.haslayer(TCP):
                tcp_sport = packet[TCP].sport
                tcp_dport = packet[TCP].dport
                if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
                    http_label = "HTTP"
                elif tcp_sport == 443 or tcp_dport == 443:
                    http_label = "HTTPS"
                protocol_label = "TCP"
            elif packet.haslayer(UDP):
                protocol_label = "UDP"
            elif packet.haslayer(ICMP):
                protocol_label = "ICMP"
            else:
                protocol_label = proto_name
            self.protocol_stats[protocol_label] += 1
            self.packet_table.setItem(row, 2, QtWidgets.QTableWidgetItem(ip_src))
            self.packet_table.setItem(row, 3, QtWidgets.QTableWidgetItem(ip_dst))
            self.packet_table.setItem(row, 4, QtWidgets.QTableWidgetItem(protocol_label))
            self.packet_table.setItem(row, 5, QtWidgets.QTableWidgetItem(http_label))

            # Color coding based on protocol
            if protocol_label == "TCP":
                self.packet_table.item(row, 4).setBackground(QtGui.QColor("#2980b9"))
                self.packet_table.item(row, 4).setForeground(QtGui.QColor("#ffffff"))
            elif protocol_label == "UDP":
                self.packet_table.item(row, 4).setBackground(QtGui.QColor("#2ecc71"))
                self.packet_table.item(row, 4).setForeground(QtGui.QColor("#ffffff"))
            elif protocol_label == "ICMP":
                self.packet_table.item(row, 4).setBackground(QtGui.QColor("#e67e22"))
                self.packet_table.item(row, 4).setForeground(QtGui.QColor("#ffffff"))
            else:
                self.packet_table.item(row, 4).setBackground(QtGui.QColor("#95a5a6"))
                self.packet_table.item(row, 4).setForeground(QtGui.QColor("#ffffff"))

            # Info text
            info_lines = []
            if http_label == "HTTP" and packet.haslayer(HTTPRequest):
                http = packet[HTTPRequest]
                info_lines.append(f"HTTP Request: {http.Method.decode()} {http.Path.decode()}")
            elif http_label == "HTTP" and packet.haslayer(HTTPResponse):
                http = packet[HTTPResponse]
                info_lines.append(f"HTTP Response: {http.Status_Code.decode()}")
            elif http_label == "HTTPS":
                info_lines.append(f"HTTPS {ip_src}:{tcp_sport} → {ip_dst}:{tcp_dport}")
            elif protocol_label == "TCP":
                info_lines.append(f"TCP {ip_src}:{tcp_sport} → {ip_dst}:{tcp_dport} [Flags: {packet[TCP].flags}]")
            elif protocol_label == "UDP" and packet.haslayer(UDP):
                udp_sport = packet[UDP].sport
                udp_dport = packet[UDP].dport
                info_lines.append(f"UDP {ip_src}:{udp_sport} → {ip_dst}:{udp_dport} [Length: {packet[UDP].len}]")
            elif protocol_label == "ICMP" and packet.haslayer(ICMP):
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                info_lines.append(f"ICMP Type:{icmp_type} Code:{icmp_code}")
            else:
                info_lines.append(f"Protocol {proto} | Size: {len(packet)} bytes")
            # Add GeoIP info
            info_lines.append(f"Src: {src_loc}")
            info_lines.append(f"Dst: {dst_loc}")
            info_text = "\n".join(info_lines)
            self.packet_table.setItem(row, 6, QtWidgets.QTableWidgetItem(info_text))
        else:
            self.packet_table.setItem(row, 2, QtWidgets.QTableWidgetItem(str(packet.src)))
            self.packet_table.setItem(row, 3, QtWidgets.QTableWidgetItem(str(packet.dst)))
            self.packet_table.setItem(row, 4, QtWidgets.QTableWidgetItem("Other"))
            self.packet_table.setItem(row, 5, QtWidgets.QTableWidgetItem(""))
            self.packet_table.item(row, 4).setBackground(QtGui.QColor("#95a5a6"))
            self.packet_table.item(row, 4).setForeground(QtGui.QColor("#ffffff"))
            self.packet_table.setItem(row, 6, QtWidgets.QTableWidgetItem(f"Size: {len(packet)} bytes"))

        # Auto-scroll to bottom
        self.packet_table.scrollToBottom()
        self._update_stats()

    def _update_stats(self, final=False):
        duration = time.time() - self.start_time if self.start_time else 1
        stats = f"Total: {self.packet_count} | Duration: {duration:.1f}s | Rate: {self.packet_count/duration:.2f}/s"
        if self.packet_count:
            stats += "<br>"
            for proto, count in self.protocol_stats.items():
                stats += f"{proto}: {count} ({count/self.packet_count*100:.1f}%)  "
        self.stats_text.setText(stats)
        if final:
            self.status_bar.setText(self.status_bar.text() + "  (Capture finished)")

    def _show_error(self, msg):
        QtWidgets.QMessageBox.critical(self, "Error", msg)
        self._stop_sniffing()

    def closeEvent(self, event):
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()
        event.accept()

def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Create main window first
    window = PacketSnifferGUI()
    
    # Show splash screen
    splash = SplashScreen()
    splash.show()
    
    # Connect splash screen close to main window show
    splash.timer.timeout.connect(lambda: (splash.close(), window.show()))
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main() 