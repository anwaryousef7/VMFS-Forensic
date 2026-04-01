import customtkinter as ctk
import tkinter.filedialog as fd
import re
import threading
import os
import requests
import time

# --- UI Configuration ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class ForensicsScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Advanced Forensics IOC Scanner")
        self.geometry("950x700")
        
        # Grid layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # 1. Header
        self.header_label = ctk.CTkLabel(
            self, text="Forensic Log & Database Analyzer (SQLi, IP Geolocator)", 
            font=ctk.CTkFont(size=22, weight="bold")
        )
        self.header_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # 2. Controls
        self.control_frame = ctk.CTkFrame(self)
        self.control_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        self.control_frame.grid_columnconfigure(1, weight=1)

        self.select_btn = ctk.CTkButton(
            self.control_frame, text="Select File to Scan", 
            command=self.select_file, font=ctk.CTkFont(weight="bold")
        )
        self.select_btn.grid(row=0, column=0, padx=10, pady=10)

        self.file_path_label = ctk.CTkLabel(
            self.control_frame, text="No file selected...", text_color="gray"
        )
        self.file_path_label.grid(row=0, column=1, padx=10, pady=10, sticky="w")

        # 3. Results Area
        self.result_textbox = ctk.CTkTextbox(self, font=ctk.CTkFont(size=13, family="Consolas"))
        self.result_textbox.grid(row=2, column=0, padx=20, pady=(10, 20), sticky="nsew")
        
        # --- Pre-compiled Regex Patterns for Maximum Speed ---
        self.patterns = {
            "IP Addresses": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            "Domains": re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'),
            "SQL Injection / SQLMap Signatures": re.compile(r'(?i)(sqlmap|UNION SELECT|SELECT.*FROM|WAITFOR DELAY|SLEEP\(|OUTFILE|LOAD_FILE|%27|--\s)'),
            "System Compromise (LFI/RCE/WebShells)": re.compile(r'(?i)(\.php\?cmd=|\/etc\/passwd|\/bin\/bash|whoami|eval\(|base64_decode)')
        }

        self.selected_file = None

    def select_file(self):
        filetypes = (
            ('All Files', '*.*'),
            ('Log Files', '*.log *.txt'),
            ('Database Dumps', '*.sql *.db *.sqlite *.dat *.ibd')
        )
        filepath = fd.askopenfilename(title='Select a file to analyze', filetypes=filetypes)
        
        if filepath:
            self.selected_file = filepath
            self.file_path_label.configure(text=filepath, text_color="white")
            self.start_scan()

    def start_scan(self):
        self.result_textbox.delete("0.0", "end")
        self.result_textbox.insert("end", "[*] Initializing scan... Please wait.\n")
        self.result_textbox.insert("end", "[*] Note: Reading raw DB files extracts raw strings and ignores binary data.\n\n")
        self.select_btn.configure(state="disabled", text="Scanning...")
        
        # Run scan in a separate thread to keep UI responsive
        scan_thread = threading.Thread(target=self.scan_file_logic)
        scan_thread.daemon = True
        scan_thread.start()

    def scan_file_logic(self):
        results = {key: set() for key in self.patterns.keys()}
        
        try:
            # 'errors=ignore' is crucial for parsing raw database files like .db or .ibd
            with open(self.selected_file, 'r', encoding='utf-8', errors='ignore') as file:
                for line in file:
                    for category, pattern in self.patterns.items():
                        matches = pattern.findall(line)
                        for match in matches:
                            if isinstance(match, tuple):
                                match = match[0]
                            results[category].add(match.strip())
            
            # Fetch IP Geolocation data for extracted IPs
            ip_info = self.locate_ips(results["IP Addresses"])
            
            # Send results back to the main GUI thread
            self.after(0, self.display_results, results, ip_info)
            
        except Exception as e:
            self.after(0, self.display_error, str(e))

    def locate_ips(self, ip_set):
        ip_data = {}
        # Limit to 15 to avoid rate-limiting from the free API (ip-api.com allows 45/min)
        ips_to_check = list(ip_set)[:15] 
        
        for ip in ips_to_check:
            # Ignore obvious private/local IPs
            if ip.startswith(("127.", "192.168.", "10.")):
                ip_data[ip] = "Local/Private IP"
                continue
                
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "success":
                        country = data.get("country", "Unknown")
                        isp = data.get("isp", "Unknown")
                        ip_data[ip] = f"{country} (ISP: {isp})"
                    else:
                        ip_data[ip] = "Geolocation failed"
            except:
                ip_data[ip] = "Connection Error"
            
            time.sleep(0.3) # Politeness delay for the API
            
        return ip_data

    def display_results(self, results, ip_info):
        self.result_textbox.delete("0.0", "end")
        self.result_textbox.insert("end", f"[*] Scan Completed for: {os.path.basename(self.selected_file)}\n")
        self.result_textbox.insert("end", "="*70 + "\n\n")
        
        total_findings = 0
        for category, items in results.items():
            if items:
                self.result_textbox.insert("end", f"🔥 [{category}] - Found ({len(items)}) unique instances:\n")
                
                # Display up to 50 items to prevent UI lag on massive log files
                for item in sorted(list(items))[:50]:
                    display_text = f"   -> {item}"
                    
                    # Append Geolocation data if the item is an IP
                    if category == "IP Addresses" and item in ip_info:
                        display_text += f"  |  🌍 Geo: {ip_info[item]}"
                        
                    self.result_textbox.insert("end", display_text + "\n")
                
                if len(items) > 50:
                    self.result_textbox.insert("end", f"   ... (Hidden {len(items) - 50} additional items for readability)\n")
                
                self.result_textbox.insert("end", "\n" + "-"*50 + "\n\n")
                total_findings += len(items)

        if total_findings == 0:
            self.result_textbox.insert("end", "[+] The file appears clean. No matching IOCs or signatures found.\n")
        
        self.select_btn.configure(state="normal", text="Select File to Scan")

    def display_error(self, error_msg):
        self.result_textbox.insert("end", f"\n[!] Error reading file: {error_msg}\n")
        self.select_btn.configure(state="normal", text="Select File to Scan")

if __name__ == "__main__":
    app = ForensicsScannerApp()
    app.mainloop()
