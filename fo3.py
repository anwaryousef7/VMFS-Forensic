import customtkinter as ctk
import tkinter.filedialog as fd
import re
import threading
import os
import requests
import time
import csv
from datetime import datetime

# --- UI Configuration ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class ForensicsScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Advanced Forensics IOC Scanner | Developed by Anwar Yousef")
        self.geometry("1150x800")
        
        # Grid layout configuration
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # 1. Header Frame
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        self.header_frame.grid_columnconfigure(0, weight=1)

        self.header_label = ctk.CTkLabel(
            self.header_frame, 
            text="Cyber Forensics & IOC Analyzer", 
            font=ctk.CTkFont(size=26, weight="bold")
        )
        self.header_label.grid(row=0, column=0, sticky="w")

        self.dev_label = ctk.CTkLabel(
            self.header_frame, 
            text="Developed by Anwar Yousef", 
            font=ctk.CTkFont(size=14, slant="italic"),
            text_color="#00FFCC"
        )
        self.dev_label.grid(row=0, column=1, sticky="e")

        # 2. Controls Frame (Modernized)
        self.control_frame = ctk.CTkFrame(self, corner_radius=15)
        self.control_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        
        # Action Buttons
        self.file_btn = ctk.CTkButton(
            self.control_frame, text="📄 Scan File / Raw Image", 
            command=self.select_file, font=ctk.CTkFont(weight="bold"),
            height=40
        )
        self.file_btn.grid(row=0, column=0, padx=15, pady=15)

        self.dir_btn = ctk.CTkButton(
            self.control_frame, text="📁 Scan Directory", 
            command=self.select_directory, font=ctk.CTkFont(weight="bold"),
            height=40
        )
        self.dir_btn.grid(row=0, column=1, padx=15, pady=15)

        self.export_btn = ctk.CTkButton(
            self.control_frame, text="💾 Export Results (TXT/CSV/HTML)", 
            command=self.export_results, font=ctk.CTkFont(weight="bold"), 
            state="disabled", fg_color="#28a745", hover_color="#218838",
            height=40
        )
        self.export_btn.grid(row=0, column=2, padx=15, pady=15)

        self.status_label = ctk.CTkLabel(
            self.control_frame, text="Status: Waiting for input...", 
            text_color="gray", font=ctk.CTkFont(size=13, weight="bold")
        )
        self.status_label.grid(row=0, column=3, padx=20, pady=15, sticky="w")

        # 3. Results Area
        self.result_textbox = ctk.CTkTextbox(
            self, font=ctk.CTkFont(size=13, family="Consolas"), 
            corner_radius=10, border_width=2, border_color="#333344"
        )
        self.result_textbox.grid(row=2, column=0, padx=20, pady=(10, 20), sticky="nsew")
        
        # --- Pre-compiled Regex Patterns ---
        self.patterns = {
            "IP Addresses": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            "Domains": re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'),
            "SQL Injection / SQLMap": re.compile(r'(?i)(sqlmap|UNION SELECT|SELECT.*FROM|WAITFOR DELAY|SLEEP\(|OUTFILE|LOAD_FILE|%27|--\s)'),
            "System Compromise (WebShells/LFI)": re.compile(r'(?i)(\.php\?cmd=|\/etc\/passwd|\/bin\/bash|whoami|eval\(|base64_decode)')
        }

        # Data stores for exporting
        self.files_to_scan = []
        self.raw_results = {}
        self.raw_ip_info = {}
        self.final_results_text = ""

    def select_file(self):
        filetypes = (
            ('All Files', '*.*'),
            ('Raw Images', '*.dd *.img *.raw *.bin'),
            ('Log Files', '*.log *.txt'),
            ('Database Dumps', '*.sql *.db *.sqlite *.dat *.ibd')
        )
        filepath = fd.askopenfilename(title='Select a file or raw image to analyze', filetypes=filetypes)
        if filepath:
            self.files_to_scan = [filepath]
            self.status_label.configure(text=f"Selected File: {os.path.basename(filepath)}", text_color="white")
            self.start_scan()

    def select_directory(self):
        dirpath = fd.askdirectory(title='Select a directory to scan recursively')
        if dirpath:
            self.files_to_scan = []
            for root, _, files in os.walk(dirpath):
                for file in files:
                    self.files_to_scan.append(os.path.join(root, file))
            
            self.status_label.configure(text=f"Selected Directory: {len(self.files_to_scan)} files found.", text_color="white")
            self.start_scan()

    def start_scan(self):
        self.result_textbox.delete("0.0", "end")
        self.result_textbox.insert("end", f"[*] Initializing scan for {len(self.files_to_scan)} file(s)...\n")
        
        # Disable buttons during scan
        self.file_btn.configure(state="disabled")
        self.dir_btn.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        
        scan_thread = threading.Thread(target=self.scan_logic)
        scan_thread.daemon = True
        scan_thread.start()

    def scan_logic(self):
        results = {key: {} for key in self.patterns.keys()}
        chunk_size = 1024 * 1024 * 5  # 5MB chunks
        overlap_size = 1024           # 1KB overlap

        try:
            for filepath in self.files_to_scan:
                self.after(0, lambda f=filepath: self.status_label.configure(text=f"Scanning: {os.path.basename(f)}", text_color="yellow"))
                
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                    overlap_data = ""
                    while True:
                        chunk = file.read(chunk_size)
                        if not chunk:
                            break
                        
                        data_to_scan = overlap_data + chunk
                        
                        for category, pattern in self.patterns.items():
                            matches = pattern.findall(data_to_scan)
                            for match in matches:
                                if isinstance(match, tuple):
                                    match = match[0]
                                clean_match = match.strip()
                                
                                if clean_match not in results[category]:
                                    results[category][clean_match] = set()
                                results[category][clean_match].add(filepath)
                        
                        overlap_data = chunk[-overlap_size:] if len(chunk) > overlap_size else chunk

            self.after(0, lambda: self.status_label.configure(text="Resolving IP Geolocation data...", text_color="yellow"))
            ip_info = self.locate_ips(list(results["IP Addresses"].keys()))
            
            # Save raw data for exporters
            self.raw_results = results
            self.raw_ip_info = ip_info

            self.after(0, self.display_results, results, ip_info)
            
        except Exception as e:
            self.after(0, self.display_error, str(e))

    def locate_ips(self, ip_list):
        ip_data = {}
        ips_to_check = ip_list[:15] # API limit protection
        
        for ip in ips_to_check:
            if ip.startswith(("127.", "192.168.", "10.")):
                ip_data[ip] = "Local/Private IP Network"
                continue
                
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "success":
                        ip_data[ip] = f"{data.get('country', 'Unknown')} | {data.get('city', 'Unknown')} | ISP: {data.get('isp', 'Unknown')} | ASN: {data.get('as', 'Unknown')}"
                    else:
                        ip_data[ip] = "Geolocation query failed"
            except:
                ip_data[ip] = "Connection/Timeout Error"
            time.sleep(0.3)
            
        return ip_data

    def display_results(self, results, ip_info):
        self.result_textbox.delete("0.0", "end")
        output_buffer = f"[*] Scan Completed by Anwar Yousef's Analyzer\n"
        output_buffer += f"[*] Total Files Scanned: {len(self.files_to_scan)}\n"
        output_buffer += "="*90 + "\n\n"
        
        total_findings = 0
        for category, items in results.items():
            if items:
                output_buffer += f"🔥 [{category}] - Found ({len(items)}) unique instances:\n\n"
                
                sorted_items = sorted(list(items.items()))[:100]
                for item, filepaths in sorted_items:
                    output_buffer += f"   ➤ {item}\n"
                    if category == "IP Addresses" and item in ip_info:
                        output_buffer += f"      🌍 Geo-Info: {ip_info[item]}\n"
                    
                    output_buffer += f"      📂 Source(s):\n"
                    for fp in sorted(list(filepaths)):
                        output_buffer += f"         - {fp}\n"
                    output_buffer += "\n"
                
                if len(items) > 100:
                    output_buffer += f"   ... (Hidden {len(items) - 100} additional items to maintain UI performance)\n"
                
                output_buffer += "-"*90 + "\n\n"
                total_findings += len(items)

        if total_findings == 0:
            output_buffer += "[+] The target appears clean. No matching IOCs found.\n"
        
        self.result_textbox.insert("end", output_buffer)
        self.final_results_text = output_buffer
        
        self.status_label.configure(text="✅ Scan Finished Successfully.", text_color="#00FFCC")
        self.file_btn.configure(state="normal")
        self.dir_btn.configure(state="normal")
        self.export_btn.configure(state="normal")

    # --- Multi-Format Export Engine ---
    def export_results(self):
        filetypes = (
            ("HTML Report", "*.html"),
            ("CSV Spreadsheet", "*.csv"),
            ("Text Document", "*.txt")
        )
        filepath = fd.asksaveasfilename(
            title="Export Results", 
            defaultextension=".html", 
            filetypes=filetypes
        )
        
        if not filepath:
            return
            
        ext = os.path.splitext(filepath)[1].lower()
        try:
            if ext == '.csv':
                self.export_csv(filepath)
            elif ext == '.html':
                self.export_html(filepath)
            else:
                self.export_txt(filepath)
                
            self.status_label.configure(text=f"✅ Exported successfully to {os.path.basename(filepath)}", text_color="#00FFCC")
        except Exception as e:
            self.status_label.configure(text=f"❌ Export Failed: {str(e)}", text_color="red")

    def export_txt(self, filepath):
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(self.final_results_text)

    def export_csv(self, filepath):
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Category", "Indicator (IOC)", "Geo-Information", "Found In Source Files"])
            
            for category, items in self.raw_results.items():
                for item, filepaths in items.items():
                    geo = self.raw_ip_info.get(item, "N/A") if category == "IP Addresses" else "N/A"
                    sources = " | ".join(filepaths)
                    writer.writerow([category, item, geo, sources])

    def export_html(self, filepath):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Forensic IOC Report</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #121212; color: #e0e0e0; margin: 0; padding: 40px; }}
                .container {{ max-width: 1200px; margin: auto; background-color: #1e1e1e; padding: 30px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }}
                h1 {{ color: #ffffff; border-bottom: 2px solid #00ffcc; padding-bottom: 10px; }}
                h2 {{ color: #00ffcc; margin-top: 30px; }}
                .meta {{ font-size: 14px; color: #aaaaaa; margin-bottom: 20px; }}
                .dev {{ color: #00ffcc; font-weight: bold; font-style: italic; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 15px; background-color: #252525; }}
                th, td {{ border: 1px solid #333; padding: 12px; text-align: left; }}
                th {{ background-color: #333333; color: #ffffff; }}
                td {{ word-break: break-all; }}
                .source-file {{ display: block; font-size: 13px; color: #888; margin-top: 4px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Cyber Forensics & IOC Analysis Report</h1>
                <div class="meta">
                    Report Generated: {timestamp}<br>
                    <span class="dev">Developed by Anwar Yousef</span>
                </div>
        """
        
        has_data = False
        for category, items in self.raw_results.items():
            if not items: continue
            has_data = True
            html_content += f"<h2>{category}</h2>"
            html_content += "<table><tr><th>Indicator (IOC)</th><th>Geo-Location / Details</th><th>Source Files</th></tr>"
            
            for item, filepaths in items.items():
                geo = self.raw_ip_info.get(item, "N/A") if category == "IP Addresses" else "N/A"
                sources_html = "".join([f"<span class='source-file'>📄 {fp}</span>" for fp in filepaths])
                html_content += f"<tr><td><strong>{item}</strong></td><td>{geo}</td><td>{sources_html}</td></tr>"
                
            html_content += "</table>"
            
        if not has_data:
            html_content += "<p>No indicators of compromise (IOCs) were found during this scan.</p>"
            
        html_content += "</div></body></html>"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def display_error(self, error_msg):
        self.result_textbox.insert("end", f"\n[!] Error during scan: {error_msg}\n")
        self.status_label.configure(text="❌ Scan failed with errors.", text_color="red")
        self.file_btn.configure(state="normal")
        self.dir_btn.configure(state="normal")

if __name__ == "__main__":
    app = ForensicsScannerApp()
    app.mainloop()
