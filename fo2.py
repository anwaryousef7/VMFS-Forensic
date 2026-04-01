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
        self.geometry("1000x750")
        
        # Grid layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # 1. Header
        self.header_label = ctk.CTkLabel(
            self, text="Forensic IOC Scanner (Files, Directories, Raw Images)", 
            font=ctk.CTkFont(size=22, weight="bold")
        )
        self.header_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # 2. Controls Frame
        self.control_frame = ctk.CTkFrame(self)
        self.control_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        
        # Buttons
        self.file_btn = ctk.CTkButton(
            self.control_frame, text="Scan File / Raw Image", 
            command=self.select_file, font=ctk.CTkFont(weight="bold")
        )
        self.file_btn.grid(row=0, column=0, padx=10, pady=10)

        self.dir_btn = ctk.CTkButton(
            self.control_frame, text="Scan Directory", 
            command=self.select_directory, font=ctk.CTkFont(weight="bold")
        )
        self.dir_btn.grid(row=0, column=1, padx=10, pady=10)

        self.export_btn = ctk.CTkButton(
            self.control_frame, text="Export Results", 
            command=self.export_results, font=ctk.CTkFont(weight="bold"), state="disabled", fg_color="green"
        )
        self.export_btn.grid(row=0, column=2, padx=10, pady=10)

        self.status_label = ctk.CTkLabel(
            self.control_frame, text="Waiting for input...", text_color="gray"
        )
        self.status_label.grid(row=0, column=3, padx=10, pady=10, sticky="w")

        # 3. Results Area
        self.result_textbox = ctk.CTkTextbox(self, font=ctk.CTkFont(size=13, family="Consolas"))
        self.result_textbox.grid(row=2, column=0, padx=20, pady=(10, 20), sticky="nsew")
        
        # --- Pre-compiled Regex Patterns ---
        self.patterns = {
            "IP Addresses": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            "Domains": re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'),
            "SQL Injection / SQLMap": re.compile(r'(?i)(sqlmap|UNION SELECT|SELECT.*FROM|WAITFOR DELAY|SLEEP\(|OUTFILE|LOAD_FILE|%27|--\s)'),
            "System Compromise (WebShells/LFI)": re.compile(r'(?i)(\.php\?cmd=|\/etc\/passwd|\/bin\/bash|whoami|eval\(|base64_decode)')
        }

        self.files_to_scan = []
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
        self.result_textbox.insert("end", "[*] Note: Large raw images (.dd/.img) are read in chunks to save memory.\n\n")
        
        # Disable buttons during scan
        self.file_btn.configure(state="disabled")
        self.dir_btn.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        
        scan_thread = threading.Thread(target=self.scan_logic)
        scan_thread.daemon = True
        scan_thread.start()

    def scan_logic(self):
        results = {key: set() for key in self.patterns.keys()}
        chunk_size = 1024 * 1024 * 5  # Read 5MB chunks for raw images
        overlap_size = 1024           # 1KB overlap to avoid breaking regex across chunks

        try:
            for filepath in self.files_to_scan:
                # Update UI safely
                self.after(0, lambda f=filepath: self.status_label.configure(text=f"Scanning: {os.path.basename(f)}"))
                
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                    overlap_data = ""
                    while True:
                        chunk = file.read(chunk_size)
                        if not chunk:
                            break
                        
                        # Prepend overlap from previous chunk to catch split strings
                        data_to_scan = overlap_data + chunk
                        
                        for category, pattern in self.patterns.items():
                            matches = pattern.findall(data_to_scan)
                            for match in matches:
                                if isinstance(match, tuple):
                                    match = match[0]
                                results[category].add(match.strip())
                        
                        # Save the end of the current chunk as overlap for the next
                        overlap_data = chunk[-overlap_size:] if len(chunk) > overlap_size else chunk

            # Geolocation for extracted IPs
            self.after(0, lambda: self.status_label.configure(text="Resolving IP Geolocation..."))
            ip_info = self.locate_ips(results["IP Addresses"])
            
            self.after(0, self.display_results, results, ip_info)
            
        except Exception as e:
            self.after(0, self.display_error, str(e))

    def locate_ips(self, ip_set):
        ip_data = {}
        ips_to_check = list(ip_set)[:15] # API limit protection
        
        for ip in ips_to_check:
            if ip.startswith(("127.", "192.168.", "10.")):
                ip_data[ip] = "Local/Private IP"
                continue
                
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "success":
                        ip_data[ip] = f"{data.get('country', 'Unknown')} (ISP: {data.get('isp', 'Unknown')})"
                    else:
                        ip_data[ip] = "Geolocation failed"
            except:
                ip_data[ip] = "Connection Error"
            time.sleep(0.3)
            
        return ip_data

    def display_results(self, results, ip_info):
        self.result_textbox.delete("0.0", "end")
        output_buffer = f"[*] Scan Completed for {len(self.files_to_scan)} file(s)\n"
        output_buffer += "="*70 + "\n\n"
        
        total_findings = 0
        for category, items in results.items():
            if items:
                output_buffer += f"🔥 [{category}] - Found ({len(items)}) unique instances:\n"
                
                for item in sorted(list(items))[:100]: # Display up to 100 items per category
                    display_text = f"   -> {item}"
                    if category == "IP Addresses" and item in ip_info:
                        display_text += f"  |  🌍 Geo: {ip_info[item]}"
                    output_buffer += display_text + "\n"
                
                if len(items) > 100:
                    output_buffer += f"   ... (Hidden {len(items) - 100} additional items for readability)\n"
                
                output_buffer += "\n" + "-"*50 + "\n\n"
                total_findings += len(items)

        if total_findings == 0:
            output_buffer += "[+] The target appears clean. No matching IOCs found.\n"
        
        # Print to UI
        self.result_textbox.insert("end", output_buffer)
        self.final_results_text = output_buffer # Store for export
        
        # Reset UI states
        self.status_label.configure(text="Scan Finished.", text_color="green")
        self.file_btn.configure(state="normal")
        self.dir_btn.configure(state="normal")
        self.export_btn.configure(state="normal")

    def export_results(self):
        filepath = fd.asksaveasfilename(
            title="Save Results As", 
            defaultextension=".txt", 
            filetypes=(("Text Files", "*.txt"), ("All Files", "*.*"))
        )
        if filepath:
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(self.final_results_text)
                self.status_label.configure(text=f"Exported successfully to {os.path.basename(filepath)}", text_color="green")
            except Exception as e:
                self.status_label.configure(text=f"Export Failed: {str(e)}", text_color="red")

    def display_error(self, error_msg):
        self.result_textbox.insert("end", f"\n[!] Error during scan: {error_msg}\n")
        self.file_btn.configure(state="normal")
        self.dir_btn.configure(state="normal")

if __name__ == "__main__":
    app = ForensicsScannerApp()
    app.mainloop()
