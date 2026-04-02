import customtkinter as ctk
from tkinter import filedialog, messagebox
import re
import os

# Set the appearance and theme of the application
ctk.set_appearance_mode("Dark")  # Modes: "System" (standard), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

class AuthLogAnalyzer(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Configure window
        self.title("Auth.log Threat Analyzer - Brute Force Detector")
        self.geometry("900x650")
        self.minsize(800, 600)

        # Configure grid layout (1x2)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # --- Header Frame ---
        self.header_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="nsew")

        self.title_label = ctk.CTkLabel(self.header_frame, text="Linux Auth.log Analyzer", font=ctk.CTkFont(size=28, weight="bold"))
        self.title_label.pack(pady=10)

        self.desc_label = ctk.CTkLabel(self.header_frame, text="Detect IPs that failed to authenticate but eventually succeeded.", font=ctk.CTkFont(size=14, slant="italic"), text_color="gray")
        self.desc_label.pack()

        self.select_btn = ctk.CTkButton(self.header_frame, text="Select auth.log File", font=ctk.CTkFont(size=15, weight="bold"), height=40, command=self.load_and_analyze_file)
        self.select_btn.pack(pady=20)

        # --- Statistics Frame ---
        self.stats_frame = ctk.CTkFrame(self)
        self.stats_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        self.stats_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.failed_lbl = ctk.CTkLabel(self.stats_frame, text="Failed IPs: 0", font=ctk.CTkFont(size=16, weight="bold"), text_color="#ff4d4d")
        self.failed_lbl.grid(row=0, column=0, padx=20, pady=15)

        self.accepted_lbl = ctk.CTkLabel(self.stats_frame, text="Accepted IPs: 0", font=ctk.CTkFont(size=16, weight="bold"), text_color="#4dff4d")
        self.accepted_lbl.grid(row=0, column=1, padx=20, pady=15)

        self.suspicious_lbl = ctk.CTkLabel(self.stats_frame, text="Suspicious IPs: 0", font=ctk.CTkFont(size=16, weight="bold"), text_color="#ffb84d")
        self.suspicious_lbl.grid(row=0, column=2, padx=20, pady=15)

        # --- Results Frame ---
        self.results_frame = ctk.CTkFrame(self)
        self.results_frame.grid(row=2, column=0, padx=20, pady=(10, 20), sticky="nsew")
        self.grid_rowconfigure(2, weight=1)

        self.results_label = ctk.CTkLabel(self.results_frame, text="Analysis Results (Suspicious IPs):", font=ctk.CTkFont(size=16, weight="bold"))
        self.results_label.pack(anchor="w", padx=20, pady=(15, 5))

        self.textbox = ctk.CTkTextbox(self.results_frame, font=ctk.CTkFont(family="Consolas", size=14), wrap="word")
        self.textbox.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self.textbox.configure(state="disabled")

    def extract_ip(self, line):
        """Extracts IPv4 address from a log line."""
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        match = ip_pattern.search(line)
        if match:
            return match.group(0)
        return None

    def load_and_analyze_file(self):
        file_path = filedialog.askopenfilename(
            title="Select auth.log",
            filetypes=[("Log Files", "*.log"), ("All Files", "*.*")]
        )

        if not file_path:
            return

        if not os.path.exists(file_path):
            messagebox.showerror("Error", "File does not exist!")
            return

        failed_ips = set()
        accepted_ips = set()

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line in file:
                    # Linux auth logs usually show "authentication failure" or "Failed password"
                    if "authentication failure" in line or "Failed password" in line:
                        ip = self.extract_ip(line)
                        if ip:
                            failed_ips.add(ip)
                    
                    # Successful logins usually show "Accepted password" or "Accepted publickey"
                    elif "Accepted password" in line:
                        ip = self.extract_ip(line)
                        if ip:
                            accepted_ips.add(ip)

            self.process_results(failed_ips, accepted_ips)

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while reading the file:\n{str(e)}")

    def process_results(self, failed_ips, accepted_ips):
        # The core logic: Intersection of both sets (IPs that are in both)
        suspicious_ips = failed_ips.intersection(accepted_ips)

        # Update Statistics UI
        self.failed_lbl.configure(text=f"Failed IPs: {len(failed_ips)}")
        self.accepted_lbl.configure(text=f"Accepted IPs: {len(accepted_ips)}")
        self.suspicious_lbl.configure(text=f"Suspicious IPs: {len(suspicious_ips)}")

        # Update Textbox UI
        self.textbox.configure(state="normal")
        self.textbox.delete("1.0", "end")

        if suspicious_ips:
            self.textbox.insert("end", "⚠️ WARNING: Potential successful brute-force attacks detected!\n")
            self.textbox.insert("end", "The following IPs have failed attempts but eventually logged in successfully:\n\n")
            
            for i, ip in enumerate(suspicious_ips, 1):
                self.textbox.insert("end", f"[{i}] {ip}\n")
                
            self.textbox.insert("end", "\nAction Recommended: Check the activities of these IPs, block them if unauthorized, and enforce SSH Key login instead of passwords.")
        else:
            if not failed_ips and not accepted_ips:
                self.textbox.insert("end", "No relevant authentication logs found in this file.\nEnsure this is a standard Linux auth.log file.")
            else:
                self.textbox.insert("end", "✅ SECURE: No suspicious IPs found.\nNo IP address from the failed attempts list has successfully logged in.")

        self.textbox.configure(state="disabled")

if __name__ == "__main__":
    app = AuthLogAnalyzer()
    app.mainloop()
