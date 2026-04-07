import os
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox

# --- Basic UI Appearance Settings ---
ctk.set_appearance_mode("Dark")  # Options: "Dark", "Light", "System"
ctk.set_default_color_theme("blue")  # Options: "blue", "green", "dark-blue"

class TextSearchApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- Window Configuration ---
        self.title("Advanced Text Search Tool")
        self.geometry("900x700")  
        self.minsize(800, 600)

        # --- Search Variables ---
        self.selected_path = ""
        self.search_type = ctk.StringVar(value="file") # Default: search in a single file

        self.create_widgets()

    def create_widgets(self):
        # --- Header ---
        self.header_label = ctk.CTkLabel(self, text="Advanced Text Search Tool", font=ctk.CTkFont(size=28, weight="bold"))
        self.header_label.pack(pady=(30, 20))

        # --- Main Frame ---
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(fill="both", expand=True, padx=30, pady=(0, 30))

        # --- Settings and Inputs Section ---
        self.settings_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.settings_frame.pack(fill="x", padx=20, pady=20)

        # 1. Search Keyword Input
        self.keyword_label = ctk.CTkLabel(self.settings_frame, text="Search Keyword:", font=ctk.CTkFont(size=16))
        self.keyword_label.grid(row=0, column=0, padx=10, pady=15, sticky="w")
        
        self.keyword_entry = ctk.CTkEntry(self.settings_frame, width=350, font=ctk.CTkFont(size=14), placeholder_text="Enter a word to search...")
        self.keyword_entry.grid(row=0, column=1, padx=10, pady=15, sticky="w")

        # 2. Search Target Selection (File or Folder)
        self.type_label = ctk.CTkLabel(self.settings_frame, text="Search Target:", font=ctk.CTkFont(size=16))
        self.type_label.grid(row=1, column=0, padx=10, pady=15, sticky="w")

        self.radio_frame = ctk.CTkFrame(self.settings_frame, fg_color="transparent")
        self.radio_frame.grid(row=1, column=1, padx=10, pady=15, sticky="w")

        self.radio_file = ctk.CTkRadioButton(self.radio_frame, text="Single File", variable=self.search_type, value="file", font=ctk.CTkFont(size=14))
        self.radio_file.pack(side="left", padx=(0, 30))
        
        self.radio_folder = ctk.CTkRadioButton(self.radio_frame, text="Entire Directory (Folder)", variable=self.search_type, value="folder", font=ctk.CTkFont(size=14))
        self.radio_folder.pack(side="left")

        # 3. Path Selection
        self.path_button = ctk.CTkButton(self.settings_frame, text="Browse...", command=self.browse_path, width=120, font=ctk.CTkFont(size=14))
        self.path_button.grid(row=2, column=0, padx=10, pady=15, sticky="w")

        self.path_label = ctk.CTkLabel(self.settings_frame, text="No path selected", text_color="gray", font=ctk.CTkFont(size=14))
        self.path_label.grid(row=2, column=1, padx=10, pady=15, sticky="w")

        # --- Start Search Button ---
        self.search_button = ctk.CTkButton(self.main_frame, text="Start Search", font=ctk.CTkFont(size=16, weight="bold"), height=45, command=self.start_search_thread)
        self.search_button.pack(pady=(10, 20))

        # --- Results Display Section ---
        self.results_label = ctk.CTkLabel(self.main_frame, text="Results:", font=ctk.CTkFont(size=18, weight="bold"))
        self.results_label.pack(anchor="w", padx=20)

        self.results_textbox = ctk.CTkTextbox(self.main_frame, font=ctk.CTkFont(size=14), wrap="word") # Changed to wrap="word" for long sentences
        self.results_textbox.pack(fill="both", expand=True, padx=20, pady=(10, 20))
        self.results_textbox.configure(state="disabled")

        # --- Bottom Status Bar ---
        self.status_label = ctk.CTkLabel(self, text="Ready", anchor="w", text_color="gray")
        self.status_label.pack(fill="x", padx=30, pady=(0, 10))

    def browse_path(self):
        """Open file or directory dialog based on the selected search type."""
        if self.search_type.get() == "file":
            path = filedialog.askopenfilename(title="Select a File")
        else:
            path = filedialog.askdirectory(title="Select a Directory")
        
        if path:
            self.selected_path = path
            self.path_label.configure(text=self.selected_path, text_color="white")

    def start_search_thread(self):
        """Start search in a separate thread to prevent UI freezing."""
        keyword = self.keyword_entry.get().strip()
        
        # Input validation
        if not keyword:
            messagebox.showwarning("Input Error", "Please enter a keyword to search.")
            return
        if not self.selected_path:
            messagebox.showwarning("Input Error", "Please select a file or directory.")
            return

        # Prepare UI for searching
        self.search_button.configure(state="disabled")
        self.results_textbox.configure(state="normal")
        self.results_textbox.delete("1.0", "end")
        self.results_textbox.configure(state="disabled")
        self.status_label.configure(text="Searching... Please wait.")

        # Run search in a daemon thread
        thread = threading.Thread(target=self.perform_search, args=(keyword, self.selected_path, self.search_type.get()))
        thread.daemon = True
        thread.start()

    def perform_search(self, keyword, path, s_type):
        """Core logic for searching text inside files."""
        found_results = []
        
        if s_type == "file":
            matches = self.check_file_for_keyword(path, keyword)
            if matches:
                found_results.append({"path": path, "matches": matches})
        else:
            # Traverse the directory and all its subdirectories
            for root, dirs, files in os.walk(path):
                for file in files:
                    filepath = os.path.join(root, file)
                    # Update status bar to show progress
                    self.status_label.configure(text=f"Scanning: {filepath}")
                    
                    matches = self.check_file_for_keyword(filepath, keyword)
                    if matches:
                        found_results.append({"path": filepath, "matches": matches})

        # Update UI with the final results
        self.update_results(found_results)

    def check_file_for_keyword(self, filepath, keyword):
        """Check if the keyword exists inside the given file and return matching lines."""
        matches = []
        # Attempt to read the file as text (UTF-8)
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if keyword in line:
                        # Append the line number and the text (stripped of extra spaces/newlines)
                        matches.append((line_num, line.strip()))
            return matches
        except UnicodeDecodeError:
            # Fallback to latin-1 if UTF-8 fails
            try:
                with open(filepath, 'r', encoding='latin-1') as f:
                    for line_num, line in enumerate(f, 1):
                        if keyword in line:
                            matches.append((line_num, line.strip()))
                return matches
            except:
                pass # Ignore binary/unreadable files
        except Exception:
            pass # Ignore files lacking read permissions
            
        return matches

    def update_results(self, found_results):
        """Display the found paths and matching lines in the results text box."""
        self.results_textbox.configure(state="normal")
        
        if not found_results:
            self.results_textbox.insert("end", "No matches found.\n")
        else:
            for item in found_results:
                # 1. Insert the File Path
                self.results_textbox.insert("end", f"📁 File: {item['path']}\n")
                
                # 2. Insert the specific lines where the keyword was found
                for line_num, text in item['matches']:
                    self.results_textbox.insert("end", f"   ↳ Line {line_num}: {text}\n")
                
                # Add a separator line for better readability
                self.results_textbox.insert("end", "-" * 60 + "\n\n")
                
        self.results_textbox.configure(state="disabled")
        self.search_button.configure(state="normal")
        self.status_label.configure(text=f"Search completed. Found in {len(found_results)} file(s).")

if __name__ == "__main__":
    app = TextSearchApp()
    app.mainloop()
