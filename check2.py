import os
import customtkinter as ctk
from tkinter import filedialog, messagebox

# ==========================================
# Application Settings (Modern Theme)
# ==========================================
ctk.set_appearance_mode("Dark")  # Options: "System", "Dark", "Light"
ctk.set_default_color_theme("blue")  # Options: "blue", "green", "dark-blue"

window = ctk.CTk()
window.title("Modern File Checker (Linux Ready)")
# Make the window larger
window.geometry("850x800")
window.minsize(700, 600)

# Global variable to store the selected Linux path
selected_folder_path = ""

# ==========================================
# Functions
# ==========================================
def select_folder():
    """Opens Linux file explorer to select a directory or mounted drive."""
    global selected_folder_path
    folder_path = filedialog.askdirectory(title="Select Target Folder or Linux Drive")
    
    if folder_path:
        selected_folder_path = folder_path
        # Truncate path for display if it's too long
        display_path = folder_path if len(folder_path) < 60 else "..." + folder_path[-57:]
        folder_label.configure(text=display_path, text_color="#2ECC71") # Green color for success

def check_files():
    """Compares the text input with the selected directory contents."""
    global selected_folder_path
    
    if not selected_folder_path:
        messagebox.showwarning("Warning", "Please select a target folder or drive first!")
        return
    
    input_text = text_input.get("1.0", ctk.END)
    # Extract filenames, ignoring empty lines
    target_files = [line.strip() for line in input_text.split('\n') if line.strip()]
    
    if not target_files:
        messagebox.showwarning("Warning", "Please enter at least one filename to check!")
        return

    # Try reading the Linux directory
    try:
        folder_files = set(os.listdir(selected_folder_path))
    except PermissionError:
        messagebox.showerror("Permission Denied", "You do not have permission to read this Linux directory.")
        return
    except Exception as e:
        messagebox.showerror("Error", f"Could not read the directory:\n{e}")
        return

    # Compare
    found_files = []
    missing_files = []

    for file_name in target_files:
        if file_name in folder_files:
            found_files.append(file_name)
        else:
            missing_files.append(file_name)

    # Display Results
    result_output.configure(state="normal")
    result_output.delete("1.0", ctk.END)
    
    result_output.insert(ctk.END, "====== FOUND FILES ======\n")
    if found_files:
        for f in found_files:
            result_output.insert(ctk.END, f"  [ ✓ ] {f}\n")
    else:
        result_output.insert(ctk.END, "  None\n")
        
    result_output.insert(ctk.END, "\n====== MISSING FILES ======\n")
    if missing_files:
        for f in missing_files:
            result_output.insert(ctk.END, f"  [ ✗ ] {f}\n")
    else:
        result_output.insert(ctk.END, "  None\n")
        
    result_output.configure(state="disabled")

# ==========================================
# Modern GUI Layout
# ==========================================
# Main Title
title_label = ctk.CTkLabel(window, text="File Existence Checker", font=ctk.CTkFont(size=28, weight="bold"))
title_label.pack(pady=(20, 10))

# Step 1
step1_label = ctk.CTkLabel(window, text="1. Enter filenames to check (one per line):", font=ctk.CTkFont(size=16))
step1_label.pack(anchor="w", padx=30)

text_input = ctk.CTkTextbox(window, height=180, font=ctk.CTkFont(family="Consolas", size=14))
text_input.pack(padx=30, pady=(5, 20), fill="x")

# Step 2
step2_label = ctk.CTkLabel(window, text="2. Select target folder (Local or Mounted Linux Drive):", font=ctk.CTkFont(size=16))
step2_label.pack(anchor="w", padx=30)

folder_frame = ctk.CTkFrame(window, fg_color="transparent")
folder_frame.pack(fill="x", padx=30, pady=(5, 20))

browse_btn = ctk.CTkButton(folder_frame, text="Browse Directory", command=select_folder, 
                           font=ctk.CTkFont(size=14, weight="bold"), width=150, height=40)
browse_btn.pack(side="left")

folder_label = ctk.CTkLabel(folder_frame, text="No directory selected", text_color="gray", font=ctk.CTkFont(size=14))
folder_label.pack(side="left", padx=15)

# Step 3
check_btn = ctk.CTkButton(window, text="3. CHECK FILES", command=check_files, 
                          fg_color="#27AE60", hover_color="#219653", # Modern Green
                          font=ctk.CTkFont(size=18, weight="bold"), height=50)
check_btn.pack(pady=10, padx=30, fill="x")

# Step 4 (Results)
step4_label = ctk.CTkLabel(window, text="Results:", font=ctk.CTkFont(size=16))
step4_label.pack(anchor="w", padx=30)

result_output = ctk.CTkTextbox(window, font=ctk.CTkFont(family="Consolas", size=15), state="disabled")
result_output.pack(padx=30, pady=(5, 20), fill="both", expand=True)

# Start Application
window.mainloop()
