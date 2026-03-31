import os
import tkinter as tk
from tkinter import filedialog, messagebox

def select_folder():
    """Opens a dialog to select a target directory."""
    folder_path = filedialog.askdirectory()
    if folder_path:
        folder_label.config(text=folder_path)
        # Store the selected path in the window object
        window.selected_folder = folder_path

def check_files():
    """Compares the input filenames with the files in the selected directory."""
    # 1. Validate if a folder is selected
    if not hasattr(window, 'selected_folder') or not window.selected_folder:
        messagebox.showwarning("Warning", "Please select a target folder first!")
        return
    
    # 2. Get filenames from the input text area
    input_text = text_input.get("1.0", tk.END)
    # Split by lines, strip whitespace, and ignore empty lines
    target_files = [line.strip() for line in input_text.split('\n') if line.strip()]
    
    if not target_files:
        messagebox.showwarning("Warning", "Please enter at least one filename to check!")
        return

    # 3. Get the list of files in the selected folder
    try:
        # Using a set for faster lookup
        folder_files = set(os.listdir(window.selected_folder))
    except Exception as e:
        messagebox.showerror("Error", f"Could not read the selected folder:\n{e}")
        return

    # 4. Compare lists
    found_files = []
    missing_files = []

    for file_name in target_files:
        if file_name in folder_files:
            found_files.append(file_name)
        else:
            missing_files.append(file_name)

    # 5. Display the results
    result_output.config(state=tk.NORMAL) # Enable editing to insert text
    result_output.delete("1.0", tk.END)   # Clear previous results
    
    # Print Found Files
    result_output.insert(tk.END, "--- FOUND FILES (موجودة) ---\n", "success")
    if found_files:
        for f in found_files:
            result_output.insert(tk.END, f"✓ {f}\n")
    else:
        result_output.insert(tk.END, "None\n")
        
    result_output.insert(tk.END, "\n--- MISSING FILES (غير موجودة) ---\n", "error")
    # Print Missing Files
    if missing_files:
        for f in missing_files:
            result_output.insert(tk.END, f"✗ {f}\n")
    else:
        result_output.insert(tk.END, "None\n")
        
    result_output.config(state=tk.DISABLED) # Make read-only again

# ==========================================
# GUI Setup
# ==========================================
window = tk.Tk()
window.title("File Existence Checker")
window.geometry("550x650")
window.configure(padx=20, pady=20)

# Step 1: Input filenames
tk.Label(window, text="1. Enter filenames to check (one file per line):", font=("Arial", 10, "bold")).pack(anchor="w")
text_input = tk.Text(window, height=10, width=60, font=("Consolas", 10))
text_input.pack(pady=(5, 15))

# Step 2: Select Folder
tk.Label(window, text="2. Select the target folder to search inside:", font=("Arial", 10, "bold")).pack(anchor="w")
folder_frame = tk.Frame(window)
folder_frame.pack(fill="x", pady=(5, 15))

browse_btn = tk.Button(folder_frame, text="Browse Folder", command=select_folder, width=15)
browse_btn.pack(side="left")

folder_label = tk.Label(folder_frame, text="No folder selected", fg="blue", wraplength=350)
folder_label.pack(side="left", padx=10)

# Step 3: Action Button
check_btn = tk.Button(window, text="3. Check Files", command=check_files, bg="#4CAF50", fg="white", font=("Arial", 12, "bold"), width=20)
check_btn.pack(pady=10)

# Step 4: Output Results
tk.Label(window, text="Results:", font=("Arial", 10, "bold")).pack(anchor="w")
result_output = tk.Text(window, height=12, width=60, font=("Consolas", 10), state=tk.DISABLED, bg="#f4f4f4")
result_output.pack(pady=5)

# Configure text colors for results
result_output.tag_config("success", foreground="green", font=("Consolas", 10, "bold"))
result_output.tag_config("error", foreground="red", font=("Consolas", 10, "bold"))

# Start the application
window.mainloop()
