import os
import hashlib
from cryptography.fernet import Fernet
import tkinter as tk
import mimetypes
from tkinter import filedialog, messagebox, scrolledtext
from datetime import datetime
from PIL import Image
from PIL.ExifTags import TAGS

#Generating key
def generate_key():
    return Fernet.generate_key()

#loading the key
def load_key(key_path):
    with open(key_path, 'rb') as key_file:
        return key_file.read()

#saving to the file
def save_key(key, key_path):
    with open(key_path, 'wb') as key_file:
        key_file.write(key)

#encryption
def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)
    return "File encrypted successfully."

#decryption
def decrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(file_path, 'wb') as file:
        file.write(decrypted_data)
    return "File decrypted successfully."

#date and time
def format_timestamp(ts):
    return datetime.utcfromtimestamp(ts).strftime('%I:%M %p %d-%m-%Y')

def format_permissions(st_mode):
    is_dir = 'Directory' if os.path.isdir(st_mode) else 'File'
    perm = ''.join(['read ' if st_mode & (256 >> i * 3) else 'no permission ' for i in range(3)])
    perm += ''.join(['write ' if st_mode & (128 >> i * 3) else 'no permission ' for i in range(3)])
    perm += ''.join(['execute ' if st_mode & (64 >> i * 3) else 'no permission ' for i in range(3)])
    return f"{is_dir}: {perm.strip()}"

#file analysis
def analyze_file(file_path):
    report = []
    file_info = {}

    file_info['File Name'] = os.path.basename(file_path)
    file_info['File Path'] = file_path
    file_info['File Size'] = os.path.getsize(file_path)
    file_info['File Creation Date'] = format_timestamp(os.path.getctime(file_path))
    file_info['File Modification Date'] = format_timestamp(os.path.getmtime(file_path))
    file_info['File Access Date'] = format_timestamp(os.path.getatime(file_path))

    with open(file_path, 'rb') as f:
        file_data = f.read()
        file_info['SHA-512'] = hashlib.sha512(file_data).hexdigest()

    file_info['MIME Type'] = mimetypes.guess_type(file_path)[0]
    file_info['File Extension'] = os.path.splitext(file_path)[1]

    file_info['File Permissions'] = format_permissions(os.stat(file_path).st_mode)
    file_info['File Owner'] = os.stat(file_path).st_uid

    if file_info['MIME Type'] and file_info['MIME Type'].startswith('image'):
        image = Image.open(file_path)
        file_info['Image Dimensions'] = image.size
        file_info['Image Color Depth'] = image.mode

        exif_data = image._getexif()
        if exif_data:
            exif = {TAGS.get(tag): value for tag, value in exif_data.items()}
            file_info['EXIF Data'] = exif

    report.append(file_info)
    return report

#hashing
def generate_file_hash(file_path):
    with open(file_path, 'rb') as f:
        file_data = f.read()
        return hashlib.sha512(file_data).hexdigest()

#comparision of files
def compare_files(file1, file2):
    hash1 = generate_file_hash(file1)
    hash2 = generate_file_hash(file2)
    return hash1 == hash2, hash1, hash2

#GUI USING TKINTER
class ForensicsToolkit:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Forensics Toolkit")
        self.root.geometry("600x400")

        self.frame = tk.Frame(root, bg='#2b2b2b')
        self.frame.pack(fill=tk.BOTH, expand=True)

        self.title_label = tk.Label(self.frame, text="Digital Forensics Toolkit", font=("Arial", 24, "bold"), bg='#2b2b2b', fg='white')
        self.title_label.pack(pady=20)

        button_frame = tk.Frame(self.frame, bg='#2b2b2b')
        button_frame.pack(pady=10)

        self.encrypt_button = tk.Button(button_frame, text="Encrypt File", command=self.encrypt_file, bg='#1f77b4', fg='white', font=("Arial", 12), width=20)
        self.encrypt_button.grid(row=0, column=0, padx=10, pady=10)

        self.decrypt_button = tk.Button(button_frame, text="Decrypt File", command=self.decrypt_file, bg='#1f77b4', fg='white', font=("Arial", 12), width=20)
        self.decrypt_button.grid(row=0, column=1, padx=10, pady=10)

        self.analyze_button = tk.Button(button_frame, text="Analyze File", command=self.analyze, bg='#1f77b4', fg='white', font=("Arial", 12), width=20)
        self.analyze_button.grid(row=1, column=0, padx=10, pady=10)

        self.integrity_button = tk.Button(button_frame, text="Test File Integrity", command=self.test_integrity, bg='#1f77b4', fg='white', font=("Arial", 12), width=20)
        self.integrity_button.grid(row=1, column=1, padx=10, pady=10)

        self.exit_button = tk.Button(self.frame, text="Exit", command=self.root.quit, bg='#d62728', fg='white', font=("Arial", 12), width=20)
        self.exit_button.pack(pady=20)

    def encrypt_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            key_path = filedialog.asksaveasfilename(title="Save Key", defaultextension=".key")
            if key_path:
                key = generate_key()
                save_key(key, key_path)
                result = encrypt_file(file_path, key)
                messagebox.showinfo("Encrypt File", result)

    def decrypt_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            key_path = filedialog.askopenfilename(title="Select Key File", filetypes=[("Key Files", "*.key")])
            if key_path:
                key = load_key(key_path)
                result = decrypt_file(file_path, key)
                messagebox.showinfo("Decrypt File", result)

    def analyze(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.analysis_data = analyze_file(file_path)
            self.display_report(self.analysis_data)

    def test_integrity(self):
        file1 = filedialog.askopenfilename(title="Select the original file")
        if file1:
            file2 = filedialog.askopenfilename(title="Select the file to compare")
            if file2:
                is_same, hash1, hash2 = compare_files(file1, file2)
                if is_same:
                    messagebox.showinfo("Integrity Check", f"The files are identical.\n\nFile 1: {file1}\nHash: {hash1}\n\nFile 2: {file2}\nHash: {hash2}")
                else:
                    messagebox.showinfo("Integrity Check", f"The files are different.\n\nFile 1: {file1}\nHash: {hash1}\n\nFile 2: {file2}\nHash: {hash2}")

    def display_report(self, data):
        report_window = tk.Toplevel(self.root)
        report_window.title("Report")
        report_window.geometry("800x600")

        text_area = scrolledtext.ScrolledText(report_window, wrap=tk.WORD, bg='#333333', fg='white', font=("Arial", 12))
        text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        for entry in data:
            for key, value in entry.items():
                if isinstance(value, dict):  # Handling nested dictionaries like EXIF data
                    text_area.insert(tk.END, f"{key}:\n")
                    for subkey, subvalue in value.items():
                        text_area.insert(tk.END, f"    {subkey}: {subvalue}\n")
                else:
                    text_area.insert(tk.END, f"{key}: {value}\n")
            text_area.insert(tk.END, "\n")

        text_area.configure(state='disabled')

if __name__ == "__main__":  
    root = tk.Tk()
    app = ForensicsToolkit(root)
    root.mainloop()