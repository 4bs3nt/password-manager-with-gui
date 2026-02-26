import os
import sqlite3
import pyperclip
from cryptography.fernet import Fernet
import customtkinter as ctk
from tkinter import Menu, messagebox

base_dir = os.path.dirname(os.path.abspath(__file__))
password_file = os.path.join(base_dir, "pass.txt")
db_file = os.path.join(base_dir, "passwords.db")

key_path = os.path.join(base_dir, "key.key")
if not os.path.exists(key_path):
    key = Fernet.generate_key()
    with open(key_path, "wb") as key_file:
        key_file.write(key)

with open(key_path, "rb") as key_file:
    key = key_file.read()

fernet = Fernet(key)

try:
    with open(password_file, "r") as f:
        security_password = f.read().strip()
except FileNotFoundError:
    security_password = ""

connection = sqlite3.connect(db_file)
cursor = connection.cursor()
cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS passwords(
        name TEXT UNIQUE,
        password TEXT
    )
    """
)
connection.commit()

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("Password Storage")
app.geometry("900x650")


header = ctk.CTkFrame(app, corner_radius=12)
header.pack(fill="x", padx=16, pady=(16, 8))

body = ctk.CTkFrame(app, corner_radius=12)
body.pack(fill="both", expand=True, padx=16, pady=8)

footer = ctk.CTkFrame(app, corner_radius=12)
footer.pack(fill="x", padx=16, pady=(8, 16))

title_label = ctk.CTkLabel(header, text="Password Storage", font=ctk.CTkFont(size=22, weight="bold"))
title_label.pack(padx=12, pady=12)


scroll = ctk.CTkScrollableFrame(body, corner_radius=10)
scroll.pack(fill="both", expand=True, padx=12, pady=12)


menu = Menu(app, tearoff=0)


add_button = ctk.CTkButton(footer, text="New password", width=120, state="disabled")
add_button.pack(side="left", padx=8, pady=12)

security_add = ctk.CTkButton(footer, text="Set Master Password", width=140, state="disabled")
security_add.pack(side="left", padx=8, pady=12)


current_selected = {"name": None, "password": None, "frame": None}

def set_selected(frame, name, password):
    if current_selected["frame"] is not None:
        try:
            current_selected["frame"].configure(border_width=0)
        except Exception:
            pass
    current_selected["name"] = name
    current_selected["password"] = password
    current_selected["frame"] = frame
    try:
        frame.configure(border_width=2, border_color=("gray55", "gray60"))
    except Exception:
        pass

def print_data():
    for child in scroll.winfo_children():
        child.destroy()

    cursor.execute("SELECT name, password FROM passwords")
    values = cursor.fetchall()

    for name, enc_pass in values:
        try:
            decrypted_password = fernet.decrypt(enc_pass.encode()).decode()
        except Exception:
            decrypted_password = "[UNREADABLE]"

        row = ctk.CTkFrame(scroll, corner_radius=8, border_width=0)
        row.pack(fill="x", padx=6, pady=(4, 0))
        row.grid_columnconfigure(0, weight=1)
        row.grid_columnconfigure(1, weight=1)

        name_label = ctk.CTkLabel(row, text=f"Name: {name}", anchor="w")
        name_label.grid(row=0, column=0, sticky="ew", padx=10, pady=8)

        pass_label = ctk.CTkLabel(row, text=f"Password: {decrypted_password}", anchor="e")
        pass_label.grid(row=0, column=1, sticky="ew", padx=10, pady=8)


        def bind_all(widget):
            widget.bind("<Button-1>", lambda e, fr=row, n=name, p=decrypted_password: set_selected(fr, n, p))
            widget.bind("<Button-3>", lambda e, fr=row, n=name, p=decrypted_password: on_right_click(e, fr, n, p))

        bind_all(row)
        bind_all(name_label)
        bind_all(pass_label)


        sep = ctk.CTkFrame(scroll, height=1, fg_color=("gray75", "gray25"))
        sep.pack(fill="x", padx=6, pady=(4, 4))

def add_data(name: str, password: str):
    if not name or not password:
        messagebox.showerror("Error", "Fields cant be empty")
        return
    try:
        encrypted_password = fernet.encrypt(password.encode()).decode()
        cursor.execute(
            "INSERT INTO passwords(name, password) VALUES (?, ?)",
            (name, encrypted_password)
        )
        connection.commit()
        print_data()
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Name must be unique!")

def delete_data(name: str):
    cursor.execute("DELETE FROM passwords WHERE name = ?", (name,))
    connection.commit()
    print_data()

def ensure_selected():
    if current_selected["name"] is None:
        messagebox.showerror("Error", "Select a row first")
        return False
    return True

def copy_name():
    if not ensure_selected():
        return
    pyperclip.copy(current_selected["name"])

def copy_password():
    if not ensure_selected():
        return
    pyperclip.copy(current_selected["password"])

def copy_all():
    if not ensure_selected():
        return
    pyperclip.copy(f"Name: {current_selected['name']}    Password: {current_selected['password']}")

def delete_combo():
    if not ensure_selected():
        return
    delete_data(current_selected["name"])

def on_right_click(event, frame, name, password):
    set_selected(frame, name, password)
    try:
        menu.tk_popup(event.x_root, event.y_root)
    finally:
        menu.grab_release()

def add_data_btn():
    win = ctk.CTkToplevel(app)
    win.title("Add Data")
    win.geometry("360x240")
    win.grab_set()

    frame = ctk.CTkFrame(win, corner_radius=12)
    frame.pack(fill="both", expand=True, padx=12, pady=12)

    name_label = ctk.CTkLabel(frame, text="Name")
    name_label.pack(pady=(10, 4))
    name_entry = ctk.CTkEntry(frame, width=260, placeholder_text="service/login")
    name_entry.pack(pady=4)

    pass_label = ctk.CTkLabel(frame, text="Password")
    pass_label.pack(pady=(10, 4))
    pass_entry = ctk.CTkEntry(frame, width=260, show="•", placeholder_text="password")
    pass_entry.pack(pady=4)

    def on_add():
        add_data(name_entry.get().strip(), pass_entry.get())
        win.destroy()

    btn = ctk.CTkButton(frame, text="Add combo", command=on_add)
    btn.pack(pady=12)

def security_to_file(win, value: str):
    with open(password_file, "w") as f:
        enc = fernet.encrypt(value.encode()).decode()
        f.write(enc)
    win.destroy()

def security_add_btn():
    win = ctk.CTkToplevel(app)
    win.title("Add Security")
    win.geometry("360x180")
    win.grab_set()

    frame = ctk.CTkFrame(win, corner_radius=12)
    frame.pack(fill="both", expand=True, padx=12, pady=12)

    label = ctk.CTkLabel(frame, text="New Security Password")
    label.pack(pady=(10, 6))
    entry = ctk.CTkEntry(frame, width=260, show="•", placeholder_text="new master password")
    entry.pack(pady=6)

    btn = ctk.CTkButton(frame, text="Add", command=lambda: security_to_file(win, entry.get()))
    btn.pack(pady=12)

def security_check(entry, win):
    try:
        with open(password_file, "r") as f:
            enc = f.read().strip()
        password_decrypted = fernet.decrypt(enc.encode()).decode()
    except Exception:
        password_decrypted = ""

    if entry.get() == password_decrypted:
        win.destroy()
        print_data()
        add_button.configure(state="normal")
        security_add.configure(state="normal")
    else:
        messagebox.showerror("Error", "Invalid security code")

add_button.configure(command=add_data_btn)
security_add.configure(command=security_add_btn)

menu.add_command(label="Copy Name", command=copy_name)
menu.add_command(label="Copy Password", command=copy_password)
menu.add_command(label="Copy All", command=copy_all)
menu.add_command(label="Delete combo", command=delete_combo)

if security_password == "":
    print_data()
    add_button.configure(state="normal")
    security_add.configure(state="normal")
else:
    sec_win = ctk.CTkToplevel(app)
    sec_win.title("Security")
    sec_win.geometry("360x160")
    sec_win.grab_set()

    frame = ctk.CTkFrame(sec_win, corner_radius=12)
    frame.pack(fill="both", expand=True, padx=12, pady=12)

    lbl = ctk.CTkLabel(frame, text="Security Check")
    lbl.pack(pady=(10, 6))
    sec_entry = ctk.CTkEntry(frame, width=260, show="•", placeholder_text="master password")
    sec_entry.pack(pady=6)
    btn = ctk.CTkButton(frame, text="Check", command=lambda: security_check(sec_entry, sec_win))
    btn.pack(pady=10)

def on_close():
    try:
        connection.close()
    except Exception:
        pass
    app.destroy()

app.protocol("WM_DELETE_WINDOW", on_close)
app.mainloop()
