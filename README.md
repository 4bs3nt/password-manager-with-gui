# Password Storage

Password Storage is a simple local password manager written in Python using SQLite and CustomTkinter.  
The application provides a graphical interface for storing and managing encrypted credentials.

---

## Description

This project allows you to store login credentials locally in an SQLite database.  
All passwords are encrypted before being saved. The program supports a master password for access control and provides basic actions such as adding, deleting and copying stored credentials.

---

## Features

- Local storage using SQLite  
- Password encryption with `cryptography.Fernet`  
- Master password protection  
- Graphical user interface (CustomTkinter)  
- Clipboard support  
- Context menu (right-click) for actions  
- Add and delete entries  
- Automatic database and encryption key creation  

---

## How it works

Passwords are stored in an SQLite database (`passwords.db`).  
Before saving, each password is encrypted using a locally generated key (`key.key`).

If a master password is set, it is stored in encrypted form (`pass.txt`).  
On application startup, the user must enter the master password to access stored data.

---

## Usage

Run the application:

```bash
python main.py
