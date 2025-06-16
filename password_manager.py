import sqlite3
from cryptography.fernet import Fernet
from tkinter import *
from tkinter import messagebox
import pyperclip 
import os

base_dir = os.path.dirname(os.path.abspath(__file__))
password_file = os.path.join(base_dir, "pass.txt")
db_file = os.path.join(base_dir, "passwords.sqlite")

key_path = os.path.join(base_dir, "key.key")
if not os.path.exists(key_path):
    key = Fernet.generate_key()
    with open(key_path, "wb") as key_file:
        key_file.write(key)

with open(key_path, "rb") as key_file:
    key = key_file.read()

fernet = Fernet(key)

try:
    with open(password_file, "r") as f:#открытие файла с паролем
        security_password = f.read().strip()
except FileNotFoundError:
    security_password = ""#если файл не найден, то пароль не установлен

connection = sqlite3.connect(db_file)#хранение базы паролей
cursor = connection.cursor()

cursor.execute(
    """
CREATE TABLE IF NOT EXISTS
passwords(
    name TEXT UNIQUE,
    password TEXT
)
""")#создание таблицы паролей, если она не существует 

def copy_name():
    selected = listbox.get(listbox.curselection())
    name = selected.split("Name: ")[1].split("    Password:")[0]#сначало сплитить имя выводя массив с паролем и именем, потом выбрать имя в следующей строке 
    pyperclip.copy(name)

def copy_password():
    selected = listbox.get(listbox.curselection())
    password = selected.split("Password: ")[1]#сплит пароля -> остается только пароль и копирование в следующей строке 
    pyperclip.copy(password)

def copy_all():
    pyperclip.copy(listbox.get(listbox.curselection()))#копирует всё выбранное поле в листбоксе

def delete_combo():
    selected = listbox.get(listbox.curselection())
    name = selected.split("Name: ")[1].split("     Password:")[0]
    delete_data(name)

def show_menu(event):
    menu.post(event.x_root, event.y_root)#функция для вызова меню при нажатии правой кнопки мыши

def add_data(name, password):#добавление данные в таблицу
    if not name or not password:
        messagebox.showerror("Error","Fields cant be empty")
    else:
        try:
            encrypted_password = fernet.encrypt(password.encode()).decode()
            cursor.execute(
                """
            INSERT INTO 
                passwords(name, password)
            VALUES 
                (?,?)
            """,
                (name, encrypted_password)

                           )
            connection.commit()
            print_data()#помогает обновить данные в таблице
        except sqlite3.IntegrityError:
            messagebox.showerror("Error","Name must be unique!")


def add_data_btn():#функция кнопки добавления данных 
    adds = Toplevel(password_window)
    adds.title("Add Data")
    adds.geometry("300x200")

    name_label = Label(adds, text="Name")
    name_label.pack()
    name_entry = Entry(adds)
    name_entry.pack()

    password_label = Label(adds, text="Password")
    password_label.pack()
    password_entry = Entry(adds)
    password_entry.pack()

    btn1 = Button(adds, text="Add combo", command=lambda: add_data(name_entry.get(), password_entry.get()))#получаем данные из полей ввода и добавляем в таблицу(без лямбды не работает)
    btn1.pack()
    
def delete_data(name):#удаление данных из таблицы
    cursor.execute(
        """
        DELETE FROM passwords 
        WHERE name = ? 
        """,
        (name,)   
    )
    connection.commit()
    print_data()#помогает обновить данные в таблице

def security_check():#проверка пароля
    if security_entry.get() == security_password:#если пароль введенный в окне совпадает с паролем в файле, то открывается доступ к программе 
        security_window.destroy()#окно для ввода пароля закрывается
        print_data()#вывод базы данных в листбокс
        add_button.config(state=NORMAL)#кнопки добавления, удаления и добавления пароля становятся активными
        security_add.config(state=NORMAL)
    else:
        messagebox.showerror("Error", "Invalid security code")#если пароль не совпадает, то выводится сообщение об ошибке

def security_add_btn():#добавление пароля
    add_security = Toplevel(password_window)#окно для ввода пароля
    add_security.title("Add Security")
    add_security.geometry("300x200")

    security_label = Label(add_security, text="Security")
    security_label.pack()

    security_key = Entry(add_security)#поле для ввода пароля
    security_key.pack()


    btn3 = Button(add_security, text="Add", command=lambda: security_to_file(security_key.get()))#кнопка для добавления пароля
    btn3.pack()

    def security_to_file(security_key):#добавление пароля в файл
        # Записываем пароль в файл
        with open(password_file, "w") as f:
            f.write(security_key)
        add_security.destroy()#окно для ввода пароля закрывается
    
def print_data():#вывод данных в листбокс

    cursor.execute("SELECT * FROM passwords")
    values = cursor.fetchall()
    listbox.delete(0, END)#полная очистка листбокса 
    for value in values:
        try:
            decrypted_password = fernet.decrypt(value[1].encode()).decode()
        except:
            decrypted_password = "[UNREADABLE]"
        print(f"name: {value[0]}, password: {decrypted_password}")
        listbox.insert(END, "Name: " + value[0] + "    " + " Password: " + decrypted_password)#добавляет данные в листбокс в ввиде:   Name:что-то Password: что-то

password_window = Tk()#основное окно 
password_window.title("Password Storage")
password_window.geometry("1000x750")


text = Label(password_window, text="Password Storage")#текст в окне
text.pack()

listbox = Listbox(password_window, width=150, height=30, selectmode=SINGLE)#листбокс для показа данных
listbox.pack()

add_button = Button(password_window, text="Add", command=add_data_btn, width=10, height=2, state=DISABLED)#кнопка добавления данных
add_button.pack(anchor=S)

security_add = Button(password_window, text="Add Security", command=security_add_btn, width=10, height=2, state=DISABLED)#кнопка для добавления пароля
security_add.pack(anchor=S)

menu = Menu(password_window, tearoff=0)#меню при нажатии правой кнопки мыши

menu.add_command(label="Copy Name", command=copy_name)#копирование имени
menu.add_command(label="Copy Password", command=copy_password)#копирование пароля
menu.add_command(label="Copy All", command=copy_all)#копирование всего поля
menu.add_command(label="Delete combo", command=delete_combo)

listbox.bind("<Button-3>", show_menu)#при нажатии правой кнопки мыши вызывается меню

if security_password == "":#если пароль не установлен, то открывается доступ к программе 
    print_data()#вывод базы данных в листбокс
    add_button.config(state=NORMAL)#кнопки добавления, добавления пароля становятся активными
    security_add.config(state=NORMAL)


else:#если пароль установлен, то открывается окно для ввода пароля
    security_window = Tk()
    security_window.title("Security")
    security_window.geometry("300x100")

    security_label = Label(security_window, text="Security Check")
    security_label.pack()

    security_entry = Entry(security_window)
    security_entry.pack()

    security_button = Button(security_window, text="Check", command=lambda: security_check())
    security_button.pack()

password_window.mainloop()






