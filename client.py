import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox, filedialog
import sqlite3
import hashlib
from datetime import datetime

KEY = "secret"
current_username = None
running = True

def xor_cipher(data, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

def encrypt_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_database():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (country TEXT, username TEXT, password TEXT, location TEXT, dob TEXT)''')
    conn.commit()
    conn.close()

def authenticate():
    global current_username
    user = username_entry.get().strip()
    pwd = password_entry.get().strip()

    if not user or not pwd:
        messagebox.showerror("Authentication Error", "Username and password cannot be blank!")
        return False

    pwd = encrypt_password(pwd)
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (user, pwd))
    result = c.fetchone()
    conn.close()

    if result:
        current_username = user
        login_frame.pack_forget()
        chat_frame.pack()
        create_menu()
        return True

    messagebox.showerror("Authentication Error", "Invalid username or password!")
    return False

def sign_up():
    def create_account():
        country = country_entry.get().strip()
        username = username_entry.get().strip()
        password = password_entry.get().strip()
        location = location_entry.get().strip()
        dob = dob_entry.get().strip()

        if not (country and username and password and location and dob):
            messagebox.showerror("Sign Up Error", "All fields must be filled!")
            return

        password = encrypt_password(password)
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("INSERT INTO users (country, username, password, location, dob) VALUES (?, ?, ?, ?, ?)",
                  (country, username, password, location, dob))
        conn.commit()
        conn.close()
        messagebox.showinfo("Sign Up Successful", "Account created successfully!")
        signup_win.destroy()

    signup_win = tk.Toplevel(root)
    signup_win.title("Sign Up")

    tk.Label(signup_win, text="Country:").pack(pady=5)
    country_entry = tk.Entry(signup_win)
    country_entry.pack(pady=5)

    tk.Label(signup_win, text="Username:").pack(pady=5)
    username_entry = tk.Entry(signup_win)
    username_entry.pack(pady=5)

    tk.Label(signup_win, text="Password:").pack(pady=5)
    password_entry = tk.Entry(signup_win, show='*')
    password_entry.pack(pady=5)

    tk.Label(signup_win, text="Location:").pack(pady=5)
    location_entry = tk.Entry(signup_win)
    location_entry.pack(pady=5)

    tk.Label(signup_win, text="Date of Birth (YYYY-MM-DD):").pack(pady=5)
    dob_entry = tk.Entry(signup_win)
    dob_entry.pack(pady=5)

    create_button = tk.Button(signup_win, text="Create Account", command=create_account)
    create_button.pack(pady=10)

def send_file():
    global current_username
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'rb') as file:
            file_data = file.read()
        file_name = file_path.split("/")[-1]
        message = f"{current_username} sent a file: {file_name}"
        encrypted_msg = xor_cipher(message, KEY)
        encrypted_file_data = xor_cipher(file_data.decode('latin-1'), KEY)
        full_msg = f"{encrypted_msg}\nFILE_DATA:{encrypted_file_data}".encode('utf-8')
        msg_length = len(full_msg)
        send_length = str(msg_length).encode('utf-8')
        send_length += b' ' * (64 - len(send_length))
        client.send(send_length)
        client.send(full_msg)
        update_gui(f"Sent: {message}")

def receive_msg():
    global running
    while running:
        msg_length = client.recv(64).decode('utf-8')
        if msg_length:
            msg_length = int(msg_length)
            msg = client.recv(msg_length).decode('utf-8')
            decrypted_msg, *file_data = msg.split("\nFILE_DATA:")
            decrypted_msg = xor_cipher(decrypted_msg, KEY)
            if file_data:
                # Handle file reception if needed
                pass
            update_gui(f"Received: {decrypted_msg}")

def send_msg():
    global current_username
    msg = message_entry.get().strip()
    if msg:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        full_msg = f"{current_username} ({timestamp}): {msg}"
        encrypted_msg = xor_cipher(full_msg, KEY)
        message = encrypted_msg.encode('utf-8')
        msg_length = len(message)
        send_length = str(msg_length).encode('utf-8')
        send_length += b' ' * (64 - len(send_length))
        client.send(send_length)
        client.send(message)
        update_gui(f"Sent: {full_msg}")
        message_entry.delete(0, tk.END)

def update_gui(message):
    text_area.configure(state="normal")
    text_area.insert(tk.END, message + '\n')
    text_area.configure(state="disabled")
    text_area.see(tk.END)

def exit_application():
    global running
    running = False
    client.close()
    root.destroy()

def clear_chat():
    text_area.configure(state="normal")
    text_area.delete(1.0, tk.END)
    text_area.configure(state="disabled")


def create_menu():
    menu = tk.Menu(root)
    root.config(menu=menu)
    file_menu = tk.Menu(menu, tearoff=0)
    menu.add_cascade(label="File", menu=file_menu)
    file_menu.add_command(label="Send File", command=send_file)
    file_menu.add_command(label="Clear Chat", command=clear_chat)  # Clear chat option
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=exit_application)

# Database creation
create_database()

SERVER = "127.0.0.1"
PORT = 5050

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((SERVER, PORT))

root = tk.Tk()
root.title("Client")
root.geometry("900x800")

# Login Frame
login_frame = tk.Frame(root)
login_frame.pack(pady=20)

tk.Label(login_frame, text="Username:", font=("Helvetica", 14)).pack(pady=5)
username_entry = tk.Entry(login_frame, font=("Helvetica", 14))
username_entry.pack(pady=5)

tk.Label(login_frame, text="Password:", font=("Helvetica", 14)).pack(pady=5)
password_entry = tk.Entry(login_frame, show='*', font=("Helvetica", 14))
password_entry.pack(pady=5)

login_button = tk.Button(login_frame, text="Login", command=authenticate, font=("Helvetica", 14))
login_button.pack(pady=10)

signup_button = tk.Button(login_frame, text="Sign Up", command=sign_up, font=("Helvetica", 14))
signup_button.pack(pady=10)

# Chat Frame
chat_frame = tk.Frame(root)

text_area = scrolledtext.ScrolledText(chat_frame, wrap=tk.WORD, width=100, height=30, font=("Helvetica", 14))
text_area.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
text_area.configure(state="disabled")

message_frame = tk.Frame(chat_frame)
message_frame.pack(pady=10)

message_entry = tk.Entry(message_frame, width=70, font=("Helvetica", 14))
message_entry.pack(side=tk.LEFT, padx=10)

send_button = tk.Button(message_frame, text="Send", command=send_msg, width=10, font=("Helvetica", 14))
send_button.pack(side=tk.LEFT, padx=10)


thread = threading.Thread(target=receive_msg)
thread.start()

root.mainloop()
