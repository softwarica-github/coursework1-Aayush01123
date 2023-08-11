import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk, simpledialog, messagebox

KEY = "secret"
USERNAME = "admin123"
PASSWORD = "9988"
LOG_KEY = "logkey123"

def xor_cipher(data, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

def handle_client(conn, addr):
    clients[addr] = conn
    usernames[addr] = None
    update_clients_dropdown()
    update_gui(f"New connection from {addr}!", encrypted=True)
    connected = True
    while connected:
        if addr not in clients:  # Check if client is still in the list
            break
        msg_length = conn.recv(64).decode('utf-8')
        if msg_length:
            msg_length = int(msg_length)
            msg = conn.recv(msg_length).decode('utf-8')
            decrypted_msg = xor_cipher(msg, KEY)
            if addr in usernames and not usernames[addr]:
                usernames[addr] = decrypted_msg.split(":")[0]
            update_gui(f"Received from {usernames[addr] if addr in usernames else addr}: {decrypted_msg}", encrypted=True)
            for other_conn in clients.values():
                if other_conn != conn:
                    send_length = str(msg_length).encode('utf-8')
                    send_length += b' ' * (64 - len(send_length))
                    other_conn.send(send_length)
                    other_conn.send(msg.encode('utf-8'))
        else:
            connected = False
            conn.close()

    update_gui(f"{addr} has disconnected.", encrypted=True)
    if addr in clients:
        del clients[addr]
    if addr in usernames:
        del usernames[addr]
    update_clients_dropdown()


def start():
    server.listen()
    update_gui(f"Server is listening on {SERVER}:{PORT}", encrypted=True)
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        update_gui(f"Active connections: {threading.activeCount() - 1}", encrypted=True)

def update_gui(message, encrypted=False):
    if encrypted:
        message = xor_cipher(message, LOG_KEY)
    text_area.configure(state="normal")
    text_area.insert(tk.END, message + '\n')
    text_area.configure(state="disabled")
    text_area.see(tk.END)

def update_clients_dropdown():
    client_list['values'] = [usernames[client] if usernames[client] else f"{client[0]}:{client[1]}" for client in clients.keys()]
    if client_list['values']:
        client_list.current(0)


def remove_client():
    selected_username = client_list.get()
    selected_client = None
    for client, username in usernames.items():
        if username == selected_username or f"{client[0]}:{client[1]}" == selected_username:
            selected_client = client
            break

    if selected_client:
        clients[selected_client].close()  # Close the socket connection
        update_gui(f"Removed client {selected_username} ({selected_client[0]}:{selected_client[1]})", encrypted=True)
        del clients[selected_client]
        del usernames[selected_client]
        update_clients_dropdown()


def authenticate():
    auth_window = tk.Toplevel(root)
    auth_window.title("Authentication")
    auth_window.geometry("300x300")

    tk.Label(auth_window, text="Username:", font=("Helvetica", 14)).pack(pady=10)
    username_entry = tk.Entry(auth_window, font=("Helvetica", 14))
    username_entry.pack(pady=5)

    tk.Label(auth_window, text="Password:", font=("Helvetica", 14)).pack(pady=10)
    password_entry = tk.Entry(auth_window, show='*', font=("Helvetica", 14))
    password_entry.pack(pady=5)

    def verify():
        user = username_entry.get().strip()
        pwd = password_entry.get().strip()
        if not user or not pwd:
            messagebox.showerror("Input Error", "Username and password should not be blank!")
        elif user != USERNAME or pwd != PASSWORD:
            messagebox.showerror("Authentication Error", "Invalid username or password!")
        else:
            auth_window.destroy()
            root.deiconify()

    login_button = tk.Button(auth_window, text="Login", command=verify, font=("Helvetica", 14))
    login_button.pack(pady=10)

SERVER = "127.0.0.1"
PORT = 5050
ADDR = (SERVER, PORT)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

clients = {}
usernames = {}

root = tk.Tk()
root.withdraw()
root.title("Server")
root.geometry("800x800")

text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=30, font=("Helvetica", 14))
text_area.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
text_area.configure(state="disabled")

control_frame = tk.Frame(root)
control_frame.pack(pady=10)

client_list = ttk.Combobox(control_frame, values=[], font=("Helvetica", 14))
client_list.pack(side=tk.LEFT, padx=10)

remove_button = tk.Button(control_frame, text="Remove User", command=remove_client, font=("Helvetica", 14))
remove_button.pack(side=tk.LEFT, padx=10)

if not authenticate():
    root.quit()

thread = threading.Thread(target=start)
thread.start()

root.mainloop()
