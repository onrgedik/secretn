import tkinter.messagebox
from tkinter import *
import tkinter
from tkinter import PhotoImage
from tkinter.filedialog import asksaveasfile
from cryptography.fernet import Fernet





window = Tk()
window.title("Secret Notes")
window.geometry("400x720")
img = PhotoImage(file="notimage.png")
#key = Fernet.generate_key() + secret_key(encode)
#chipher_suite = Fernet(key)
#f_key = chipher_suite.decrypt(chipher_suite.encrypt(key))
def generate_key(secret_key):
    return Fernet.generate_key() + secret_key.encode()

#Resim label
img_label = Label(window, image = img)
img_label.pack(side="top",padx=10, pady=10)

#Başlık label
baslik_label = Label(window, text="Başlık Giriniz", font=("Arial",10,"bold"))
baslik_label.pack(side="top",padx=10, pady=10)


#Başlık entry
baslik_entry = Entry(window, width=60, font=("Arial", 8), fg="red")
baslik_entry.get()
baslik_entry.pack(side="top",padx=10, pady=10)

#Text label

not_label = Label(window, text="Notunuzu buraya giriniz", font=("Arial",10,"bold"))
not_label.pack(side="top",padx=10, pady=10)

#Textbox

not_text = Text(window, font=("Arial", 8), width=60, height=25)
not_text.get("1.0", END)
not_text.pack(side="top",padx=10, pady=10)


#Encrypt and Decrypt

def encrypt(key, data):


    if baslik_entry.get() == "" and not_text.get("1.0", END) == "":
        tkinter.messagebox.showerror("Hata", "Başlık ve Notu birlikte giriniz")
    else:

        ft = Fernet(key)
        d = data
        encr = ft.encrypt(d.encode())

        def save_file():
            f = asksaveasfile(initialfile='Untitled.txt',defaultextension=".txt", filetypes=[("All Files", "*.*"), ("Text Documents", "*.txt")])
            f.write(encr)
        save_file()
    return encrypt

def decrypted():

    if not_text.get("1.0", END) == "":
        tkinter.messagebox.showerror("Hata", "Şifreyi Giriniz")
    else:
        '''def open_file():
            f = askopenfile(initialfile='Untitled.txt',defaultextension=".txt", filetypes=[("All Files", "*.*"), ("Text Documents", "*.txt")])
            f.read()
            not_text.insert("1.0", f.read())
        open_file()'''

        #ayrı bir decrypt yapman gerek keyler sıkıntı oluyor

#Decrypt buton
decrypt_button = Button(window, font=("Arial", 10, "bold"), text="Decrypt(Şifreyi Çöz)", command=decrypted)
decrypt_button.pack(side="top",padx=5, pady=5)
#Encrypt button

encrypt_button = Button(window, font=("Arial", 10, "bold"), text="Encrypt(Şifrele)", command=encrypt)
encrypt_button.pack(side="top",padx=10, pady=10)

window.mainloop()

