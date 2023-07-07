import tkinter as tk
from PIL import ImageTk, Image
from tkinter import messagebox
import base64

def main():
    window = tk.Tk()
    window.title("Secret Notes")
    window.minsize(height=600,width=500)
    window.maxsize(height=600,width=500)


    def open_img():
        image = Image.open('topsecret.png')
        image = image.resize((150,150))
        image = ImageTk.PhotoImage(image)
        panel = tk.Label(window, image=image)
        panel.image = image
        panel.place(x=180,y=30)

    def texts_and_entrys():

        def encode(key, clear):
            enc = []
            for i in range(len(clear)):
                key_c = key[i % len(key)]
                enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
                enc.append(enc_c)
            return base64.urlsafe_b64encode("".join(enc).encode()).decode()

        def decode(key, enc):
            dec = []
            enc = base64.urlsafe_b64decode(enc).decode()
            for i in range(len(enc)):
                key_c = key[i % len(key)]
                dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
                dec.append(dec_c)
            return "".join(dec)

        def encrypt_and_save_button():
            master_key = entry_key.get()
            title = title_entry.get()
            text = text_secret.get(1.0,"end-1c")
            if entry_key != "" and text != "" and title != "":
                enc_text = encode(master_key,text)
                messagebox.showinfo("Successful !","Your secret is safe with me ;)")
                with open('topsecret.txt','a') as top :
                    top.write("\n")
                    top.write("\n")
                    top.write(title)
                    top.write("\n")
                    top.write(str(enc_text))
                title_entry.delete(0, "end")
                entry_key.delete(0, "end")
                text_secret.delete(1.0, "end")
            else:
                messagebox.showinfo("Info", "<<Please make sure you entered everything i need to work!>>")


        def decrypt_button():
            enc_text = text_secret.get(1.0, "end-1c")
            masterkey = entry_key.get()
            if entry_key != "" and enc_text != "" :
                dec_text = decode(masterkey,enc_text)
                text_secret.delete("1.0",tk.END)
                text_secret.insert("1.0",dec_text)
            else:
                messagebox.showinfo("Info", "<<Please make sure you entered key and encoded secret>>")

        enter_title = tk.Label(text="Enter your Title")
        enter_title.place(x=210, y=195)
        title_entry = tk.Entry(width=35)
        title_entry.place(x=150, y=220)
        text_secret = tk.Text(width=50,height=12)
        text_secret.place(x=50, y=275)
        title_secret = tk.Label(text="Enter your secret")
        title_secret.place(x=210, y=248)
        title_key = tk.Label(text="Enter master key")
        title_key.place(x=210, y=480)
        entry_key = tk.Entry(width=35)
        entry_key.place(x=150, y= 505)
        button_save = tk.Button(text="Save & Encrypt",command=encrypt_and_save_button)
        button_save.place(x=210, y= 530)
        button_decrypt = tk.Button(text="Decrypt",command=decrypt_button)
        button_decrypt.place(x=229, y=560)

    texts_and_entrys()
    open_img()
    window.mainloop()
main()