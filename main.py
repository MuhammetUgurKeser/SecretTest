import tkinter
from tkinter import messagebox
import base64



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


#
def saveandecryption():
    titlemain=Entry1.get()
    secret=textbox.get("1.0",tkinter.END)
    password=Entry2.get()

    if len(secret) == 0 or len(password) == 0 or len(titlemain) == 0:
        messagebox.showinfo(title="Error",message="Please fill in all the blanks")
    else:

        encodemessage = encode(password, secret)
        with open("mysavefile.txt","a") as myfile:
            myfile.write(f"\n{titlemain}\n{encodemessage}")

        Entry1.delete(0, tkinter.END)
        Entry2.delete(0 ,tkinter.END)
        textbox.delete("1.0" , tkinter.END)

def decryption():
    secret = textbox.get("1.0", tkinter.END)
    password = Entry2.get()
    if len(secret)==0 or len(password)==0 :
        messagebox.showinfo(title="Error",message="Please fill in all the blanks")
    else:
        try:
            decodemessage=decode(password,secret)
            textbox.delete("1.0",tkinter.END)
            textbox.insert("1.0",decodemessage)
        except:
            messagebox.showinfo(message="Please write encrypt something")


root = tkinter.Tk()

########################### UI

#İmage
canvas = tkinter.Canvas(height=200,width=200)
logo = tkinter.PhotoImage(file="top-road.png",width=100,height=100)
canvas.create_image(100,100,image=logo)
canvas.pack()




#ENTRY
label1=tkinter.Label(text="Enter your Title")
label1.pack()
Entry1=tkinter.Entry(width=50)
Entry1.pack()
label2=tkinter.Label(text="Enter your secret")
label2.pack()
textbox=tkinter.Text(width=40,height=10)
textbox.pack()
label3=tkinter.Label(text="Enter your Key")
label3.pack()
Entry2=tkinter.Entry(width=50)
Entry2.pack()



#BUTTON
savebutton=tkinter.Button(text="save&Encrypt",command=saveandecryption)
savebutton.pack()
decryptbutton=tkinter.Button(text="Decrypt",command=decryption)
decryptbutton.pack()



root.mainloop()