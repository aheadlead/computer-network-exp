#!/usr/bin/env python3
# coding=utf-8

import os
import platform
import re
import subprocess
from tkinter import *
from tkinter.messagebox import *

from traceroute import traceroute

if platform.system() != 'Windows':
    if os.geteuid() != 0:
        print('root permission needed')
        exit(1)
else:
    print('STOP: This program is incompatible with Microsoft Windows.')
    exit(1)

ttl = 1

root = Tk()
root.geometry('{}x{}'.format(470, 400))

dest_ip_label = Label(root, text='ip address')
dest_ip_label.grid(row=0, column=0, sticky='W')

dest_ip_entry = Entry(root)
dest_ip_entry.grid(row=0, column=1)

result_text = Text(root, width=65)
result_text.grid(row=1, columnspan=4)

next_svar = StringVar(value='traceroute')

def go():
    global ttl
    ip_pattern = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if re.match(ip_pattern, dest_ip_entry.get()) is None:
        showerror(title='error', message='invaild ip address')
    else:
        r = traceroute(dest_ip_entry.get(), ttl)
        if ttl == 1:
            result_text.delete(1.0, END)
            result_text.insert(END, 'ttl\taddress\t\ttype\tcode\t1\t2\t3\n')
        result_text.insert(END, r)
        if '\t3\t3' in r:
            ttl = 1
            next_svar.set('traceroute')
            showinfo(title='done', message='traceroute finished')
        else:
            ttl += 1
            next_svar.set('next')
        
next_button = Button(root, textvariable=next_svar, command=go)
next_button.grid(row=0, column=2)

root.mainloop()

