import os
import tkinter as tk

from sqlalchemy import func
from sqlalchemy.orm import sessionmaker

from models import Samata, engine

Session = sessionmaker(bind=engine)

session = Session()


def gauk_visas_eilutes():
    return sesion.query(Samata).all()


Sesion = sessionmaker(bind=engine)
sesion = Sesion()
redaguojamas_obj = None


def padaryk_bakupa():
    os.system("copy samata.db samata.db.bak")
    status_l["text"] = "ivykdytas backupo veiksmas"


def pakeis_uzrasa():
    ivestis = sesion.query(func.sum(Samata.price)).scalar().get()
    rez_uzrasas_l[""] = ivestis
    refresink()
    refresink_suma()


def refresink():
    boksas.delete(0, tk.END)
    boksas.insert(tk.END, *gauk_visas_eilutes())


def refresink_suma():
    sumavimas_s["text"] = skaiciavimas_suma()


def redaguoti():
    global redaguojamas_obj
    pasirinkimas = boksas.curselection()
    if len(pasirinkimas) == 0:
        return
    indexas = pasirinkimas[0]
    eilutes = gauk_visas_eilutes()
    redaguojamas_obj = eilutes[indexas]
    isvalyk_laukelius()
    pavadinimas_e.insert(0, redaguojamas_obj.name)
    kaina_e.insert(0, redaguojamas_obj.price)
    refresink_suma()
    status_l["text"] = "ivykdytas redagavimo veiksmas"


def issaugoti():
    global redaguojamas_obj
    if redaguojamas_obj:
        redaguojamas_obj.name = pavadinimas_e.get()
        redaguojamas_obj.price = kaina_e.get()
    else:
        pavadinimas = pavadinimas_e.get()
        kaina = kaina_e.get()
        nauja_eil_o = Samata(kaina, pavadinimas)
        sesion.add(nauja_eil_o)
    sesion.commit()
    redaguojamas_obj = None
    refresink()
    refresink_suma()
    isvalyk_laukelius()
    status_l["text"] = "ivykdytas issaugojimo veiksmas"


def isvalyk_laukelius():
    pavadinimas_e.delete(0, tk.END)
    kaina_e.delete(0, tk.END)


def trinti():
    pasirinkimas = boksas.curselection()
    if len(pasirinkimas) == 0:
        return
    pasirinkimas = pasirinkimas[0]
    eilutes = gauk_visas_eilutes()
    trinama_eilute_o = eilutes[pasirinkimas]
    sesion.delete(trinama_eilute_o)
    sesion.commit()
    refresink()
    refresink_suma()
    status_l["text"] = "ivykdytas trinimo veiksmas"


def bandymas_isvengti_raidziu():
    if not kaina_e.get().isdigit():
        last_char = len(kaina_e.get()) - 1
        kaina_e.delete(-1, tk.END)


def skaiciavimas_suma():
    suma = sesion.query(func.sum(Samata.price)).scalar()
    return suma


def paieska():
    session = Session()

    ivestis = paieska1_e.get() + '%%'
    eilutes = session.query(Samata).filter(
        (Samata.name.ilike(ivestis)) |
        (Samata.price.ilike(ivestis))
    ).all()

    boksas.delete(0, tk.END)
    boksas.insert(tk.END, *eilutes)

    session.close()
    status_l["text"] = "ivykdyta paieska"


langas = tk.Tk()
langas.geometry("800x500")
langas.resizable(False, False)

meniu = tk.Menu(langas)
langas.config(menu=meniu)
submeniu = tk.Menu(meniu, tearoff=False)

meniu.add_cascade(label="Meniu", menu=submeniu)

submeniu.add_command(label="iseiti", command=exit)

langas.eval("tk::PlaceWindow . center")

freimas_1 = tk.Frame(langas)

pavadinimas_l = tk.Label(freimas_1, text="Islaidos/darbai")
pavadinimas_e = tk.Entry(freimas_1)
kaina_l = tk.Label(freimas_1, text="Kaina")
kaina_e = tk.Entry(freimas_1)
paieska1_l = tk.Label(freimas_1, text="%%")
paieska1_e = tk.Entry(freimas_1)
sumavimas_l = tk.Label(freimas_1)
sumavimas_e = tk.Label(freimas_1, text=skaiciavimas_suma())
rez_uzrasas_l = tk.Label(freimas_1, text="")
sumavimas_s = tk.Label(freimas_1, text="")

kaina_e.bind("<KeyRelease>", lambda event: bandymas_isvengti_raidziu())

redaguoti_b = tk.Button(freimas_1, text="redaguoti", command=redaguoti, bg="#FFA07A")
issaugoti_b = tk.Button(freimas_1, text="issaugoti", command=issaugoti, bg="#98FB98")
trinti_b = tk.Button(freimas_1, text="trinti", command=trinti, bg="#eb3d34")
bakupas_b = tk.Button(freimas_1, text="padaryk bakupa", command=padaryk_bakupa)
paieska1_b = tk.Button(freimas_1, text="ieskoti", command=paieska, bg='#ebe534')
sumavimas_b = tk.Button(freimas_1, text="sumavimas", command=skaiciavimas_suma)

boksas = tk.Listbox(langas, width=60, height=25)
boksas.insert(tk.END, *gauk_visas_eilutes())
scrollbaras = tk.Scrollbar(langas)
boksas.config(yscrollcommand=scrollbaras.set)
scrollbaras.pack(side=tk.RIGHT, fill=tk.Y)

status_l = tk.Label(langas, text="Šiuo metu programa nieko nedaro..",
                    bd=5, relief=tk.SUNKEN, anchor=tk.W, font=("Consolas", 10))

pavadinimas_l.grid(row=0, column=0, sticky=tk.W)
pavadinimas_e.grid(row=0, column=1)
kaina_l.grid(row=1, column=0, sticky=tk.W)
kaina_e.grid(row=1, column=1)
redaguoti_b.grid(row=3, columnspan=2, sticky=tk.W + tk.E)
issaugoti_b.grid(row=2, columnspan=2, sticky=tk.W + tk.E)
trinti_b.grid(row=4, columnspan=2, sticky=tk.W + tk.E)
bakupas_b.grid(row=5, columnspan=2, sticky=tk.W + tk.E)
paieska1_b.grid(row=6, columnspan=1, sticky=tk.W + tk.E)
paieska1_l.grid(row=6, columnspan=2, sticky=tk.W + tk.E)
paieska1_e.grid(row=6, columnspan=2, sticky=tk.E + tk.E)
sumavimas_b.grid(row=7, columnspan=1, sticky=tk.W + tk.E)
sumavimas_s.grid(row=7, columnspan=2, sticky=tk.W + tk.E)

status_l.pack(side=tk.BOTTOM, fill=tk.X)
freimas_1.pack(side=tk.LEFT, anchor=tk.N)
boksas.pack(side=tk.LEFT, anchor=tk.N)

langas.mainloop()
