#!/bin/bash

master_password="nekipassword"
nastavak="Pritisnite enter za nastavak."

echo "Demo password managera."

echo "Inicijalizacija: "
echo "python3 password_manager.py init $master_password"
python3 password_manager.py init $master_password

read -p "Pritisnite enter za nastavak"

echo "Nakon inicijalizacije, master.txt file ce biti stvoren sa pohranjenim šifriranim master passwordom."
echo "Dodavanje novih passworda: "
echo "python3 password_manager.py put $master_password www.primjer.hr nekasifra"

python3 password_manager.py put $master_password www.primjer.hr nekasifra

read -p "Pritisnite enter za nastavak"

echo "Šifre stranica se pohranjuju u json fileu oblika {šifra_web_stranice : [šifra_password, salt, iv]}"
 
echo "Ako pokušamo opet upisati password za istu stranicu, on će se updateati."
echo "python3 password_manager.py put $master_password www.primjer.hr nekasifra"

python3 password_manager.py put $master_password www.primjer.hr nekasifrapromijenjena

echo "Metodom get dobivamo vec spremljene sifre."
echo "python3 password_manager.py get $master_password www.primjer.hr"
python3 password_manager.py get $master_password www.primjer.hr