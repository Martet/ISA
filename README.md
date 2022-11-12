# Síťové aplikace a správa sítí - Projekt
## Čtečka novinek ve formátu Atom a RSS s podporou TLS
Autor: Martin Zmitko <xzmitk01@stud.fit.vutbr.cz>

Datum: 12. 11. 2022

### Popis programu
Jednoduchý nástroj pro získávání a výpis informací z RSS 2.0 a Atom zdrojů.
Program je napsaný v jazyce C++ s použitím knihoven OpenSSL pro zabezpečené spojení a libxml2 pro zpracování XML zdrojů.
Program vypisuje informace načtené ze vstupních URL na standardní výstup, dle specifikace argumentů při spuštění.

### Překlad programu
Program se překládá pomocí přiloženého Makefile příkazem `make` (je podporován pouze GNU make) pomocí překladače c++.
Pro vyčištění dočasných souborů a přeloženého spustitelného souboru použijte příkaz `make clean`.

### Použití programu
`./feedreader URL | -f <feedfile>> [-c <certfile>] [-C <certdir>] [-T] [-a] [-u] [-h]`, kde:
- `-f <feedfile>` - nastavení souboru se seznamem odkazů na zdroje s jedním URL na každém řádku
- `-c <certfile>` - nastavení souboru s certifikátem použitým k šifrované komunikaci se zdrojem
- `-C <certdir>` - nastavení složky s certifikáty použitými k šifrované komunikaci se zdrojem
- `-T` - vypsat čas poslední změny u záznamu
- `-a` - vypsat autora u záznamu
- `-u` - vypsat URL u záznamu
- `-h` - vypíše informace o použití programu a skončí

Na pořadí argumentů nezáleží, program je schopný zpracovat více URL zadaných jako argumenty.
Je možná i kombinace souboru feedfile a URL zadaných jako argument, zpracují se všechny, ovšem musí být jedním z obou způsobů zadané alespoň jedno URL.
Po úspěšném zpracování alespoň jednoho zdroje skončí program s chybovým kódem 0, jinak 1.

### Testování
Součástí řešení jsou testy funkčnosti programu. Testy jsou napsané v jazyce Python, minimální verze 3.8 s použitím testovacího frameworku pytest.
Testy se spouští příkazem `make test`.

### Odevzdané soubory
    xzmitk01.tar
    ├── feedreader.cpp
    ├── Makefile
    ├── manual.pdf
    ├── README
    └── test
        ├── empty.txt
        ├── feedfile.txt
        └── test_feedreader.py
