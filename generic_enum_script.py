import inquirer
import os
import subprocess
from datetime import datetime
from time import sleep
import requests
from requests.exceptions import ConnectionError
import re
#importit

###########################################################################################################################################################
#---------------------------------------------------------------------------------------------------------------------------------------------------------#

#Tämä skripti on työkalu penetraatiotestauksen enumerointivaiheeseen, jossa hyödynnetään jo olemassa olevia työkaluja.
#Skriptissä käytetyt työkalut: Nmap, Gobuster, Metasploit, Enum4Linux

#---------------------------------------------------------------------------------------------------------------------------------------------------------#
###########################################################################################################################################################
#---------------------------------------------------------------------------------------------------------------------------------------------------------#

#Tämä skripti on tarkoitettu käytettäväksi ainoastaan luvalliseen penetraatiotestaukseen sekä opetuskäyttöön.
#Skriptiä ei saa käyttää järjestelmään, jota et omista tai järjestelmään, johon sinulla ei ole lupaa.
#Tekijä ei ole vastuussa skriptin väärinkäytöstä tai siitä aiheutuvasta vahingosta.

#Tekijä ei ota vastuuta skriptin toimivuudesta tai anna takuita sen toiminnalle.
#---------------------------------------------------------------------------------------------------------------------------------------------------------#
###########################################################################################################################################################

#Tehdään ICMP ping kysely kohteeseen.
def yhteystarkastus(ip_osoite):
    print(f" Testataan yhteys kohteeseen: {ip_osoite}")
    pingaus = os.system(f"ping -c 4 {ip_osoite} > /dev/null 2>&1") #ICMP ping kohteeseen 4 kertaa
    
    #Tarkistetaan vastaus
    #mikäli ping ei onnistu, varmistetaan jatkuminen.
    if pingaus != 0: 
        pingaus_vastaus = f"\n Kohteeseen {ip_osoite} ei saatu yhteyttä.\n Suoritusta jatketaan."
        varmistetaan_jatko = input("\n Kohteenseen ei saatu yhteyttä. Haluatko silti jatkaa suoritusta? (kyllä, k / ei) ").strip().lower()
        if varmistetaan_jatko not in ["kyllä", "k"]:
            print("\nSuoritus peruutetaan.")     
            puhdistus()
            exit()
    else:
        pingaus_vastaus = f" Yhteystarkastus kohteeseen {ip_osoite} onnistui!"
        puhdistus()
    return pingaus_vastaus
    

#nmap skannauksen output tarkistus.
# jos logitiedoon ei ole tullut tekstiä > suoritus on mahdollisesti epäonnistunut.
def nmap_skannauksen_tarkistus(logfile):
    try:
        with open(logfile, "r") as file:
            lines = [line.strip() for line in file.readlines() if line.strip()]
            if len(lines) < 3: 
                return False
            for line in lines[1:-1]:
                if "PORT" in line:
                    return True
            return False
    except Exception:
        return False
        
# perusmuotoinen nmap porttiskannaus koko porttiavaruuteen (-p-)

def nmap_skannaus(ip_osoite):
    #output file
    logfile = f"nmap_tulokset_{ip_osoite}.txt"
    
    #komennon muodostaminen
    nmap_komento = ["nmap","-n","-T4","-p-", ip_osoite, "-oN", logfile]
    try:
        subprocess.run(nmap_komento, check=True) #komennon suoritus
    except subprocess.CalledProcessError as virhe:
        return f"Nmap Skannaus epäonnistui virheeseen: {virhe}"
    if nmap_skannauksen_tarkistus(logfile):
        print(f"Nmap skannaus onnistui! Skannaus tallennettu logitiedostoon: {logfile}")
        puhdistus()
        return f"Nmap skannaus onnistui! Skannaus tallennettu logitiedostoon: {logfile}"

    else:
        return f"Nmap Skannaus epäonnistui"

#skannataan servicetiedot löytyneille avoimille porteille
def tarkempi_nmap_skannaus(ip_osoite):
    #outputfile
    logfile = f"tarkempi_nmap_tulokset_{ip_osoite}.txt"
    #tiedosto, jossa aikaisemmin skanantut tulokset
    skannatut_portit = f"nmap_tulokset_{ip_osoite}.txt"
    
    #tarkistus, että onko aikaisempi skannaus olemassa
    if not os.path.exists(skannatut_portit):
        return ("Aikaisempaa Nmap scannausta ei löytynyt, suorita normaali Nmap scannaus ensiksi")
    
    #tarkistetaan avoimet portit aikaisemmasta skannauksesta, ettei kohdetta tarvitse skannata uudestaan.
    with open(skannatut_portit, "r") as avoimet:
        rivit = avoimet.readlines()
        avoimet_portit = [line.strip().split('/')[0] for line in rivit if "/tcp" in line and "open" in line]
    portti_str = ",".join(avoimet_portit)
    
    #komennon muodostaminen
    tarkempi_nmap_komento = ["nmap", "-p",portti_str,"-sC","-sV",ip_osoite,"-oN", logfile]
    
    try:
        subprocess.run(tarkempi_nmap_komento, check=True) #komennon suoritus
    except subprocess.CalledProcessError as virhe:
        return f"Tarkempi Nmap Skannaus epäonnistui virheeseen: {virhe}"
    if nmap_skannauksen_tarkistus(logfile):
        print(f"Tarkempi Nmap skannaus onnistui! Skannaus tallennettu logitiedostoon: {logfile}")
        puhdistus()
        return f"Tarkempi Nmap skannaus tallennettu logitiedostoon: {logfile}"
    else:
        return f"Tarkempi Nmap Skannaus epäonnistui"    


#tarkistetaan kohteesta uudelleenohjaukset header kentästä.
#Tarkistetaan saadaanko sivustoon yhteys (timeout 5 sec)
def uudelleenohjaus_tarkistus(alkuosoite):
    try:
        tarkista = requests.get(alkuosoite, allow_redirects=False,verify=False, timeout=5)
        print(f"\nTarkistetaan osoite uudelleenohjauksista.\n")
        
        if tarkista.is_redirect or tarkista.is_permanent_redirect:
            print(f"Osoite {alkuosoite} ohjautuu osoitteeseen: {tarkista.headers.get('Location')}") #otetaan ohjausosoite header kentästä
            vaihtunut_osoite = tarkista.headers.get('Location')
            return vaihtunut_osoite
        else:
            print(f"Osoitteessa ei uudelleenohjausta.")
            return alkuosoite
    except requests.ConnectionError:
        print(f"Ei yhteyttä")
        return False
    except requests.RequestException as virhe:
        return virhe


def gobuster_skannaus(ip_osoite):
    
    #Tarkistetaan onko uudelleenohjausta
    uudelleenohjaus = uudelleenohjaus_tarkistus(f"http://{ip_osoite}")
    if uudelleenohjaus == False:
        print(f"Sivustoon ei saatu yhteyttä Gobuster skannia vasten.")
        return f"Sivustoon ei saatu yhteyttä Gobuster skannia vasten."    
    
    #tallennetaan portti sekä alkuosoite
    alkuosoite = f"http://{ip_osoite}"
    portti = []
    portti = input("Syötä webportti Gobusteriin: \n").strip()

    #wordlistit, logifile, osoite
    wordlist = "/usr/share/wordlists/raft-medium-directories.txt"
    logfile = f"gobuster_{ip_osoite}.txt"
    osoite = f"{alkuosoite}:{portti}/"
    
    #jos redirect osoitteessa on vain path
    if not uudelleenohjaus.startswith(("http","https")):
        osoite = f"http://{ip_osoite}:{portti}"

    #komentoa varten poistetaan /
    if uudelleenohjaus.endswith("/"):
        uudelleenohjaus = uudelleenohjaus[:-1]
    
    #jos osoite on muuttunut, käytetään uutta osoitetta
    if osoite != alkuosoite:
        osoite = uudelleenohjaus
        
    #mikäli https protokolla, varmistetaan portti uudelleen
    if uudelleenohjaus.startswith("https://"):
        print(f"Osoite ohjautuu https protokollaan. Tarkista portti!\n")
        portti = input(f"Valittu portti: {portti}\nTarkista portti!\nSyötä portti:").strip()
        osoite = f"{uudelleenohjaus}:{portti}/"
    
    #komennon muodostaminen
    komento = f"gobuster dir -u {osoite} -w {wordlist} -k -t 50 -x php,html,txt,asp,bak -e -o {logfile}"
    terminaali =f"qterminal -e 'bash -c \"{komento}; exec bash\"'"
    print(f"komento busteriin:\n{komento}")
    try:
        subprocess.Popen(terminaali, shell=True) #suoritus
        puhdistus()
        return f"Suoritetaan Gobuster skannaus.\nTulokset tallennetaan tiedostoon: {logfile}"
    except subprocess.CalledProcessError as virhe:
        return f"Gobuster skannaus epäonnistui: {virhe}"
    
    
  
#puhdistus terminaaliin. sleep 5 auttaa käyttäjää näkemään viestit onnistuneesta/epäonnistuneesta suorituksesta.
def puhdistus():
    sleep(5)
    os.system("clear")



#Suoritetaan enum4linux sekö nmap smb skriptit
def smb_enumeration(ip_osoite):
    
    #output file
    logfile = f"smb_enum_{ip_osoite}.txt"
    print(f"\nSuoritetaan SMB enumerointi kohteeseen: {ip_osoite}...")
    
    #komennon muodostaminen
    komento = f"enum4linux -a {ip_osoite} | tee -a {logfile}"
    terminaali =f"qterminal -e 'bash -c \"{komento}; exec bash\"s'"

    #nmap komento
    nmap_komento = ["nmap","--script","smb-enum*,smb-os-discovery,smb-protocols,smb-security-mode,smb2-capabilities","-p","139,445",ip_osoite,"-oN",logfile]
    try:
        print(nmap_komento)
        subprocess.run(nmap_komento,check=True) #suoritetaan nmap   
        subprocess.Popen(terminaali, shell=True)#suoritetaan enum4lonux
        print(f"Suoritetaan SMB enumerointi...")  
        puhdistus()
        return f"smb_enumeration ajon tiedot tallennetaan tiedostoon {logfile}"
    except subprocess.CalledProcessError as virhe:
        return f"smb_enumeration suoritus epäonnistui: {virhe}" 


#kerätään avoimet portit nmap skannauksista
def parse_nmap_txt(file_path):
    
    with open(file_path, 'r') as file:
        tied = file.readlines()

    results = []
    servicelista = []
    uusilista = []
    
    #kerätään avoimet portit ja siirretään servicelistaan
    for line in tied:
        match = re.match(r'(\d{1,5}\/tcp|udp)\s+open\s+(\S+)[ \t]*(.*)?', line.strip())
        if match:
            port,service,version = match.groups()
            results.append((port,service,version))
            servicelista.append(version)

    poistadupe = list(set(servicelista)) #poistetaan duplikaatit
    for palvelu in poistadupe:
        uusi = palvelu.split()[:3] #kerätään 3 alkiota service nimen alusta
        uusilista.append(' '.join(uusi)) #lisätään litaan
    with open("service_versiot.txt", "w") as file:
        for i in uusilista:
            file.write(i + "\n")
            
    return uusilista


#metasploit komennon muodostaminen
def metasploit_haku(servicet,ip_osoite):
    #outputfile, komennon muodostaminen
    logfile = f"metasploit_haku_{ip_osoite}.txt"
    komento = f"bash -c 'msfconsole -q -x \"search {servicet}; exit\"| tee -a {logfile}'"
    terminaali = f"qterminal -e {komento}"
    
    print(f"komento:\n{komento}")
    try:
        
        print(f"Haetaan metasploitista: {servicet}")
        with open(logfile,"a") as f:
            f.write(f"\nHaeataan metasploitista: {servicet}\n")
            
        subprocess.run(terminaali, shell=True) #komennon suorittaminen 
        with open(logfile,"a") as f:
            f.write("\n"+"-" * 30 + "\n")
        print(f"Tulokset hausta tallennettu tiedostoon: {logfile}\n")       
        print("-" *30 + "\n")
        return
    except subprocess.CalledProcessError as virhe:
        return f"skannaus epäonnistui: {virhe}"   
    
#suoritetaan metasploit looppaamalla löydetyt servicet
def suorita_metasploit(ip_osoite):
    
    for service in parse_nmap_txt(f"tarkempi_nmap_tulokset_{ip_osoite}.txt"):
        print(f"Haetaan metasploitista: {service}")
        metasploit_haku(service,ip_osoite)
        
    return f"Metasploit suoritettu\n Suorituksen tiedot tallennettu tiedostoon: metasploit_haku_{ip_osoite}.txt"

#toolsjako 
def toolsjako():
    
    sijainti=f"~/Desktop/jako" #polku, missä kansiot tarkistetaan/luodaan
    portti = "5555" #verkkojakoon käytetty portti
    
    kansio = os.path.expanduser(sijainti)
    os.makedirs(sijainti,exist_ok=True)
    os.makedirs(os.path.join(kansio, "skriptit"),exist_ok=True)
    os.makedirs(os.path.join(kansio, "ohjelmat"),exist_ok=True)
    os.makedirs(os.path.join(kansio, "muut"),exist_ok=True)
    
    #komennon muodostaminen
    komento = f"python3 -m http.server {portti} --directory {sijainti}"
    terminaali = f"qterminal -e 'bash -c \"{komento}; exec bash\"'"
    
    try: 
        subprocess.Popen(terminaali, shell=True) #komennon suorittaminen
        return f"Avataan verkkojako työkaluille uuteen terminaaliin\nVerkkojako avautuu osoitteeseen: http://localhost:{portti}"
    except subprocess.CalledProcessError as virhe:
        return f"Verkkojaon avaaminen epäonnistui: {virhe}"


# poistetaan logien tekstistä ANSI kirjaimet @ > ~ https://en.wikipedia.org/wiki/ANSI_escape_code
def ascii_puhdistus(ip_osoite):
    
    output_tiedostot = [f"smb_enum_{ip_osoite}.txt",f"metasploit_haku_{ip_osoite}.txt",f"gobuster_{ip_osoite}.txt"]
    
    for tiedosto in output_tiedostot:
        tekstikorjaus = fr"perl -i -pe 's/\e\[?.*?[\@-~]//g' {tiedosto}"
        if os.path.exists(tiedosto):
            subprocess.run(tekstikorjaus, shell=True)

#logitusta
def logitus(ip_osoite, moduuli_output):    
    
    with open(f"enumlog_{ip_osoite}.txt","a",encoding="utf-8") as logfile:
        
        aikaleima = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logfile.write(f"Skripti suoritettu: {aikaleima} ---- IP-Osoite {ip_osoite}\n")
        
        for valittu_moduuli,ajotiedot in moduuli_output.items():
            logfile.write(f" -{valittu_moduuli}:\n {ajotiedot}\n")
        logfile.write("-" *30 + "\n")  


#main.
def main():
    ip_osoite = input("Syötä kohteen IP-osoite\n").strip() # kerätään kohteen IP osoite
    confirm = input(f"Onko osoite: {ip_osoite} oikea (kyllä/ei): ").strip().lower() # Varmistetaan vielä IP käyttäjältä
    
    if confirm not in ["kyllä", "k"]: # Varmistetaan vielä IP käyttäjältä, perutaan, mikäli kielteinen vastaus
        print("Perutaan suoritus, tarkista IP-osoite.")
        exit()
        return ip_osoite

    
   
   #skriptin funktiot
    valittavat_moduulit = {
        "Yhteystarkastus" : [yhteystarkastus, True],
        "Nmap skannaus"   : [nmap_skannaus, True],
        "Tarkempi Nmap kannaus": [tarkempi_nmap_skannaus, True],
        "Gobuster skannaus": [gobuster_skannaus, True],
        "SMB enumerointi": [smb_enumeration, True],
        "Metasploit haku": [suorita_metasploit, True],
        "Toolsjako": [toolsjako, False]
    }
    
    #Checkbox käyttöliittymä moduuleille
    valinnat = list(valittavat_moduulit.keys())
    
    moduulivalinta = [
        inquirer.Checkbox(
            name="valitut_moduulit",
            message="Valitse suoritettavat moduulit",
            choices=valinnat
        )
    ]
    
    #valinta moduuleille
    valinta = inquirer.prompt(moduulivalinta)
    valitut = valinta.get("valitut_moduulit",[])
    if not valitut:
        print(f"Ei valittuja moduuleita")
        return
    
    #näytetään valikossa valitut moduulit
    print("Valitut työkalut:")
    for moduuli in valitut:
        print(f"      {moduuli}")
    
    #varmistetaan vielä suoritus
    varmistetaan_ajo = input("Jatketaanko suoritusta?: (kyllä, k / ei) ").strip().lower()
    
    if varmistetaan_ajo not in ["kyllä", "k"]:
        print("Peruutetaan.")
        return 
    
    #ajetaan moduulit ja kerätään vastaukset returneista
    moduuli_output = {}
    for valittu_moduuli in valitut:
        moduuli, tarvitaan_ip = valittavat_moduulit[valittu_moduuli]
        ajotiedot = moduuli(ip_osoite) if tarvitaan_ip else moduuli()
        print(ajotiedot)
        moduuli_output[valittu_moduuli] = ajotiedot
    
    #logitus, tulosten odottaminen sekä logiedoston puhdistus
    logitus(ip_osoite, moduuli_output)
    print(f"Odotetaan 2 minuuttia ja siivotaan logitiedostot ASCII-kirjaimilta.")
    sleep(120)
    ascii_puhdistus(ip_osoite)
if __name__ == "__main__":
    main()