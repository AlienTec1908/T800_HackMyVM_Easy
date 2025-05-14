# T800 - HackMyVM (Easy)
 
![T800.png](T800.png)

## Übersicht

*   **VM:** T800
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=T800)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 8. April 2021
*   **Original-Writeup:** https://alientec1908.github.io/T800_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "T800"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Enumeration eines Webservers (Port 80), der ein Verzeichnis `/sexy/` enthielt. In einer Bilddatei (`nudeslut.jpeg`) aus diesem Verzeichnis wurde mittels `exiftool` ein Passwort (`chmodxheart`) in den Metadaten gefunden. Auf der Webseite `/index.html` wurde der Benutzername `ruut` entdeckt. Mit diesen Credentials gelang der SSH-Login auf dem nicht standardmäßigen Port 800. Als `ruut` wurden zwei SUID-Root-Binaries gefunden: `/usr/bin/calife` und `/usr/bin/conky`. `/usr/bin/calife` wurde verwendet, um zu Benutzer `superruut` zu wechseln, da das Passwort wiederverwendet wurde (`chmodxheart`). Als `superruut` wurde die User-Flag gelesen. Schließlich wurde `/usr/bin/conky` mit einer manipulierten Konfigurationsdatei (`/tmp/conky.conf`) ausgeführt, um den privaten SSH-Schlüssel von `root` (`/root/.ssh/id_rsa`) auszulesen. Dies ermöglichte den SSH-Login als `root`.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `gobuster`
*   `nmap`
*   `curl`
*   `exiftool`
*   `ssh`
*   `cat`
*   `grep`
*   `find`
*   `/usr/bin/calife`
*   `vi` / `nano`
*   `conky`
*   `chmod`
*   `mv`
*   `bash`
*   `cd`
*   `ls`
*   `id`
*   Standard Linux-Befehle

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "T800" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Findung mit `arp-scan` (`192.168.2.142`).
    *   `gobuster` auf Port 80 fand `/index.html`, `/robots.txt` und das Verzeichnis `/sexy/`.
    *   `nmap`-Scan identifizierte offene Ports: 80 (HTTP - Nginx 1.14.2) und 800 (SSH - OpenSSH 7.9p1 auf nicht standardmäßigem Port).

2.  **Information Disclosure & Initial Access (ruut):**
    *   `curl http://192.168.2.142/index.html` zeigte den Text "Im ruut", was auf den Benutzernamen `ruut` hindeutete.
    *   Download einer Bilddatei (angenommen `nudeslut.jpeg`) aus dem `/sexy/`-Verzeichnis.
    *   `exiftool nudeslut.jpeg` extrahierte aus den Metadaten (Kommentarfeld) das Passwort `passwd:chmodxheart`.
    *   Erfolgreicher SSH-Login als `ruut` mit Passwort `chmodxheart` auf Port 800 (`ssh ruut@t800.vm -p 800`).

3.  **Privilege Escalation (von `ruut` zu `superruut`):**
    *   `cat /etc/passwd | grep bash` identifizierte die Benutzer `root`, `ruut` und `superruut`.
    *   `find / -type f -perm -4000 ...` fand die SUID-Root-Binaries `/usr/bin/conky` und `/usr/bin/calife`.
    *   Ausführung von `/usr/bin/calife superruut` als `ruut`. Das Passwort `chmodxheart` (Passwortwiederverwendung) wurde akzeptiert.
    *   Durch Ausbrechen aus `vim` (gestartet von `calife`) mittels `:!bash` wurde eine Shell als `superruut` erlangt.
    *   User-Flag `ruutrulezhmv` in `/home/superruut/userflag.txt` gelesen.

4.  **Privilege Escalation (von `superruut` zu `root`):**
    *   Erstellung einer `conky`-Konfigurationsdatei `/tmp/conky.conf` als `superruut`:
        ```
        conky.config = {
               out_to_console = true,
               out_to_x = false,
        }
        conky.text = [[
        ${tail /root/.ssh/id_rsa 30}
        ]]
        ```
    *   Ausführung von `conky -c /tmp/conky.conf` als `superruut`. Da `conky` SUID-Root war, las es den privaten SSH-Schlüssel von `root` (`/root/.ssh/id_rsa`) und gab ihn aus.
    *   Der extrahierte Root-SSH-Schlüssel wurde lokal gespeichert (z.B. `idroot`) und die Berechtigungen auf `600` gesetzt.
    *   Erfolgreicher SSH-Login als `root` mit dem privaten Schlüssel auf Port 800 (`ssh root@t800.vm -i idroot -p 800`).
    *   Root-Flag `hmvtitoroot` in `/root/rootflag.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Passwörter in Metadaten:** Ein Passwort wurde in den Exif-Daten einer Bilddatei gespeichert.
*   **Benutzernamen-Leak auf Webseite:** Ein Benutzername wurde direkt im HTML-Inhalt preisgegeben.
*   **SSH auf nicht standardmäßigem Port:** Erschwert die Entdeckung geringfügig, bietet aber keine echte Sicherheit.
*   **Passwort-Wiederverwendung:** Das Passwort von `ruut` funktionierte auch für `superruut` im Kontext von `calife`.
*   **SUID-Binary-Exploitation (`calife`):** Ein SUID-Binary erlaubte durch Passwort-Wiederverwendung und Shell-Escape aus einem Editor (`vim`) den Wechsel zu einem anderen Benutzer.
*   **SUID-Binary-Exploitation (`conky`):** Ein SUID-Binary (`conky`) konnte durch eine benutzerdefinierte Konfigurationsdatei dazu missbraucht werden, beliebige Dateien (hier den Root-SSH-Schlüssel) im Kontext von Root zu lesen.
*   **Auslesen privater SSH-Schlüssel:** Ermöglichte passwortlosen Login als der betroffene Benutzer.

## Flags

*   **User Flag (`/home/superruut/userflag.txt`):** `ruutrulezhmv`
*   **Root Flag (`/root/rootflag.txt`):** `hmvtitoroot`

## Tags

`HackMyVM`, `T800`, `Easy`, `SSH`, `Exiftool`, `Metadaten`, `SUID Exploitation`, `calife`, `conky`, `Password Reuse`, `Linux`, `Web`, `Privilege Escalation`
