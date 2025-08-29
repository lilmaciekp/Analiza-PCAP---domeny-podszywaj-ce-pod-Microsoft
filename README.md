# Analiza PCAP – Fałszywe domeny podszywające się pod Microsoft (C2)

---

## Opis
Repozytorium zawiera wyniki analizy pliku PCAP.  
W ruchu sieciowym wykryto komunikację z **domenami typosquatting** podszywającymi się pod usługi Microsoft.  
Artefakty wskazują na możliwą **komunikację Command & Control (C2)** oraz **exfiltrację danych**.

- LAN segment range:  `10.6.13[.]0/24`
    - Domain:  `massfriction[.]com`
    - Active Directory (AD) domain controller:  `10.6.13[.]3 - WIN-DQL4WFWJXQ4`
    - AD environment name:  `MASSFRICTION`
    - LAN segment gateway:  `10.6.13[.]1`
    - LAN segment broadcast address:  `10.6.13[.]255`

---

## Najważniejsze ustalenia
- **DNS**  
  - Zapytania do podejrzanych domen:  
    - `dng-microsoftds.com`  
    - `event-time-microsoft.org`  
    - `eventdata-microsoft.live`  
    - `windows-msgas.com`  
    - `event-datamicrosoft.live`  

- **HTTP**  
  - `POST` z **binarnymi payloadami (30KB+)** → prawdopodobna exfiltracja danych  
  - `GET` z **User-Agent PowerShell** → pobieranie poleceń z serwera  
  - Nietypowe ścieżki URI (`/cirkYkCa4qwbET/...`, `/zh0GPFZdKt`)  

- **TLS**  
  - Połączenie do `172.67.146.241` (Cloudflare edge)  
  - **SNI:** `dng-microsoftds.com`  
  - **Issuer:** Google Trust Services (zaufane CA)  
  - **SAN:** `dng-microsoftds.com` → certyfikat wystawiony na fałszywą domenę  

---

## Wnioski
Analiza PCAP jednoznacznie wskazuje na **komunikację malware z infrastrukturą C2** ukrytą za Cloudflare.  
Występują oznaki zarówno **exfiltracji danych**, jak i **zdalnego wykonywania poleceń** poprzez HTTP/TLS.
Zainfekownym hostem jest `10.6.13.133`


## Zawartość repozytorium
- `analiza.docx` – szczegółowe notatki z analizy (krok po kroku)  
- `report.md` – ustrukturyzowany raport SOC w formacie Markdown  
- `iocs.csv` – zebrane wskaźniki kompromitacji (domeny i IP)  
- `suricata.rules` – reguły IDS (DNS/HTTP/TLS)  
- `sigma.yml` – reguła Sigma (detekcja DNS)  
- `sentinel_kql.txt` – zapytania huntingowe do Microsoft Sentinel/Defender  
- `splunk_spl.txt` – zapytania huntingowe do Splunka  
- `stix_bundle.json` – paczka IoC w formacie STIX 2.1 (Threat Intelligence)  

---

## Rekomendacje
1. Zablokować podejrzane domeny na poziomie DNS/firewalla.  
2. Izolować host `10.6.13.133` i przeprowadzić pełną analizę powłamaniową.  
3. Wdrożyć reguły detekcyjne (Suricata, Sigma, SIEM).  
4. Monitorować telemetrię pod kątem beaconingu (cyklicznych połączeń).  

---

## Autor
Case study przygotowane przez Macieja Przepiórkowskiego – analityk SOC (ćwiczenie do portfolio).  
