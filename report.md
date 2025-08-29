# Raport SOC – Analiza PCAP (fałszywe domeny Microsoft)

**Data analizy:** 2025-08-28  
**Analityk:** Maciej Przepiorkowski

---

## 1. Streszczenie kierownicze
Analiza pliku PCAP ujawniła komunikację z domenami podszywającymi się pod Microsoft.  
Ruch wskazuje na wykorzystanie tych domen jako infrastruktury Command & Control (C2).  
Zaobserwowano elementy exfiltracji danych (HTTP POST z dużym payloadem) oraz odbierania komend (HTTP GET z User-Agent PowerShell).  
W warstwie TLS widoczny certyfikat od zaufanego CA (Google Trust Services), ale przypisany do fałszywej domeny.  

**Wniosek:** silne przesłanki wskazujące na zainfekowaną stację kliencką o ip `10.6.13.133` komunikującą się z C2.

---

## 2. Artefakt wejściowy
- Plik: `sample.pcap`
- Host źródłowy: `10.6.13.133`

---

## 3. Analiza DNS
- Podejrzane domeny:
  - `dng-microsoftds.com`
  - `event-time-microsoft.org`
  - `eventdata-microsoft.live`
  - `windows-msgas.com`
  - `event-datamicrosoft.live`
- Wszystkie rozwiązywały się do IP z zakresów Cloudflare (`172.67.x.x`, `104.21.x.x`).

**Wniosek:** domeny typosquatting podszywające się pod Microsoft, hostowane za Cloudflare.

---

## 4. Analiza HTTP
### 4.1 Podejrzane żądania
- **POST /cirkYkCa4qwbET/...**
  - Host: `event-datamicrosoft.live`
  - Content-Type: `application/octet-stream`
  - Content-Length: 33605 bajtów
  - **Ocena:** exfiltracja danych (binarny payload)

- **GET /zh0GPFZdKt**
  - Host: `event-time-microsoft.org`
  - User-Agent: `WindowsPowerShell/5.1...`
  - Odpowiedź zawierała polecenia PowerShell (`Get-Hotfix ...`)
  - **Ocena:** odbieranie komend C2

### 4.2 Normalny ruch (baseline)
- **GET /connecttest.txt**
  - Host: `msftconnecttest.com`
  - User-Agent: `Microsoft NCSI`
  - Odpowiedź: 22 bajty tekstu
  - **Ocena:** typowy test łączności Windows

**Wniosek:** kontrast między normalnym ruchem a C2 → wyraźna anomalia.

---

## 5. Analiza TLS
- IP docelowe: `172.67.146.241` (Cloudflare edge, AS13335)
- SNI: `dng-microsoftds.com`
- Issuer: Google Trust Services
- SAN: `dng-microsoftds.com`, `*.dng-microsoftds.com`
- CN: brak

**Wniosek:** certyfikat poprawny technicznie, ale przypisany do domeny podszywającej się pod Microsoft. Typowy przypadek ukrywania C2 za Cloudflare.

---

## 6. IoC (Indicators of Compromise)
- Domeny: `dng-microsoftds.com`, `event-time-microsoft.org`, `eventdata-microsoft.live`, `windows-msgas.com`, `event-datamicrosoft.live`
- IP: `172.67.146.241`, `104.21.10.227`, `104.21.24.186`, `172.67.219.231` (Cloudflare edge)

---

## 7. Rekomendacje
1. Izolacja hosta `10.6.13.133` i analiza powłamaniowa.  
2. Blokada domen na poziomie DNS/firewalla.  
3. Wdrożenie reguł detekcyjnych (Suricata, Sigma, SIEM).  
4. Hunting w logach za ostatnie 30 dni pod kątem IoC.  
5. Monitorowanie powtarzalnych sesji TLS (beaconing).  

---

## 8. Podsumowanie
Analiza PCAP potwierdziła ruch do fałszywych domen Microsoft hostowanych za Cloudflare.  
Ruch HTTP wskazuje na exfiltrację danych i kontrolę zdalną. Certyfikat TLS od zaufanego CA chroni złośliwą domenę, co utrudnia detekcję.  
Incydent należy klasyfikować jako **wysokiego ryzyka** – komunikacja z C2.  
