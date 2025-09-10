# XIDS: a tiny packet-sniffing IDS with PDF reporting.

## Install
```bash
git clone https://github.com/DanielaCe18/XIDS.git
cd XIDS
poetry lock
poetry install --no-root
````

## Run

```bash
poetry run tp1
```
or to run tests : 

```bash
poetry run pytest -v
```

Pick an interface (Loopback for local tests, Wi-Fi/Ethernet for LAN).
Outputs: `report.pdf` (+ `report_protocols.svg`).

## What it does

* Captures traffic (Scapy) and counts protocols.
* Detects: ARP spoofing, port scan, SYN flood, SSH/FTP/RDP brute force,
  HTTP enumeration, SQLi, XSS, LFI/RFI, HTTP flood.
* Generates a **PDF** (ReportLab) with an embedded **SVG** chart (Pygal)
  and a list of detected events (URL + method when available).

## Tips

* Quick local demo:

  ```bash
  python -m http.server 8080 &
  curl "http://127.0.0.1:8080/?q=<script>alert(1)</script>"
  ```

