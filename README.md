# Firewall w PowerShell

Interaktywny skrypt do zarządzania regułami Zapory Windows z **audytem wszystkich zmian polityki zapory** (kto / co / kiedy).

Wymagania: Windows PowerShell **5.1 (Desktop)**, uruchomienie jako administrator.

## Uruchomienie

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\firewall.ps1
```

## Menu

| Opcja | Działanie |
|-------|-----------|
| 1–3 | Dodawanie reguł blokujących (przez `Invoke-AuditedChange`) |
| 4 | Usuwanie reguły (przez `Invoke-AuditedChange`) |
| 5 | Podgląd dziennika audytu |
| 6 | Weryfikacja integralności dziennika (łańcuch skrótów, także przez pliki rotacji) |
| 7 | Synchronizacja audytu teraz (wykrycie zmian wykonanych poza narzędziem) |
| 8 | Instalacja / usunięcie watchera (zadanie harmonogramu `\FirewallAudit\Watcher`) |
| 9 | Wyjście |

## Audyt – jak to działa

- Kod audytu mieści się w sekcji `#region AUDIT ... #endregion AUDIT` w `firewall.ps1` (nagłówek opisuje kontrakt dla pozostałych modułów).
- Każda zmiana polityki wykonywana przez narzędzie musi przechodzić przez
  `Invoke-AuditedChange -Operation <nazwa> -Scope Names|NewRules|Profiles|All -Action { ... }`.
  Wrapper zapisuje zamiar (`intent`) **przed** akcją (write-ahead; brak możliwości zapisu logu = zmiana nie jest wykonana), następnie rzeczywisty diff (`change`) i wynik (`result`).
- Zmiany wykonane obok narzędzia (GUI, `netsh`, GPO, inne skrypty) wykrywa `Invoke-AuditSync` – przy starcie skryptu, ręcznie (opcja 7) oraz przez watchera uruchamianego zdarzeniem z dziennika zapory.
- Dziennik: `C:\ProgramData\FirewallAudit\audit.jsonl` (JSON Lines, UTF-8, czas UTC), łańcuch skrótów SHA-256, rotacja przy 10 MB z zachowaniem ciągłości łańcucha.
- Stan odniesienia: `C:\ProgramData\FirewallAudit\baseline.json`.
- Watcher uruchamia chronioną kopię skryptu z `C:\ProgramData\FirewallAudit\bin\` (ACL: SYSTEM i Administratorzy – pełne, Users – odczyt).
- Dla pełnej atrybucji (kto) warto włączyć audyt zdarzeń: `auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable`. Skrypt tylko ostrzega, niczego sam nie włącza.

## Testy

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-FirewallAudit.ps1
```

Testy działają w piaskownicy (katalog tymczasowy, atrapa rejestru w HKCU); nie zmieniają prawdziwej polityki zapory. Ostatnia sekcja tylko czyta prawdziwy magazyn polityki. Nie wymagają uprawnień administratora.
