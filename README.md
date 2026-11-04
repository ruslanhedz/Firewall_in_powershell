# Firewall w PowerShell

[![CI](https://github.com/ruslanhedz/Firewall_in_powershell/actions/workflows/ci.yml/badge.svg)](https://github.com/ruslanhedz/Firewall_in_powershell/actions/workflows/ci.yml)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20Desktop-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg)

Interaktywny skrypt do zarządzania regułami Zapory Windows z **audytem wszystkich zmian polityki zapory** (kto / co / kiedy / skąd).

Wymagania: Windows PowerShell **5.1 (Desktop)**, uruchomienie jako administrator.

## Uruchomienie

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\firewall.ps1
```

## Menu

Numeracja jest stała (1–9). Nowe funkcje audytu trafiają do podmenu opcji 8, więc nikt nie musi renumerować własnych opcji.

| Opcja | Działanie |
|-------|-----------|
| 1–3 | Dodawanie / listowanie reguł (zmiany przez `Invoke-AuditedChange`) |
| 4 | Usuwanie reguły (przez `Invoke-AuditedChange`) |
| 5 | Podgląd dziennika audytu (filtry: dni, operacja, źródło) |
| 6 | Weryfikacja integralności dziennika (łańcuch skrótów, rotacja); opcjonalnie porównanie z zapisanym *head hash* |
| 7 | Synchronizacja audytu teraz (wykrycie zmian wykonanych poza narzędziem) |
| 8 | Ustawienia audytu: **[I]** instalacja / aktualizacja watchera, **[U]** usunięcie watchera, **[F]** przełącznik *fail-closed / fail-open*, **[H]** pokaż *head hash* |
| 9 | Backup: backup now / restore / list (backup server) |
| 10 | Exit |

Pod menu widać stan: watcher (zainstalowany / nieaktywny / ostatni przebieg nieudany / brak udanego przebiegu od > 45 min) oraz wyraźny czerwony wiersz `AUDIT FAIL-OPEN`, gdy włączony jest tryb fail-open, albo informację o zmianach czekających na uzgodnienie.

## Audyt – jak to działa

- Kod audytu mieści się w sekcji `#region AUDIT ... #endregion AUDIT` w `firewall.ps1` (nagłówek opisuje kontrakt dla pozostałych modułów).
- **Zakres:** cały magazyn polityki w rejestrze – reguły (`rule:`), reguły zabezpieczeń połączeń / IPsec (`consec:`), profile (Domain / Private / Public), ustawienia globalne i podgałęzie (np. `Mdm`, `RestrictedServices`) oraz to samo dla **Group Policy** (`gporule:`, `gpoconsec:`, `gpoprofile:`, `gposetting:`). Źródło zmiany jest oznaczane: `oso` (to narzędzie), `gpo`, `system`, `external`.
- Każda zmiana polityki wykonywana przez narzędzie musi przechodzić przez
  `Invoke-AuditedChange -Operation <nazwa> -Scope Names|NewRules|Profiles|All -Action { ... }`.
  Wrapper zapisuje zamiar (`intent`) **przed** akcją (write-ahead), następnie rzeczywisty diff (`change`) i wynik (`result`). Po akcji porównywana jest **cała** polityka – zmiana poza zadeklarowanym zakresem jest zapisana jako `scope-escape` i zgłoszona ostrzeżeniem. Test (AST) pilnuje, by w `firewall.ps1` poza regionem AUDIT nie było poleceń zmieniających politykę poza wrapperem.
- Zmiany wykonane obok narzędzia (GUI, `netsh`, GPO, inne skrypty) wykrywa `Invoke-AuditSync` – przy starcie skryptu, ręcznie (opcja 7) oraz przez watchera.
- **Dziennik:** `C:\ProgramData\FirewallAudit\audit.jsonl` (JSON Lines, UTF-8, czas UTC), łańcuch skrótów SHA-256, rotacja przy 10 MB z zachowaniem ciągłości łańcucha.
- **Katalog audytu** ma własną, chronioną ACL (SYSTEM i Administratorzy; Users tylko odczyt). Istniejący katalog jest sprawdzany przy każdym użyciu: zbyt szerokie uprawnienia są naprawiane i zapisywane jako `integrity`, nieufny właściciel = odmowa pracy. Nieznane pliki `audit-*` w katalogu są raportowane i nie wchodzą do łańcucha.
- **Watcher** (zadanie `\FirewallAudit\Watcher`, SYSTEM) uruchamia chronioną kopię skryptu z `...\FirewallAudit\bin\`. Wyzwalacze: zdarzenia dziennika zapory, start systemu oraz **co 15 minut** (siatka bezpieczeństwa, gdy dziennik zdarzeń jest wyłączony, pełny lub wyczyszczony). Wynik ostatniego przebiegu jest w `state.json`.
- Dla pełnej atrybucji (kto) warto włączyć audyt zdarzeń: `auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable`. Skrypt tylko ostrzega, niczego sam nie włącza.

### Polityka awarii: fail-closed / fail-open

| Tryb | Gdy dziennik jest niedostępny (zablokowany, brak miejsca, błąd ACL, timeout blokady) |
|------|------|
| **Closed** (domyślny) | zmiana **nie jest wykonywana** (brak audytu = brak zmiany) |
| **Open** | zmiana jest wykonywana, wrapper ostrzega, a w `pending.jsonl` (lub dzienniku zdarzeń Aplikacji) zostaje znacznik; następna synchronizacja zapisuje rekord `integrity` / `unlogged-change` i rzeczywisty diff |

- Przełącznik: menu 8 → **F** (wymaga powodu i potwierdzenia) albo parametr `-FailPolicy Default|Closed|Open` dla pojedynczego wywołania `Invoke-AuditedChange`.
- Zmiana trybu to rekord `setting` w dzienniku (kto, kiedy, stara i nowa wartość, powód). `settings.json` z wartością *Open* jest respektowany tylko, gdy zgadza się z ostatnim rekordem `setting` w dzienniku; ręczna edycja daje *Closed* i rekord `integrity`.
- Fail-open nie jest cichy: wiersz `AUDIT FAIL-OPEN` w menu, ostrzeżenie przy każdej zmianie, `FailOpen = $true` w wyniku wrappera.

### Co dziennik NIE gwarantuje (świadome ograniczenia)

- Łańcuch skrótów **nie jest kluczowany** (brak HMAC): administrator, który zna format, może przepisać cały dziennik tak, że łańcuch zweryfikuje się poprawnie; może też obciąć koniec pliku.
- Ochrona: **head hash**. Menu 8 → **H** pokazuje `<seq>:<skrót>` najnowszego rekordu. Zapisz go **poza tym komputerem** (e-mail, zgłoszenie, wydruk). Opcja 6 porównana z zapisaną wartością wykryje obcięcie i pełne przepisanie. Bez zewnętrznej kopii tego nie da się wykryć.
- Administrator może też wyłączyć watchera lub wyczyścić dziennik zdarzeń; skutki widać jako brak udanego przebiegu (stan watchera) i luki w atrybucji, a nie jako blokadę.

## Testy i CI/CD

Projekt posiada automatyczny pipeline CI/CD w **GitHub Actions** ([.github/workflows/ci.yml](.github/workflows/ci.yml)), który przy każdym commicie i pull requeście uruchamia testy na systemach Windows i Linux.

### 1. Testy jednostkowe (uruchamiane lokalnie i w CI)

Wszystkie testy jednostkowe działają w piaskownicy (katalogi tymczasowe, mocki, rejestr HKCU) i **nie modyfikują** rzeczywistej konfiguracji systemu ani nie wymagają uprawnień administratora:

- **Audyt polityki i integralność łańcucha SHA-256 (oraz weryfikacja kontraktu AST):**
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-FirewallAudit.ps1
  ```
- **Moduł kopii zapasowych i przywracania (walidacja kont, SHA-256, SFTP):**
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-BackupModule.ps1
  ```
- **Interfejs CLI, walidacja danych wejściowych i generowanie nazw reguł:**
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-CliHelpers.ps1
  ```
- **Serwer backupu Ubuntu (parsowanie klientów, retencja 30 kopii, sanityzacja):**
  ```bash
  bash ./tests/test-fw-server.sh
  ```

### 2. Ręczny test akceptacyjny E2E (wyłącznie na maszynie testowej / VM)

Czego nie da się sprawdzić bez administratora (zadanie Scheduled Task jako SYSTEM, prawdziwa ACL w `ProgramData`, atrybucja z dziennika zdarzeń) pokrywa **ręczny test akceptacyjny** – uruchamiany na maszynie testowej / w VM:

```powershell
# w oknie PowerShell 5.1 uruchomionym jako administrator
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-WatcherAcceptance.ps1
```

Skrypt instaluje watchera, tworzy i usuwa własne reguły `FWAUDIT-ACCEPT-*` poza narzędziem, czeka na wpisy watchera, sprawdza `state.json`, scenariusz fail-open przy zablokowanym dzienniku oraz łańcuch skrótów; kończy się kodem 0 tylko przy wszystkich zaliczonych krokach. Zapisuje do prawdziwego dziennika audytu.


# Backup

Skrypt `firewall.ps1` zapisuje kopię **wszystkich reguł Zapory Windows** na osobnym serwerze i w każdej chwili potrafi ją przywrócić. Każde przywrócenie trafia do dziennika audytu.

- Kopia powstaje **automatycznie przed każdym dodaniem i usunięciem reguły**, a także na żądanie.
- Przed przywróceniem można zapisać kopię bieżącej konfiguracji (`pre-restore`), więc zawsze jest droga powrotu.
- Przywracany plik jest sprawdzany skrótem SHA-256 po stronie serwera i jeszcze raz na Windowsie, przed importem.

> **Uwaga:** przywrócenie **zastępuje całą politykę zapory**, nie pojedyncze reguły. Nie ma automatycznego cofania, dlatego na pytanie o kopię `pre-restore` odpowiadaj `yes`.

---

## 1. Jak z tego korzystać

Uruchom `firewall.ps1` jako administrator, w menu wybierz **9**, a potem literę:

| Litera | Co robi |
|:------:|---------|
| **B** | zrób kopię teraz |
| **L** | pokaż listę kopii z serwera |
| **R** | przywróć wybraną kopię (trzeba wpisać słowo `RESTORE`) |

Przykład nazwy kopii: `DESKTOP-M67HB24_20261103_163456_auto-add.wfw`, czyli `<komputer>_<data>_<godzina>_<powód>`. Powody: `manual`, `auto-add`, `auto-delete`, `pre-restore`, `scheduled`.

---

## 2. Jak to działa

```
 Windows 10.0.2.20                                Ubuntu 10.0.2.30
 ┌──────────────────────────┐                    ┌──────────────────────────────┐
 │ firewall.ps1 (menu)      │ ─── 1. polecenie ─▶│ fw-server.sh                 │
 │ backup\Backup-*.ps1      │      (SSH :22)     │                              │
 │                          │                    │                              │
 │ sshd  ◀──────────────────│─── 2. eksport ─────│ serwer POBIERA politykę      │
 │ (agent „Export”)         │      (SSH :22)     │                              │
 │                          │                    │ /srv/fwbackups/<konto>/      │
 │ sftp  ◀──────────────────│─── 3. pobranie ────│  backups/*.wfw + *.sha256    │
 └──────────────────────────┘      (SFTPGo :2022)└──────────────────────────────┘
```

1. **Backup (B albo automatycznie):** klient prosi serwer o kopię. Serwer łączy się z Windowsem, pobiera politykę (`netsh advfirewall export`), sprawdza SHA-256 i zapisuje plik `.wfw` oraz `.wfw.sha256`.
2. **Lista (L):** klient pyta SFTPGo o nazwy plików. Widzi tylko kopie, które mają plik `.sha256`.
3. **Przywracanie (R):**
   - serwer sprawdza wybraną kopię i (jeśli chcesz) zapisuje kopię bieżącej konfiguracji,
   - Windows **pobiera** kopię przez SFTP, liczy SHA-256 i porównuje ze skrótem z serwera,
   - dopiero wtedy importuje ją przez moduł audytu (operacja `Restore`), więc zmiana trafia do dziennika.

Serwer **nie wysyła** niczego do Windowsa przy przywracaniu. To usunęło losowe błędy `timeout waiting for request data` i sprawiło, że serwer nie potrzebuje klucza, który pozwala wgrać dowolną politykę na komputer.

---

## 3. Co jest potrzebne

- **Windows** (10.0.2.20): tu działa skrypt i tu są reguły. Zainstalowany OpenSSH Client i **OpenSSH Server**, konto administratora.
- **Ubuntu** (10.0.2.30): tu leżą kopie w `/srv/fwbackups/`. Działa SFTPGo na porcie 2022.
- **Konto `student` w SFTPGo** z uprawnieniami **`list` i `download`** do `/backups`. Bez `upload`, `overwrite`, `delete`, `rename`, czyli kopii nie da się zmienić ani skasować, tylko odczytać.

---

## 4. Instalacja (jednorazowo)

Adresy i nazwy (10.0.2.20, 10.0.2.30, `student`, `Student`) zmień na własne.

### 4.1 Serwer Ubuntu

Użytkownik, katalogi i klucz do pobierania kopii z Windowsa:

```bash
sudo useradd --system --create-home --shell /bin/bash fwbackup
sudo install -d -o fwbackup -g fwbackup -m 750 /etc/fwbackup /srv/fwbackups /var/lib/fwbackup/locks /var/log/fwbackup
sudo -u fwbackup ssh-keygen -t ed25519 -N '' -C fwbackup-export -f /etc/fwbackup/id_export
sudo -u fwbackup sh -c 'ssh-keyscan -t ed25519 10.0.2.20 > /etc/fwbackup/known_hosts'
sudo install -m 755 fw-server.sh /usr/local/bin/fw-server.sh
```

Plik `/etc/fwbackup/clients.conf`, jedna linia: konto, adres Windowsa, nazwa użytkownika Windows:

```
student 10.0.2.20 Student
```

Opcjonalnie kopia co godzinę, w `/etc/cron.d/fwbackup`:

```
0 * * * * fwbackup /usr/local/bin/fw-server.sh scheduled
```

### 4.2 SFTPGo i uprawnienia plików

SFTPGo działa jako użytkownik `sftpgo` i musi móc **czytać** kopie. Katalog z kopiami powinien mieć grupę `sftpgo` i bit setgid, żeby nowe pliki dziedziczyły grupę:

```bash
sudo chgrp sftpgo /srv/fwbackups/student /srv/fwbackups/student/backups
sudo chmod 750 /srv/fwbackups/student
sudo chmod 2750 /srv/fwbackups/student/backups
sudo chgrp sftpgo /srv/fwbackups/student/backups/*     # tylko jeśli już są kopie
sudo chmod 640 /srv/fwbackups/student/backups/*
```

W panelu SFTPGo (użytkownik `student`):
- katalog wirtualny `/backups` wskazuje na `/srv/fwbackups/student/backups`,
- uprawnienia dla `/backups`: **`list` i `download`**,
- logowanie kluczem publicznym klienta (z kroku 4.3), port `2022`.

### 4.3 Windows – skrypty

Układ plików:

```
C:\FW\firewall.ps1
C:\FW\backup\Backup-Create.ps1     tworzenie kopii, agent eksportu, lista
C:\FW\backup\Backup-Restore.ps1    przywracanie
```

```powershell
New-Item -ItemType Directory -Path C:\FW\backup -Force | Out-Null
# skopiuj firewall.ps1 do C:\FW oraz Backup-Create.ps1 i Backup-Restore.ps1 do C:\FW\backup
icacls.exe C:\FW /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"
Get-ChildItem C:\FW -Recurse -Filter *.ps1 | Unblock-File
```

Pliki w `backup\` działają z uprawnieniami administratora, dlatego skrypt odmówi ich wczytania, jeśli zwykły użytkownik ma prawo zapisu do tego katalogu. Katalog `backup` musi leżeć **obok** `firewall.ps1`.

### 4.4 Windows – SSH i zapora

```powershell
Set-Service sshd -StartupType Automatic; Start-Service sshd
New-NetFirewallRule -Name 'FWBackup-SSH-In' -DisplayName 'FWBackup SSH from backup server' `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -RemoteAddress 10.0.2.30 -Profile Any
```

W pliku `C:\ProgramData\ssh\sshd_config` na samym początku dopisz (nazwa konta **małymi literami**):

```
AllowUsers student@10.0.2.30
```

Na końcu pliku:

```
Match Address 10.0.2.30
    PasswordAuthentication no
```

```powershell
Copy-Item "$env:ProgramData\ssh\sshd_config" "$env:ProgramData\ssh\sshd_config.bak" -Force
& "$env:WINDIR\System32\OpenSSH\sshd.exe" -t      # brak wyniku = składnia poprawna
Restart-Service sshd
```

Jeśli sam administrujesz komputerem przez SSH, dopisz w `AllowUsers` także swój adres.

### 4.5 Windows – klucz do rozmowy z serwerem

```powershell
New-Item -ItemType Directory -Path "$env:USERPROFILE\.fwbackup" -Force | Out-Null
ssh-keygen -t ed25519 -N '""' -f "$env:USERPROFILE\.fwbackup\id_ed25519"
ssh-keyscan -t ed25519 -p 22   10.0.2.30 | Out-File -Encoding ascii -Append "$env:USERPROFILE\.fwbackup\known_hosts"
ssh-keyscan -t ed25519 -p 2022 10.0.2.30 | Out-File -Encoding ascii -Append "$env:USERPROFILE\.fwbackup\known_hosts"
Get-Content "$env:USERPROFILE\.fwbackup\id_ed25519.pub"
```

Wypisany klucz publiczny dodaj w **dwóch** miejscach:

1. Na serwerze, w pliku `~fwbackup/.ssh/authorized_keys` (katalog `700`, plik `600`, właściciel `fwbackup`), w jednej linii:
   ```
   from="10.0.2.20",restrict,command="/usr/local/bin/fw-server.sh request student" ssh-ed25519 AAAA... student@KOMPUTER
   ```
2. W koncie `student` w SFTPGo.

### 4.6 Windows – pozwól serwerowi pobierać kopię

Serwer loguje się na Windows kluczem `id_export` i może uruchomić tylko eksport. W `C:\ProgramData\ssh\administrators_authorized_keys` ma być **jedna** linia na ten klucz (inne wpisy zostają):

```powershell
$exportPub = 'ssh-ed25519 AAAA...'     # cała linia z /etc/fwbackup/id_export.pub
if ($exportPub -notmatch '^ssh-ed25519 AAAA\S{40,}') { throw 'Klucz wygląda na niepełny.' }

$ak   = "$env:ProgramData\ssh\administrators_authorized_keys"
$opts = 'no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty'
$cmd  = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:/FW/firewall.ps1 -Agent Export'
if (Test-Path $ak) { Copy-Item $ak "$ak.bak" -Force }
$keep = @(); if (Test-Path $ak) { $keep = @(Get-Content $ak | Where-Object { $_ -notmatch 'FirewallRules\.ps1|firewall\.ps1' }) }
Set-Content -Path $ak -Encoding ascii -Value ($keep + @("command=`"$cmd`",$opts $exportPub"))
icacls.exe $ak /inheritance:r /grant "*S-1-5-18:F" /grant "*S-1-5-32-544:F"
```

Ten plik obowiązuje, bo konto `Student` jest administratorem. Ścieżka w `command=` musi dokładnie wskazywać `firewall.ps1`. Jeśli kiedyś był tu wpis `-Agent Import`, filtr powyżej go usuwa (tryb `Import` już nie istnieje).

### 4.7 Windows – obserwator audytu

Uruchom `firewall.ps1`, wybierz **8**, potem **I**. Po każdej zmianie `firewall.ps1` zainstaluj obserwatora ponownie.
