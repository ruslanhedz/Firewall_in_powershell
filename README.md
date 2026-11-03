# Firewall w PowerShell

Interaktywny skrypt do zarządzania regułami Zapory Windows z **audytem wszystkich zmian polityki zapory** (kto / co / kiedy / skąd).

Wymagania: Windows PowerShell **5.1 (Desktop)**, uruchomienie jako administrator.

## Uruchomienie

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\firewall.ps1
```

> **Plik `FirewallRules.ps1` jest przestarzały.** To pierwsza wersja skryptu, bez audytu – nie należy go uruchamiać, bo zmienia politykę zapory poza `Invoke-AuditedChange`. Jedyny aktualny plik to `firewall.ps1` (usunięcie starego pliku jest przygotowane w indeksie git).

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
| 9 | Wyjście |

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

## Testy

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-FirewallAudit.ps1
```

Testy jednostkowe działają w piaskownicy (katalog tymczasowy, atrapa rejestru w HKCU, prywatny mutex); nie zmieniają prawdziwej polityki zapory i nie wymagają uprawnień administratora. Ostatnia sekcja tylko czyta prawdziwy magazyn polityki.

Czego nie da się sprawdzić bez administratora (zadanie SYSTEM, prawdziwa ACL w `ProgramData`, atrybucja z dziennika zdarzeń) pokrywa **ręczny test akceptacyjny** – uruchamiany na maszynie testowej / w VM:

```powershell
# w oknie PowerShell 5.1 uruchomionym jako administrator
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-WatcherAcceptance.ps1
```

Skrypt instaluje watchera, tworzy i usuwa własne reguły `FWAUDIT-ACCEPT-*` poza narzędziem, czeka na wpisy watchera, sprawdza `state.json`, scenariusz fail-open przy zablokowanym dzienniku oraz łańcuch skrótów; kończy się kodem 0 tylko przy wszystkich zaliczonych krokach. Zapisuje do prawdziwego dziennika audytu.


# Backup

Skrypt zapisuje kopię **wszystkich reguł Zapory Windows** na osobnym serwerze i w każdej chwili potrafi ją przywrócić. Każde przywrócenie trafia do dziennika audytu.

- Kopia powstaje **automatycznie przed każdym dodaniem i usunięciem reguły**, a także na żądanie.
- Przed przywróceniem można zapisać kopię bieżącej konfiguracji (`pre-restore`), więc zawsze jest droga powrotu.
- Przywracany plik jest sprawdzany skrótem SHA-256 po stronie serwera i jeszcze raz na Windowsie, przed importem.

> **Uwaga:** przywrócenie **zastępuje całą politykę zapory**, nie pojedyncze reguły. Nie ma automatycznego cofania, dlatego zalecana odpowiedź na pytanie o kopię `pre-restore` to `yes`.

---

## 1. Jak z tego korzystać

Uruchom `FirewallRules.ps1` jako administrator, w menu wybierz **9**, a potem literę:

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
 │ FirewallRules.ps1 (menu) │ ─── 1. polecenie ─▶│ fw-server.sh                 │
 │ backup\Backup-*.ps1      │      (SSH :22)     │  backup.sh / restore.sh      │
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

Serwer **nie wysyła** już niczego do Windowsa przy przywracaniu. To usunęło losowe błędy `timeout waiting for request data` i sprawiło, że serwer nie potrzebuje klucza, który pozwala wgrać dowolną politykę na komputer.

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
```

Skrypty serwera (biblioteki muszą należeć do roota, żeby `fwbackup` nie mógł zmienić kodu, który wykonuje):

```bash
sudo install -d -m 755 /usr/local/lib/fwbackup
sudo install -m 644 -o root -g root backup.sh restore.sh /usr/local/lib/fwbackup/
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

SFTPGo działa jako użytkownik `sftpgo` i musi móc **czytać** kopie. Katalog z kopiami powinien mieć grupę `sftpgo` i bit setgid, żeby nowe pliki dziedziczyły grupę (nowy `fw-server.sh` zapisuje pliki właśnie tak):

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
C:\FW\FirewallRules.ps1
C:\FW\backup\Backup-Create.ps1     tworzenie kopii, agent eksportu, lista
C:\FW\backup\Backup-Restore.ps1    przywracanie
```

```powershell
New-Item -ItemType Directory -Path C:\FW\backup -Force | Out-Null
# skopiuj FirewallRules.ps1 do C:\FW oraz Backup-Create.ps1 i Backup-Restore.ps1 do C:\FW\backup
icacls.exe C:\FW /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"
Get-ChildItem C:\FW -Recurse -Filter *.ps1 | Unblock-File
```

Pliki w `backup\` działają z uprawnieniami administratora, dlatego skrypt odmówi ich wczytania, jeśli zwykły użytkownik ma prawo zapisu do tego katalogu.

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

Zastrzeżenie: dopisz też adres, z którego sam administrujesz komputerem przez SSH, jeśli taki masz.

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
$cmd  = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:/FW/FirewallRules.ps1 -Agent Export'
if (Test-Path $ak) { Copy-Item $ak "$ak.bak" -Force }
$keep = @(); if (Test-Path $ak) { $keep = @(Get-Content $ak | Where-Object { $_ -notmatch 'FirewallRules\.ps1|firewall\.ps1' }) }
Set-Content -Path $ak -Encoding ascii -Value ($keep + @("command=`"$cmd`",$opts $exportPub"))
icacls.exe $ak /inheritance:r /grant "*S-1-5-18:F" /grant "*S-1-5-32-544:F"
```

Ten plik obowiązuje, bo konto `Student` jest administratorem. Ścieżka w `command=` musi dokładnie wskazywać skrypt.

### 4.7 Windows – obserwator audytu

Uruchom `FirewallRules.ps1`, wybierz **8**, potem **I**. Po każdej zmianie `FirewallRules.ps1` zainstaluj obserwatora ponownie.

---

## 5. Test odbiorczy

| # | Co zrobić | Oczekiwany wynik |
|:-:|-----------|------------------|
| 1 | Ubuntu: `sudo -u fwbackup ssh -T -o LogLevel=ERROR -i /etc/fwbackup/id_export -o UserKnownHostsFile=/etc/fwbackup/known_hosts Student@10.0.2.20 agent \| head -6` | `FWAGENT-BEGIN`, `COMPUTER=`, `SHA256=`, `SIZE=`, `DATA` |
| 2 | Menu **9 → B** | `Backup OK`, na serwerze pojawiają się `.wfw` i `.sha256` |
| 3 | Menu **9 → L** | lista kopii z datą i powodem |
| 4 | Windows: `sftp -P 2022 -i $env:USERPROFILE\.fwbackup\id_ed25519 student@10.0.2.30`, potem `get backups/<plik>` | plik się pobiera |
| 5 | W tej samej sesji `put x.txt backups/x.txt` i `rm backups/<plik>` | **odmowa** (brak `upload` i `delete`) |
| 6 | Dodaj regułę (1) i usuń ją (4) | przed każdą zmianą powstaje kopia `auto-add` i `auto-delete` |
| 7 | **9 → R**, kopia z regułą | `Restore completed`, reguła wraca (opcja 3) |
| 8 | Powtórz restore 10 razy | 10 na 10 bez błędu |
| 9 | Menu **5** i **6** | w dzienniku rekord `Restore`, łańcuch skrótów poprawny |

---

## 6. Gdy coś nie działa

Dzienniki: `/var/log/fwbackup/server.log` (serwer), `C:\ProgramData\FirewallBackup\agent\agent.log` (Windows), `OpenSSH/Operational` w Podglądzie zdarzeń.

| Objaw | Co sprawdzić |
|-------|--------------|
| `Permission denied (publickey)` w `server.log` | klucza `id_export` nie ma w `administrators_authorized_keys`, zła ścieżka w `command=`, złe prawa pliku albo `AllowUsers` pisane wielkimi literami |
| `client not registered on the server` | brak wpisu w `clients.conf` albo nazwa konta ma wielkie litery |
| `download failed ... permission` | w SFTPGo brakuje `download` albo użytkownik `sftpgo` nie ma prawa odczytu pliku (punkt 4.2) |
| `SHA-256 mismatch` | pobranie uszkodzone albo kopia zmieniona; spróbuj jeszcze raz i sprawdź plik na serwerze |
| `backup not found on server` | kopię przycięto (zostaje 30 najnowszych `auto-*` i `scheduled`); odśwież listę |
| `Backup module directory ... is not protected` | popraw ACL katalogu `C:\FW\backup` (polecenie jest w komunikacie) |
| `netsh import failed` | `netsh` odrzucił plik; komunikat jest też w `agent.log` |
| Po przywróceniu nie ma połączenia z serwerem | zaimportowana polityka blokuje SSH lub SFTP; użyj konsoli maszyny i przywróć kopię `pre-restore` |
| Zawieszona operacja na serwerze | `sudo pkill -u fwbackup -f 'ssh -T'; sudo pkill -u fwbackup -f fw-server.sh` |

---

## 7. Bezpieczeństwo i ograniczenia

- **Klucze mają jedno zadanie.** Klucz klienta pozwala tylko wywołać `fw-server.sh request` i listować/pobierać kopie. Klucz `id_export` na Windowsie pozwala tylko na eksport. Żaden klucz nie daje powłoki (`restrict`, `command=`).
- **Adresy są ograniczone** w trzech miejscach: `from=` w kluczu klienta, `Match Address` i `AllowUsers` w `sshd_config`, regułą `FWBackup-SSH-In` dla serwera.
- **Klucze hostów są przypięte** (`StrictHostKeyChecking=yes`).
- **Klient `student` może czytać swoje kopie**, ale nie może ich zmienić ani usunąć. Kopie zawierają reguły zapory, więc traktuj je jak dane wrażliwe.
- **Kopie nie są szyfrowane** i leżą w jednym miejscu. Skrót SHA-256 chroni przed uszkodzeniem, nie przed złośliwą zmianą na serwerze.
- **Brak automatycznego cofania.** Dlatego zapisuj kopię `pre-restore`, a przy pracy zdalnej miej dostęp do konsoli maszyny.
- Jeśli przywrócona polityka blokuje ruch do serwera (porty 22 lub 2022), kolejne kopie i restore nie zadziałają, dopóki jej nie naprawisz.

---

## 8. Ustawienia

| Co | Gdzie | Domyślnie |
|----|-------|-----------|
| Adres serwera | `Backup-Create.ps1`, `$script:BkServerIp` | `10.0.2.30` |
| Porty SFTP/SSH, konto serwisowe, konto SFTP (`UserOverride`) | `Backup-Create.ps1`, `Initialize-BkClient` | `2022`, `22`, `fwbackup`, nazwa użytkownika Windows małymi literami |
| Czekanie na backup / restore | `Backup-Create.ps1`, `Initialize-BkClient` | 120 s / 180 s |
| Ile kopii `auto-*` i `scheduled` zostaje | `fw-server.sh`, `KEEP_AUTO` | 30 |
| Liczba prób pobrania kopii z Windowsa | `fw-server.sh`, `EXPORT_TRIES` | 3 |

---

## 9. Pliki projektu

| Plik | Gdzie leży | Rola |
|------|------------|------|
| `FirewallRules.ps1` | Windows: `C:\FW\` | menu, audyt, ładowanie modułu backupu |
| `Backup-Create.ps1` | Windows: `C:\FW\backup\` | tworzenie kopii, agent eksportu, lista |
| `Backup-Restore.ps1` | Windows: `C:\FW\backup\` | przywracanie |
| `fw-server.sh` | Ubuntu: `/usr/local/bin/` | dyspozytor i funkcje wspólne |
| `backup.sh`, `restore.sh` | Ubuntu: `/usr/local/lib/fwbackup/` | tworzenie kopii i przygotowanie restore |
