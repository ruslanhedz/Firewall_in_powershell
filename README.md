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

## Dla współautorów

- **Adam** (dodawanie reguł), **Aliaksei** (przełączanie profili), **Ruslan** (kopie zapasowe / przywracanie): każda zmiana polityki idzie przez `Invoke-AuditedChange`; nie edytujcie regionu AUDIT. Test kontraktu (`Test-FirewallAudit.ps1`) zakończy się błędem, jeśli poza regionem pojawi się bezpośrednie `New-NetFirewallRule`, `Set-…`, `Remove-…`, `netsh advfirewall` itp.
- Gałęzie `ADAM-firewall_rules` i `Alex-Firewall` nie zmieniają polityki w sposób omijający audyt (stan na dzień przeglądu: tylko usunięcie komentarzy w `firewall.ps1`, scalenie z `main` bez konfliktów).

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
