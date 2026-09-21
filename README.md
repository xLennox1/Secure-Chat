# Invite-Chat

Privater Chat im Browser, Ende-zu-Ende verschlüsselt. Herein kommt nur, wer einen
Einmal-Code hat. Direktnachrichten und Gruppen, Nachrichten laufen live über Supabase
Realtime — als Chiffrat, das der Server nicht lesen kann.

- **Next.js** (App Router) auf **Vercel**
- **Supabase** für Datenbank, Auth und Realtime
- **GitHub** als Quelle für die automatischen Deployments

---

## Was hier verschlüsselt ist, und was nicht

| | |
|---|---|
| **Nachrichtentext** | AES-256-GCM. Der Schlüssel existiert nur in den Browsern der Mitglieder. In der Datenbank steht Chiffrat, sonst nichts — es gibt keine Klartextspalte. |
| **Schlüsselverteilung** | ECDH P-256 → HKDF-SHA-256. Der Gruppenschlüssel wird für jedes Mitglied einzeln verpackt. |
| **Dein Schlüssel auf dem Gerät** | AES-256-GCM, Schlüssel aus dem Sperrcode über PBKDF2-SHA-256 mit 600 000 Runden. Liegt in IndexedDB. |
| **Nicht verschlüsselt** | Wer mit wem schreibt, wann, wie oft, Gruppennamen und Benutzernamen. Diese Metadaten sieht der Server. |

### Wie ein Schlüssel zu dir kommt

Jedes Konto hat ein ECDH-Schlüsselpaar. Der öffentliche Teil steht im Profil, der private
verlässt das Gerät nie — außer verschlüsselt, wenn du ein zweites Gerät verbindest.

Für jede Unterhaltung gibt es je **Epoche** einen zufälligen AES-Schlüssel. Wer ihn hat,
verpackt ihn mit *statischem* ECDH für jedes Mitglied: mein privater mal dein öffentlicher
Schlüssel ergibt beidseitig dasselbe Geheimnis. Statisch statt ephemer, weil der Empfänger so
prüfen kann, **von wem** die Verpackung stammt. Passt der Schlüssel in der Zeile nicht zu dem
Profil, das sie angelegt hat, wird sie verworfen.

Dazu drei Sperren in der Datenbank:

- `conversation_keys` hat **keine UPDATE- und keine DELETE-Policy**. Eine einmal geschriebene
  Schlüsselzeile ist unveränderlich. Niemand kann dir nachträglich einen eigenen Schlüssel
  unterschieben.
- `profiles` lässt den öffentlichen Schlüssel **genau einmal** setzen. Danach ist die Zeile
  eingefroren. Selbst wer eine Sitzung übernimmt, kann seinen Schlüssel nicht an deine Stelle
  setzen, um künftig mitzulesen.
- Jeder Ciphertext trägt Unterhaltung und Epoche als authentifiziertes Datum. Eine Nachricht
  lässt sich nicht in eine andere Unterhaltung umhängen.

### Neue Mitglieder sehen keinen alten Verlauf

Kommt jemand in eine Gruppe, steigt die Epoche und ein frischer Gruppenschlüssel wird nur an
die jetzigen Mitglieder verteilt. Für die älteren Epochen bekommt die neue Person keinen
Schlüssel — der alte Verlauf bleibt für sie unlesbar.

### Was das kostet

- **Vergisst du den Sperrcode, ist der Verlauf weg.** Es gibt keine Wiederherstellung, weil es
  keine Stelle gibt, die mitlesen könnte. Das ist der Punkt.
- **Wer neu in eine Unterhaltung kommt, muss warten**, bis ein bestehendes Mitglied den Chat
  einmal öffnet. Erst dann wird der Schlüssel für ihn verpackt. Die App zeigt das an.
- **Kein Schlüsselwechsel.** Gerät verloren heißt: Konto in Supabase löschen und neu einladen.

---

## Automatische Sperre

Nach `NEXT_PUBLIC_IDLE_MINUTES` ohne Eingabe (Standard: 5) passiert dreierlei:

1. Alle entschlüsselten Schlüssel werden aus dem Arbeitsspeicher gelöscht.
2. Die Supabase-Sitzung wird lokal abgemeldet — im Browser bleibt kein brauchbares Token.
3. Es erscheint der Entsperrbildschirm.

Dreißig Sekunden vorher warnt ein Hinweis, damit niemand mitten im Tippen herausfliegt. Timer
in Hintergrund-Tabs werden von Browsern gedrosselt, deshalb wird beim Zurückkehren zusätzlich
die tatsächlich verstrichene Zeit geprüft.

Zurück kommst du mit dem **Sperrcode**, nicht mit einem neuen Einladungscode: die Sitzung liegt
mit dem Sperrcode verschlüsselt im Tresor und wird beim Entsperren wiederhergestellt. Genau das
war der Grund, es nicht als harte Abmeldung zu bauen — sonst wäre man nach fünf Minuten Pause
dauerhaft ausgesperrt, ohne dass ein anderes Gerät aushelfen kann.

Nach **fünf falschen Eingaben** löscht sich der Tresor. Dann hilft nur ein neuer Code.

Frist ändern: `NEXT_PUBLIC_IDLE_MINUTES` in Vercel setzen und neu deployen.

---

## Zwei Sorten Code

| | Länge | Wofür |
|---|---|---|
| **Einladung** | 16 Zeichen | Neues Konto. Benutzername wird beim Einlösen vergeben. |
| **Gerät** | 20 Zeichen | Weiteres Gerät für ein bestehendes Konto. |

Die App erkennt an der Länge, worum es sich handelt. Beide gelten genau einmal.

### Der Trick beim Geräte-Code

Der Code entsteht **im Browser** des Geräts, das schon drin ist. Er wird in der Mitte geteilt:

- Die ersten 10 Zeichen gehen an den Server und werden dort als HMAC-Hash abgelegt. Sie
  berechtigen zur Anmeldung.
- Die letzten 10 Zeichen **verlassen den Browser nie**. Mit ihnen verschlüsselt das Gerät
  seinen eigenen Identitätsschlüssel. Dieses Paket lädt es als `payload` hoch.

Der Server transportiert das Paket, kann es nicht öffnen — ihm fehlt die zweite Hälfte.
Das neue Gerät tippt den vollständigen Code, schickt nur die erste Hälfte an den Server und
entschlüsselt mit der zweiten das Paket. Der Code gilt zehn Minuten, wird nach dem Einlösen
sofort entwertet und das Paket im selben Zug aus der Datenbank gelöscht.

Gib ihn über einen Weg weiter, den sonst niemand mitliest — er ist für diese zehn Minuten der
Schlüssel zu deinem ganzen Verlauf.

### Fingerabdrücke

Unter **Schlüssel** in der Seitenleiste steht für jede Person eine kurze Zeile aus dem
SHA-256 ihres öffentlichen Schlüssels. Vergleicht sie über einen anderen Kanal, am besten
persönlich. Stimmen sie überein, hat unterwegs niemand Schlüssel ausgetauscht — auch der
Serverbetreiber nicht.

---

## Aufräumen

`02-retention.sql` legt einen `pg_cron`-Job an, der täglich um 03:17 UTC läuft und löscht:

- Nachrichten älter als 90 Tage, dazu die Schlüssel-Epochen, zu denen es keine Nachricht mehr gibt
- Einlöse-Versuche älter als 7 Tage
- abgelaufene Geräte-Codes samt transportiertem Schlüsselpaket
- verfallene Einladungscodes älter als 30 Tage
- Unterhaltungen ohne Nachrichten

Die Fristen stehen in `app_config` und lassen sich einzeln ändern.

---

## Einrichten

### 1. Supabase

1. Neues Projekt anlegen.
2. **Database → Extensions**: `pg_cron` einschalten.
3. **SQL Editor**: `supabase/01-schema.sql`, danach `supabase/02-retention.sql` ausführen.
4. API-Schlüssel und Secret Key sicher als Umgebungsvariablen hinterlegen.

### 2. Lokal starten

```bash
cp .env.example .env.local
npm install
npm run build
npm run dev
```

### 3. GitHub + Vercel

Das Projekt kann direkt aus diesem Repository bei Vercel importiert werden.

## Codes verwalten

```bash
npm run codes -- 5
npm run codes -- 1 "Laptop Anna"
npm run codes -- 10 "Verein" --days 7
```

Die Klartext-Codes erscheinen nur im Terminal und sind danach unwiederbringlich weg.

## Grenzen

- Der Server sieht Metadaten wie Beteiligte und Zeitpunkte.
- Es gibt keinen Nachrichten-Ratchet und keine Forward Secrecy je Nachricht.
- Der ausgelieferte Browser-Code ist Teil der Vertrauensbasis.
- Kein Schlüsselwechsel und keine Wiederherstellung.
