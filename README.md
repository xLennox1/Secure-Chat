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

Der Server transportiert das Paket, kann es aber nicht öffnen — ihm fehlt die zweite Hälfte.
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

Die Fristen stehen in `app_config` und lassen sich einzeln ändern:

```sql
update public.app_config set value = '30' where key = 'message_retention_days';
select public.purge_old_data();                          -- einmal von Hand
select jobname, schedule, active from cron.job;          -- läuft der Job?
select * from cron.job_run_details order by start_time desc limit 10;
```

Dafür muss **pg_cron** unter *Database → Extensions* aktiviert sein.

---

## Einrichten

### 1. Supabase

1. Neues Projekt anlegen, Region in der EU, wenn die Leute in Europa sitzen.
2. **Database → Extensions**: `pg_cron` einschalten.
3. **SQL Editor**: `supabase/01-schema.sql` ausführen, danach `supabase/02-retention.sql`.
4. **Settings → API Keys**: Publishable Key (`sb_publishable_…`) und Secret Key (`sb_secret_…`)
   kopieren. Die alten `anon`/`service_role`-Keys funktionieren noch, laufen aber Ende 2026 aus.

### 2. Lokal starten

```bash
cp .env.example .env.local
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"   # → INVITE_CODE_PEPPER
npm install
npm run build        # einmal durchlaufen lassen, bevor du pushst
npm run dev
npm run codes -- 3 "Testgeräte"     # in einem zweiten Terminal
```

### 3. GitHub + Vercel

```bash
git init && git add . && git commit -m "Invite-Chat"
git remote add origin git@github.com:DEINNAME/invite-chat.git
git push -u origin main
```

In Vercel das Repo importieren und **vor dem ersten Build** alle Variablen aus `.env.local`
unter *Settings → Environment Variables* eintragen. Danach in Supabase unter
**Authentication → URL Configuration** die Vercel-Domain als *Site URL* eintragen.

---

## Sicherheit: was du einstellen musst

### Supabase

| Einstellung | Wo | Warum |
|---|---|---|
| **RLS auf allen Tabellen** | Table Editor, Spalte „RLS" | Das Schema macht das schon. Prüf trotzdem, dass keine Tabelle als *Unrestricted* markiert ist — das ist der Fehler, der bei Supabase-Projekten am häufigsten alles offenlegt. |
| **Neue Nutzer dürfen sich nicht selbst registrieren** | Authentication → Sign In / Providers → „Allow new users to sign up" **aus** | Sonst kann jeder ein Konto anlegen und die Codes sind sinnlos. Der Server umgeht das legitim über die Admin-API. |
| **Anonymous sign-ins aus** | Authentication → Providers | Dasselbe Loch, andere Tür. |
| **E-Mail-Provider bleibt AN** | Authentication → Providers | ⚠️ Nicht abschalten, auch wenn nie eine Mail versendet wird: Die Anmeldung läuft über `generateLink` + `verifyOtp`, und das ist technisch ein E-Mail-Verfahren. Ist der Provider aus, scheitert `verifyOtp` nach dem Einlösen eines Codes — genau das Symptom „Code eingeben, danach wieder leeres Formular". SMTP kannst du trotzdem unkonfiguriert lassen, es wird ja nie etwas verschickt. |
| **Site URL + Redirect URLs** | Authentication → URL Configuration | Nur deine echte Domain. Keine Wildcards wie `https://*.vercel.app`. |
| **Auth Rate Limits** | Authentication → Rate Limits | Standardwerte runtersetzen. |
| **Secret Key nur serverseitig** | — | Er darf nie in einer Variable mit `NEXT_PUBLIC_` landen. Als zweites Netz antworten die neuen Secret Keys mit HTTP 401, wenn sie aus einem Browser kommen. |
| **MFA für dein Supabase-Konto** | Account → Security | Dein Dashboard-Login ist der Generalschlüssel — für die Metadaten, nicht für die Nachrichten. |
| **Point-in-Time-Recovery** | Database → Backups | Gegen versehentliches `delete from messages`. |
| **Netzwerkbeschränkung** | Database → Network Restrictions | Wenn du nie direkt auf Postgres zugreifst, direkte Verbindungen zumachen. |
| **pg_cron aktiv** | Database → Extensions | Ohne die Extension läuft `02-retention.sql` nicht. |

Unter **Advisors → Security** zeigt Supabase Verstöße gegen genau diese Punkte. Die Liste
sollte leer sein.

### Vercel

| Einstellung | Wo | Warum |
|---|---|---|
| **Deployment Protection für Preview** | Settings → Deployment Protection → Vercel Authentication für Preview | Sonst läuft unter jeder Preview-URL eine voll funktionsfähige Kopie im Netz. Der am meisten unterschätzte Punkt der Liste. |
| **Secret Key nur in Production** | Settings → Environment Variables | Haken bei *Sensitive*. Für Preview idealerweise ein zweites Supabase-Projekt mit eigenen Keys. |
| **Security-Header** | `next.config.mjs` + `middleware.ts` | Siehe unten. Nach dem Deploy auf securityheaders.com gegenprüfen. |
| **WAF / Rate Limiting** | Firewall | `/api/redeem` ist der einzige Endpunkt, den Fremde erreichen. Die App bremst dort schon selbst: 8 Fehlversuche pro IP in 15 Minuten. |

### GitHub

| Einstellung | Wo | Warum |
|---|---|---|
| **Repo privat** | Settings | Auch ohne Secrets: die Struktur deiner RLS-Policies muss niemand kennen. |
| **Secret Scanning + Push Protection** | Settings → Code security | Fängt einen versehentlich committeten `sb_secret_…` ab, **bevor** er im Verlauf landet. |
| **Branch Protection auf `main`** | Settings → Rules | `main` geht live. Direktpushes blockieren, PR erzwingen. |
| **2FA für dein Konto** | Account settings | |
| **Dependabot** | Settings → Code security | Next.js und supabase-js aktuell halten. |

---

## Content-Security-Policy

Die CSP steht in `middleware.ts`, nicht in `next.config.mjs` — sie braucht pro Anfrage eine
frische Nonce. Next.js liest den Header vom Request und hängt die Nonce automatisch an seine
eigenen Skript-Tags.

```
script-src 'self' 'nonce-…' 'strict-dynamic'
```

`'strict-dynamic'` heißt: nur Skripte mit gültiger Nonce laufen, und nur die dürfen weitere
nachladen. Eine eingeschleuste `<script>`-Zeile hat keine Nonce und wird verworfen. Kein
`'unsafe-inline'`, kein `'unsafe-eval'` außer im Dev-Modus.

Die Schriften kommen über `next/font` aus dem eigenen Build, nicht von Google — deshalb steht
in `font-src` nur `'self'`, und beim Besucher fließt keine IP zu Dritten ab.

Bei `style-src` bleibt `'unsafe-inline'` stehen. Next.js injiziert Style-Attribute, die sich
nicht sauber noncen lassen; eingeschleustes CSS ist ungleich harmloser als eingeschleustes JS.

---

## Codes verwalten

```bash
npm run codes -- 5                        # 5 Einladungen, unbegrenzt gültig
npm run codes -- 1 "Laptop Anna"          # mit Notiz für dich
npm run codes -- 10 "Verein" --days 7     # verfallen nach 7 Tagen
```

Die Klartext-Codes erscheinen nur im Terminal und sind danach unwiederbringlich weg. Einzeln
weitergeben, nicht als Liste in einem Gruppenchat.

Geräte-Codes erzeugst du **nicht** hier, sondern in der App selbst unter *Weiteres Gerät
verbinden* — sonst könnte der Server den transportierten Schlüssel lesen.

Zugang entziehen: **Authentication → Users**, Benutzer löschen. Profil, Mitgliedschaften,
Schlüsselzeilen und Nachrichten verschwinden per Cascade mit.

---

## Grenzen, ehrlich benannt

- **Der Sperrcode ist nur so gut wie seine Länge.** Wer dein Gerät in die Hand bekommt, kann den
  Tresor offline angreifen. 600 000 PBKDF2-Runden machen das teuer, aber nicht unmöglich. Nimm
  eine Passphrase aus mehreren Wörtern, keine sechs Ziffern.
- **Der Server sieht die Metadaten.** Wer mit wem, wann, wie oft. Das lässt sich ohne einen ganz
  anderen Aufbau nicht ändern.
- **Kein Ratchet, keine Forward Secrecy je Nachricht.** Ein Gruppenschlüssel gilt für eine ganze
  Epoche. Wer ihn bekommt, kann alles dieser Epoche lesen. Signal treibt das weiter; für einen
  Freundes- oder Vereinschat ist dieser Aufbau angemessen.
- **Der ausgelieferte JavaScript-Code ist die Vertrauensbasis.** Wer das Deployment kontrolliert,
  könnte eine Version ausliefern, die Schlüssel abschöpft. Das gilt für jede Krypto im Browser.
  Branch Protection und Deployment Protection sind deshalb keine Formalie.
- **Kein Schlüsselwechsel und keine Wiederherstellung.** Bewusst so, siehe oben.
