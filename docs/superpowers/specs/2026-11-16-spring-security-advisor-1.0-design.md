# spring-security-advisor 1.0.0: design

Data: 2026-11-16. Stato: da approvare.

## Intento e perché

Chi installa il plugin vuole sapere **quanta sicurezza c'è davvero** nel suo progetto Spring Boot, cosa manca e dove ci sono debolezze, su un perimetro largo: non solo "la chiave JWT è corta". Oggi (0.2.0) c'è uno scanner con 7 regole e le skill `review` e `map`. Mancano: una vista complessiva con un voto, i temi che le regex non vedono (rotazione e race condition dei refresh token, rate limiting, autorizzazione sugli oggetti) e le regole sui secret e sulla configurazione.

## Obiettivi

1. **Voto da 0 a 100** per tutta la repository, con voto per categoria, riproducibile e non gonfiabile dal modello.
2. **Copertura larga**: autenticazione, token, autorizzazione, sessione/CSRF/CORS, password, rate limiting, secret e configurazione, header e actuator.
3. **Priorità e consigli**: le prime azioni da fare, con rischio, correzione e fonte.
4. **Onestà**: certezza dichiarata per ogni elemento; il voto dice quanta parte è stata verificata.
5. Sola lettura; stabile come 1.0.0.

## Non-obiettivi

- Niente analisi delle dipendenze (CVE), dell'infrastruttura o del runtime.
- Niente `apply` (modifiche automatiche) né `advise` (scelta di architettura): restano fuori dalla 1.0, i consigli stanno nel report.
- Niente parser Java completo.
- Il voto non è una certificazione di sicurezza.

## Anti-obiettivi

- Un voto alto perché il modello è stato generoso.
- Un voto che cambia da una run all'altra sullo stesso codice e le stesse risposte.
- Regole rumorose che fanno perdere fiducia nel voto.

## Approcci considerati

| | Descrizione | Esito |
|---|---|---|
| A | Solo più regole regex | Scartato: non vede race condition, rotazione, rate limiting |
| B | Solo audit del modello | Scartato: voto non riproducibile |
| C | Ibrido: scanner (regole + segnali) + checklist guidata + voto calcolato dallo script | **Scelto da Fabio** |

## Design

### 1. Scanner: più regole

Da 7 a circa 20 regole (`rules.json`), ciascuna **con una fonte verificata** (documentazione ufficiale, RFC; il builder le controlla, per esempio con Context7, e scrive la data del controllo come oggi) e con un caso positivo e uno negativo nei fixture. Candidate (il builder può scartare una regola se non riesce a verificarne la fonte o se è troppo rumorosa):

- CORS: `allowedOrigins("*")` con `allowCredentials(true)`; `@CrossOrigin("*")`.
- JWT: parsing senza verifica della firma (`parseClaimsJwt`, `parseUnsecuredClaims`); token creato senza scadenza; scadenza dell'access token molto lunga (euristica).
- Secret nel codice e nei file di configurazione (`application*.properties|yml`): chiavi JWT, password del database, token. Il valore **non** viene mai stampato.
- Actuator: `management.endpoints.web.exposure.include=*`.
- `anyRequest().permitAll()` o `/**` con `permitAll()`.
- Header: `frameOptions().disable()`, `headers.disable()`; console H2 abilitata.
- Hash deboli: `MD5`/`SHA-1` per password, `Md4PasswordEncoder`, `StandardPasswordEncoder`, `MessageDigestPasswordEncoder`; `BCryptPasswordEncoder` con costo basso.
- Cookie: `HttpOnly`/`Secure` disattivati.
- Casualità non sicura (`java.util.Random`, `Math.random`) per token, OTP, reset.
- SQL costruito per concatenazione in JDBC / query native (euristica).
- Errori: `server.error.include-stacktrace=always`.
- Log di token o password (euristica).
- Refresh token: lettura poi revoca/aggiornamento senza lock né aggiornamento atomico nella stessa unità (euristica, confidenza media, da confermare dalla checklist).

Per leggere la configurazione serve un lettore minimo di `application*.properties` e `application*.yml` (chiavi appiattite, nessuna dipendenza esterna, nessun PyYAML). Le regole sui secret ignorano i segnaposto (`${...}`).

### 2. Scanner: segnali

L'output `scan` ottiene una sezione `signals`: presenza o assenza di meccanismi, con `file:riga`. Esempi: rate limiting (Bucket4j, Resilience4j `RateLimiter`, `RequestRateLimiter` di Spring Cloud Gateway, filtro con "RateLimit"), blocco dopo tentativi falliti, refresh token (entità, repository, metodi), revoca/blacklist, lock e concorrenza (`@Version`, `@Lock`, `PESSIMISTIC_WRITE`, `UPDATE` condizionato, vincoli di unicità), validazione JWT (`JwtDecoder`, `JwtValidators`, issuer/audience), reset password, validazione input (`@Valid`), logout, test di sicurezza presenti.

I segnali non sono finding: servono a dire alla checklist dove leggere e cosa manca.

### 3. Checklist guidata

File `checklists/checklist.json`. Ogni elemento: `id`, `category`, `weight` (1 normale, 2 importante, 3 critico), `question`, `look_for` (cosa cercare nel codice), `signals` (da quale segnale parte; se il segnale manca la domanda diventa "manca il meccanismo?"), `source`.

Esempi per categoria:
- **Token**: access token di breve durata? Il refresh token è monouso e ruota a ogni uso? È salvato come hash? Il riuso di un refresh già usato revoca la famiglia? Il controllo e la revoca sono atomici, così due richieste concorrenti con lo stesso refresh non passano entrambe (race condition)? Il logout revoca? La validazione fissa l'algoritmo e controlla scadenza, issuer, audience?
- **Autenticazione**: rate limiting e/o blocco sul login; messaggi di errore che non rivelano se l'utente esiste; token di reset monouso e a scadenza; cambio password che richiede quella vecchia.
- **Rate limiting**: limite globale sull'API; limiti specifici su login, registrazione, reset password, refresh.
- **Autorizzazione**: negazione di default (`anyRequest().authenticated()`); controllo di proprietà sugli oggetti (IDOR) sugli endpoint con id; sicurezza anche a livello di service; DTO invece di entità nelle richieste (mass assignment).
- **Sessione/CSRF/CORS, Password, Secret e configurazione, Header e actuator**: coperti in gran parte dalle regole, con poche domande aggiuntive.

Il modello legge il codice indicato e risponde per ogni elemento con `answer` (`yes`, `partial`, `no`, `not_applicable`, `cannot_determine`), `evidence` (lista di `file:riga`) e una `note` breve. Le domande su cui non c'è evidenza vanno in `cannot_determine`, non in `yes`.

### 4. Punteggio: `scan.py score`

Comando nuovo: `scan.py score <path> --answers answers.json [--baseline vecchio.json] [--format json|text]`. Esegue la scansione, legge le risposte, calcola. Tutto in codice, documentato nel README:

- **Validazione delle risposte**: un `yes` o `partial` richiede almeno una evidenza; lo script controlla che il file esista nel progetto e che la riga sia nel file. Altrimenti l'elemento passa a `cannot_determine` con il motivo scritto nel report. Come per il ledger, il modello non può gonfiare il voto con le parole.
- **Voto di categoria** (0-100): `100 × guadagnato / disponibile` sugli elementi applicabili e determinabili (`yes` = peso intero, `partial` = metà, `no` = 0), meno le penalità dei finding della categoria (alto 20, medio 10, basso 3; la ripetizione della stessa regola pesa il 25% dopo la prima), con minimo 0. Gli elementi `not_applicable` e `cannot_determine` sono esclusi dal calcolo.
- **Voto totale**: media pesata delle categorie (pesi nel file, token e autorizzazione i più alti) con **tetti**: un finding alto di tipo "bug certo" limita il totale a 69; un elemento critico in `no` lo limita a 79.
- **Lettera**: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F sotto.
- **Copertura**: percentuale di elementi determinabili. Sotto il 70% il voto è etichettato *provvisorio*.
- **Confronto**: con `--baseline`, mostra la differenza rispetto al report precedente. `--save` scrive il report in `.spring-security-advisor/` nel progetto (la skill lo propone, non lo scrive senza consenso).
- Il report elenca le **prime 5 azioni** ordinate per impatto sul voto.

Il voto è deterministico: stesso codice e stesse risposte, stesso risultato.

### 5. Skill

- **`audit` (nuova, comando principale)**: scan con segnali; legge il codice secondo la checklist; compila le risposte con evidenza; esegue `score`; riporta voto totale e per categoria, copertura, prime azioni, finding con rischio / correzione / fonte / certezza, e gli elementi da verificare. Termina con *Scope*, *Non coperto*, *Limiti*.
- **`review`**: resta, come controllo veloce delle sole regole (nessun voto).
- **`map`**: invariata, più i nuovi segnali nell'inventario.
- Convenzioni: lingua dell'utente; mai stampare valori di secret; mai dire "sicuro"; distinguere bug certo, rischio da valutare, miglioramento, stile; i finding euristici sono sempre "da verificare". Per modificare qualcosa serve la richiesta esplicita dell'utente, un cambiamento alla volta.

### 6. Test e fixture

- Fixture nuovo `jwt-refresh-app` con refresh token (versione con race condition e versione corretta), rate limiter presente e assente, secret in `application.yml`.
- Test: ogni regola ha un caso positivo e uno negativo; i fixture `fixed` e `stateless-api` continuano a non produrre finding alti; `score` è deterministico; le evidenze non valide vengono declassate; i tetti funzionano; il lettore di configurazione gestisce `${...}`.
- Test strutturali delle skill (frontmatter con `name` uguale alla cartella e `description` non vuota).
- CI invariata (Python 3.11-3.13).

## Vincoli

- Python 3 standard library, nessuna rete, nessun Maven/JDK, solo lettura dei sorgenti.
- L'output JSON esistente (`findings`, `scope`) resta compatibile; si aggiungono campi.
- Niente commit finché Fabio non lo autorizza.

## Cosa resta al builder

- Selezione finale delle regole (dopo verifica delle fonti), soglie delle euristiche, pesi esatti delle categorie e degli elementi, testo della checklist.
- Testo dei SKILL.md, README (spiegazione del voto, esempio di report), CHANGELOG, versione 1.0.0 in `plugin.json`.
- Aggiornare la roadmap del README: `advise` e `apply` dopo la 1.0.

## Scelte mie (da controllare)

- Soglie del voto (penalità 20/10/3, tetti 69 e 79, lettere) e il 70% di copertura sono una mia proposta: si possono regolare dopo aver visto il voto su un progetto vero.
- `audit` come nome del comando principale, `review` mantenuta.
- Salvataggio del report in `.spring-security-advisor/` e confronto con il baseline: aggiunta mia.
- Il fatto che `advise` e `apply` escano dalla 1.0.
