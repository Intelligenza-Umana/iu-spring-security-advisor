# AGENTS.md

## Scopo
Plugin per Claude Code che esegue un audit di sicurezza su progetti Spring Boot: scanner Python senza dipendenze (`scan.py`), checklist e punteggio da 0 a 100.

## Fonti di verità
Il codice dello scanner e le skill sono la verità tecnica. `README.md` e `CHANGELOG.md` (in inglese) descrivono regole, checklist, punteggio e versioni.

## Regole operative
- **Documentazione sempre allineata.** Ogni modifica (codice, struttura, stato, decisione, versione) aggiorna nella stessa PR tutti i documenti che la riguardano: `README.md`, `CHANGELOG.md`, `docs/`, la versione nel manifest del plugin (`plugins/spring-security-advisor/.claude-plugin/plugin.json`), il numero di regole e di voci della checklist citato nei testi, questo file e la scheda Notion del progetto. Se cambiano versione, stato, descrizione o schema del progetto, controllare anche la sua scheda nel portfolio (`fabio-zagaria-portfolio`: dati in `portfolio-angular/src/app/data`, `README.md` e `docs/CONTEXT.md`). Prima di dichiarare finito un lavoro, passare in rassegna l'elenco e dire per ciascun documento se è stato aggiornato o perché non serve. Una modifica senza documenti allineati non è Done.
- Niente commit, push, merge o deploy senza autorizzazione esplicita del proprietario.
- Nessun segreto, password o token nel repository.
