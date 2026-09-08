# Veille quotidienne Adobe Commerce Cloud / Magento

Agent qui surveille chaque jour :
- les **CVE / vulnérabilités** publiées sur le NVD pour "Magento" et "Adobe Commerce" ;
- les **bulletins de sécurité Adobe** (patchs) ;
- les **nouvelles releases** du dépôt GitHub `magento/magento2` ;
- un ou plusieurs **flux RSS** (blog, forums, etc.).

Dès qu'un nouvel élément apparaît par rapport à la veille, un **email récapitulatif**
est envoyé. Rien n'est renvoyé deux fois : l'état est mémorisé dans `state.json`.

## Option A — Déploiement gratuit via GitHub Actions (recommandé)

1. Créez un nouveau dépôt GitHub (public ou privé) et déposez-y tous ces fichiers.
2. Dans **Settings > Secrets and variables > Actions**, ajoutez ces secrets :
   - `SMTP_HOST` (ex : `smtp.gmail.com`, `smtp.office365.com`, `ssl0.ovh.net`...)
   - `SMTP_PORT` (ex : `587`)
   - `SMTP_USER` (votre adresse d'envoi)
   - `SMTP_PASS` (mot de passe ou **mot de passe d'application** — obligatoire avec Gmail/Office365)
   - `MAIL_FROM` (adresse expéditeur, peut être identique à SMTP_USER)
   - `MAIL_TO` (un ou plusieurs destinataires séparés par des virgules)
3. Le workflow `.github/workflows/watch.yml` tourne automatiquement tous les jours
   à 07h00 UTC. Vous pouvez aussi le lancer manuellement depuis l'onglet **Actions**
   (bouton "Run workflow") pour tester tout de suite.
4. Après chaque exécution, le fichier `state.json` est automatiquement remis à jour
   et commité dans le dépôt (c'est ce qui évite les doublons d'un jour sur l'autre).

## Option B — Cron sur votre propre serveur

```bash
git clone <votre-repo>
cd adobe-commerce-watch
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

export SMTP_HOST=smtp.example.com
export SMTP_PORT=587
export SMTP_USER=alertes@monentreprise.com
export SMTP_PASS=xxxxxxxx
export MAIL_FROM=alertes@monentreprise.com
export MAIL_TO=vous@monentreprise.com,collegue@monentreprise.com

python3 monitor.py
```

Ajoutez ensuite une tâche cron :
```
0 7 * * * cd /chemin/vers/adobe-commerce-watch && source venv/bin/activate && python3 monitor.py >> watch.log 2>&1
```

## Personnaliser les sources

Tout se configure dans `sources.yaml`, sans toucher au code :
- ajoutez/retirez des flux RSS (`type: rss`) — c'est le moyen le plus simple d'ajouter
  un blog, un site d'articles ou un agrégateur ;
- ajoutez d'autres mots-clés NVD (`type: nvd_cve`) si vous voulez suivre d'autres
  produits ;
- ajoutez d'autres dépôts GitHub à surveiller (`type: github_releases`), par exemple
  des extensions que vous utilisez.

## Tester sans envoyer d'email

```bash
DRY_RUN=1 python3 monitor.py
```
Affiche le contenu de l'email qui aurait été envoyé, sans réellement l'envoyer.

## Limites connues

- La page des bulletins Adobe (`helpx.adobe.com/security/products/magento.html`)
  est scrappée par pattern (`apsb`) faute de flux RSS officiel fiable : si Adobe
  change la structure de sa page, ajustez `link_pattern` dans `sources.yaml`.
- L'URL RSS du Magento DevBlog dans `sources.yaml` est indicative : vérifiez-la en
  ouvrant la page du forum et en cliquant sur "Subscribe to RSS Feed".
- L'API NVD publique impose des limites de débit ; en cas d'erreur 403/429
  fréquente, vous pouvez ajouter une clé API NVD (variable `NVD_API_KEY`, non
  implémentée par défaut mais facile à ajouter dans `fetch_nvd_cve`).
