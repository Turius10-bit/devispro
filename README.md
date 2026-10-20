# DevisPro (Flask)

Gestion de devis, clients, produits et utilisateurs — SQLite persistant, sessions, rôles admin/employé.

## Lancer

    python -m venv venv && source venv/bin/activate      # Windows : venv\Scripts\activate
    pip install -r requirements.txt
    python app.py                                        # http://127.0.0.1:5000

Au premier lancement, un compte administrateur est créé (par défaut `admin` / `admin123`) :
**changez le mot de passe dans « Profil »**. Pour choisir vous-même les identifiants initiaux :

    DEVISPRO_ADMIN_USER=moi DEVISPRO_ADMIN_PASSWORD='mot-de-passe' python app.py

Données d'exemple (optionnel) : `flask --app app seed-demo`

## Configuration (variables d'environnement)

| Variable | Rôle | Défaut |
|---|---|---|
| `DEVISPRO_DB` | chemin de la base SQLite | `instance/devispro.sqlite` |
| `DEVISPRO_SECRET` | clé de session | générée dans `instance/secret.key` |
| `DEVISPRO_CURRENCY` | symbole monétaire (`Ar` = ariary, sans centimes) | `Ar` |
| `DEVISPRO_DECIMALS` | décimales affichées/arrondies | 0 pour Ar, 2 sinon |
| `DEVISPRO_COMPANY` / `DEVISPRO_ADDRESS` / `DEVISPRO_EMAIL` | en-tête des devis imprimés | Honey Group Madagascar… |

## Production

    pip install gunicorn && gunicorn -w 2 app:app

## Sauvegardes

Réservées à l'administrateur : *Exporter la base* (menu) et *Importer une base* (page Utilisateurs).
Les anciennes sauvegardes `.sqlite` de la version HTML sont acceptées (les mots de passe sont migrés à la connexion).
Avant chaque import, la base actuelle est copiée dans `instance/backups/`.
