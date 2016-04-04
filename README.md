# Labo 5 GTI619 - Shapr
## Installation
  1. Installer Python 3 et possiblement les fichiers de développement pour Python (`python3-dev`).
  2. Cloner le repo `git clone git@github.com:isra17/gti619_tp5.git`.
  3. Configurer l'environnement Python avec `virtualenv -p python3 venv` et `source venv/bin/activate`.
  4. Installer les dépendances avec `pip install -r requirements.txt`.
  5. Créer la base de donnée avec `python manage.py db upgrade`.
  6. Créer les utilisateurs initiaux avec `python manage.py seed`.

## Exécution
Rouler le serveur avec `DEBUG=1 python manage.py runserver`.
Naviguer sur [http://localhost:5000](http://localhost:5000).
Connectez-vous avez l'un des utilisateurs suivant:
  * `Administrateur` / `Administrateur`
  * `Utilisateur1` / `Utilisateur1`
  * `Utilisateur2` / `Utilisateur2`

