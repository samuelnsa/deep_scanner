# Deep Scanner

Ce projet contient un script Python de reconnaissance et de scan de sites web.

## Description

Le script `deep_scanner.py` permet de :

- vérifier des sous-domaines communs
- tester des répertoires et fichiers sensibles
- détecter des CMS et frameworks connus
- analyser des points d'entrée potentiellement vulnérables
- extraire des éléments de configuration et de rapport

## Fichiers du projet

- `deep_scanner.py` : script principal
- `README.md` : documentation du projet

## Prérequis

- Python 3.x
- Bibliothèque `requests`

Installation :

```bash
pip install requests
```

## Utilisation

```bash
python deep_scanner.py
```

Le script est conçu pour être lancé depuis la ligne de commande. Selon la version, il peut demander ou utiliser une cible à scanner.

## Attention

> Ce type d'outil ne doit être utilisé que sur des systèmes pour lesquels vous avez une autorisation explicite d'audit ou de test.

L’utilisation non autorisée de scripts de scan ou d’exploration de sécurité peut être illégale et contraire aux politiques de sécurité.

## Objectif

Ce projet sert à illustrer des techniques de reconnaissance et d’audit de sécurité dans un contexte éthique et autorisé.

## Licence

Ce projet est fourni à titre éducatif. Vérifiez les règles applicables à votre environnement avant toute utilisation.
