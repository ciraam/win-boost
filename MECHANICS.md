# Paramètres & Constantes Système (WinBoost)

Ce document recense les valeurs techniques qui gouvernent le comportement et les garde-fous de WinBoost.

| Paramètre | Groupe | Valeur | Unité | Source |
| :--- | :--- | :--- | :--- | :--- |
| Intervalle de scan Auto-Boost | detection | 2500 | ms | Spécification utilisateur (2-3 s) |
| Plafond CPU cible en veille | performance | 1.0 | % | Spécification utilisateur (< 1 % CPU) |
| Plafond RAM cible en veille | performance | 50 | Mo | Spécification utilisateur (< 50 Mo RAM) |
| Priorité CPU maximale autorisée | cpu | High (0x80) | Win32 class | Garde-fou anti-gel (jamais Realtime) |
| Seuil de cœurs minimum pour exclure Core 0 | cpu | 4 | cœurs logiques | Sécurité multi-cœurs |
| Seuil par défaut de purge Standby List | ram | 2048 | Mo | Estimation équilibrée anti-stutter |
| Cooldown minimum entre purges Standby | ram | 60 | s | Garde-fou anti micro-stutter |
| Valeur DSCP QoS pour le jeu actif | network | 46 | DSCP EF | Standard Expedited Forwarding |
| Paquets par test ICMP Ping | network | 4 | paquets | Standard diagnostic latence/gigue |
| Pause du monitoring dans le Tray | monitoring | true | bool | Spécification zéro impact en jeu |
