# abpq-redirections

Redirections courtes sur `abpq.cc/<chemin>` et dashboard pour les gérer sur https://redirections.abpq.cc.

## Fonctionnement

- Ce Worker sert **abpq.cc**. Pour chaque visite, il cherche le chemin dans le KV `abpq-redirects`.
  - Trouvé → redirection 302 (ou 301), paramètres d'URL transmis, visite comptée.
  - Sinon → la requête part vers le Worker `abpq-home` (service binding `HOME`), qui affiche la home.
- **Aucune déclaration DNS par redirection.** Seuls `abpq.cc` et `redirections.abpq.cc` sont rattachés au Worker (custom domains). Les enregistrements MX/SPF de l'email routing ne sont pas touchés.
- Un changement fait dans le dashboard est actif en moins d'une minute (cache KV de 30 s).

## Données (KV `abpq-redirects`)

| Clé | Contenu |
|---|---|
| `redirects` | `{ [chemin]: { slug, target, description, group, status, createdAt, updatedAt } }` |
| `h:<chemin>` | `{ count, last }` : visites |
| `auth` | sel + hash PBKDF2 du mot de passe du dashboard |

## Accès au dashboard

Protégé par mot de passe (session de 30 jours). Premier réglage : `https://redirections.abpq.cc/setup?token=<SETUP_TOKEN>`, utilisable une seule fois.
Pour réinitialiser : supprimer la clé `auth` du KV, puis repasser par `/setup`.

## Déployer

```
npx wrangler deploy
```
