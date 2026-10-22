# The directory: mail schema and what it controls

Elemta keeps people in an LDAP directory: `elemta-ldap`, OpenLDAP 2.6 built
from `docker/ldap`, or a directory you already run. This page describes the
mail schema it uses and what each part does, so the directory can drive
forwarding, sending rights, lists, domains and classes of service, as well
as the dashboard.

The schema is `docker/ldap/10-mail-schema.ldif`. New directories load it when
they are created. `scripts/ldap-schema.sh` adds what an existing directory
lacks, by name, without changing a definition that is already there.
`scripts/cloud-deploy.sh`, `ldap-migrate.sh`, `restore.sh` and the dev
bootstrap run it on every deploy.

## Where entries live

| Branch | Holds |
|---|---|
| `ou=people` | Accounts (`inetOrgPerson`, `posixAccount`, `elemtaMailAccount`) |
| `ou=groups` | Groups (`groupOfNames`); distribution lists add `elemtaMailList` |
| `ou=domains` | Mail domains (`elemtaMailDomain`) |
| `ou=mail-addresses` | Reservations that keep two accounts from claiming one address |
| `ou=services` | The accounts Elemta's own components bind as |

The mailbox service looks accounts up under `ldap_base` (`ou=people,…`) and
lists and domains under `ldap_directory_base`, which defaults to the parent of
`ldap_base` when that is an `ou` (here `dc=example,dc=com`). Set it in the
mailbox configuration's `[auth]` section if your groups and domains live
elsewhere.

Groups use `groupOfNames` with `member` DNs, and the directory keeps each
member's `memberOf` up to date (the `memberof` overlay). A group that predates
this setting doesn't gain `memberOf` values until its members change.

## Accounts: `elemtaMailAccount`

| Attribute | Meaning |
|---|---|
| `mailAlternateAddress` | Aliases. Mail to them is delivered to the account. |
| `accountStatus` | `active` (or unset), `suspended` (receives mail, can't sign in), or anything else for disabled (neither). |
| `mailQuotaSize` | Quota in bytes. Unset means the class of service decides. |
| `elemtaForwardTo` | Forward all mail to these addresses (up to 10). |
| `elemtaForwardKeepCopy` | `TRUE` also keeps a copy in the mailbox. Without it, forwarded mail isn't stored. |
| `elemtaSendAs` | Addresses the account may use as its sender, besides its own: an alias, a list or a shared address. `@example.com` allows every address in that domain. |
| `elemtaClassOfService` | The name of a class of service defined in the mailbox service. |

Forwarding happens before the account's own filters, which then see only the
copy kept here, if any. It goes out like a filter's redirect: through
submission, with the original sender, once per message even if delivery is
retried. A message that comes back to the account it was forwarded from is
kept there instead of going round again. A class of service that turns off
forwarding outside the server stops forwarding to outside addresses too.

Send-as rights are checked whenever mail is sent through submission, from
the webmail or a mail app. In the webmail, the addresses an account may send
as appear as choices for From when writing, and a reply to mail sent to one
of them goes out from it. (A grant for a whole `@domain` isn't offered there,
since there's no one address to offer; mail apps can use any address in it.)

Users change their own forwarding in the webmail (Settings, Account,
"Forwarding"); the webmail does it as them, and the directory lets a user
write those two attributes of their own entry and nothing else. Send-as
rights are only for administrators to grant: in the dashboard (account
details, "Forwarding and sending"), with
`elemta provision modify-account --forward … --keep-copy --send-as …`, or in
the directory directly. A domain administrator can grant only addresses in
their own domains.

## Distribution lists: `elemtaMailList`

Add `elemtaMailList` to a group to make it a list:

| Attribute | Meaning |
|---|---|
| `mail` | The list's address (required) |
| `mailAlternateAddress` | Other addresses for the list |
| `member` | Members by DN: people, or other lists |
| `elemtaListMember` | Members by address, on this server or anywhere else |
| `elemtaListOwner` | Gets the list's bounces and may always post |
| `elemtaListPosting` | `anyone` (or unset), `members`, `domain` or `owner`. Any other value means `members`. |
| `displayName`, `description` | Shown in the address book and in `List-Id` |

```ldif
dn: cn=sales,ou=groups,dc=example,dc=com
objectClass: groupOfNames
objectClass: elemtaMailList
cn: sales
mail: sales@example.com
displayName: Sales team
member: uid=dana@example.com,ou=people,dc=example,dc=com
elemtaListMember: partner@agency.example
elemtaListOwner: dana@example.com
elemtaListPosting: members
```

Directory lists deliver exactly like lists made in the dashboard: local
members through their own filters and quota, one copy to the outside members,
nested lists, loop protection and `List-Id`. The webmail's address book
offers them.

## Domains: `elemtaMailDomain`

| Attribute | Meaning |
|---|---|
| `elemtaDomainName` | The domain (required; also the entry's RDN) |
| `elemtaCatchAll` | Gets mail for addresses in the domain that don't exist |
| `elemtaAliasDomainOf` | Every address here means the same name at that domain |
| `elemtaClassOfService` | The class of service for the domain's accounts |
| `description` | Free text |

```ldif
dn: elemtaDomainName=example.com,ou=domains,dc=example,dc=com
objectClass: elemtaMailDomain
elemtaDomainName: example.com
elemtaCatchAll: inbox@example.com
elemtaClassOfService: staff
```

The MTA still accepts mail for the domains in `local_domains`, which the
dashboard's domain list maintains. A domain entry adds routing and a class;
it doesn't make the server accept a new domain on its own.

## The directory and the dashboard together

The mailbox service also keeps lists, domain routes and class assignments,
which the dashboard edits. Where the directory says something, it wins;
where it says nothing, the dashboard's setting applies:

- **Lists:** a directory list hides a dashboard list with the same address.
- **Catch-all and alias domains:** a domain entry's `elemtaCatchAll` or
  `elemtaAliasDomainOf` replaces the dashboard's for that domain.
- **Classes of service** stack, each later one overriding the earlier:
  the default class, then the dashboard's domain class, then the domain
  entry's class, then the account's `elemtaClassOfService`, and last a class
  chosen for the account in the dashboard, which is the administrator's
  explicit override. A class name the mailbox service doesn't define is
  ignored, as if unset.

Each mailbox replica remembers a domain entry and an account's class for up
to 30 seconds, so a change in the directory takes effect within that time.

## Access

`scripts/ldap-service-accounts.sh` sets who may read what. The mailbox and
SMTP service accounts read people, groups and domains; the provisioning
account writes them. Users may change their own forwarding and nothing
else in their entry but their password. No service account can read a
password, and anonymous binds see nothing but the root entry.

## Object identifiers

`mailAlternateAddress`, `accountStatus` and `mailQuotaSize` keep the OIDs of
the published [mail directory schema](https://github.com/amery/qmail/blob/master/qmail.schema)
they come from, so a directory that already defines them keeps its own
definitions. Elemta's own definitions are under
`2.25.264978151140743919262615765353185555365`, an arc derived from a UUID
(ITU-T X.667) that needs no registration: `.1.n` for attributes and `.2.n`
for object classes. New definitions take the next number; none is ever
reused.
