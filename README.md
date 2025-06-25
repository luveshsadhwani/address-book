# Minimal KV Store

## 1 . CLI synopsis

`node kv.mjs --as <principal> <command> …`

| Command      | Syntax                                                 | Effect                                                                |
| ------------ | ------------------------------------------------------ | --------------------------------------------------------------------- |
| set          | `set <tenant>:<ns> <key> <value>`                      | Append `{k,key; v,value}` to the namespace log.                       |
| get          | `get <tenant>:<ns> <key>`                              | Stream-scan log and print the most-recent value. Exit 1 if not found. |
| root init    | `root init <tenant> <principal>`                       | Creates the first root for that tenant (only if none exists).         |
| root rotate  | `root rotate <tenant> <newPrincipal>`                  | Current root appoints a new root.                                     |
| (ACL helper) | `set <tenant>:<ns> **acl** "<comma,list,of,users,\*>"` | Last **acl** line defines who may access the namespace.               |

`--as` is mandatory for every call; it identifies the caller.

## 2 . Storage layout

```
data/
├─ <tenant>/ # one folder per tenant
│ └─ <ns>.jsonl # append-only JSON Lines (UTF-8, 1 record / line)
└─ **meta**.jsonl # tenant roots
```

_Record format_ : `{"k":"someKey","v":"someValue"}` (plus `\n`).

## 3 . Roots & ACLs

| Concept            | Where stored                                                                                                                    | Rule                                                                                          |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Tenant root        | `data/__meta__.jsonl` line whose key is `__root__:<tenant>`                                                                     | One per tenant; last write wins. The root bypasses ACL checks only inside its own tenant.     |
| Namespace ACL      | Last line in <tenant>/<ns>.jsonl whose key is `__acl__`                                                                         | Value `"*"` = public, otherwise comma-separated principals. Missing ACL ⇒ nobody except root. |
| Authorisation flow | 1. Extract tenant from namespace. 2. If caller == tenant root → allow. 3. Else read last **acl**; allow if \_ or caller listed. |                                                                                               |

Everything (data, ACLs, roots) is just more lines in JSONL logs—no external DB.

4 . Common examples
bash
Copy
Edit

# bootstrap tenant

node kv.mjs --as ops root init acme alice

# grant public read/write to a namespace

node kv.mjs --as alice set acme:profiles **acl** "\*"

# write a value

node kv.mjs --as bob set acme:profiles user:42 '{"name":"Jane"}'

# read it back

node kv.mjs --as guest get acme:profiles user:42 # prints {"name":"Jane"}

# rotate root

node kv.mjs --as alice root rotate acme charlie
5 . Notes
Append-only writes are atomic per line; last value wins on get.

Blank or malformed lines are ignored during scans.

Filenames avoid : to stay cross-platform (data/<tenant>/<ns>.jsonl).
