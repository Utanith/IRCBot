This is an IRCBot. As of this writing, the bot allows users to set personal fields which may be inspected by other users. It's much like a key-value store.

Commands:
* `!addfield <field> <data>` | Sets \<field\> to \<data\>
* `!login <password>` | Authorizes you to use !addfield (And !password if you've set one)
* `!describe <user>` | Alias for !fields \<user\> description
* `!check` | Tells you whether you're logged in or not.
* `!logout` | Logs you out
* `!fields <nick> [field]` | Lists \<nick\>'s fields, or show the value of [field] for \<nick\>
* `!password <password>` | Changes your password to \<password\>

Admin commands:
* `!addspec <field> <spec>` | Allows you to add a special format specifier for a field. {u} is replaced with the subject of the data, {d} is replaced with the field data, and {f} is replaced with the field name
* `!pwreset <user> <password>` | Sets \<user\>'s password to \<password\>
