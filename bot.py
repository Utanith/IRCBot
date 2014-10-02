import irc.bot, irc.strings, hashlib
import sqlite3 as sql
from irc.client import ip_numstr_to_quad, ip_quad_to_numstr

help_text = [
        [ "addfield <field> <data>", "Sets <field> to <data>"],
        [ "check", "Tells you whether you're logged in or not."],
        [ "delfield [nick] <field>", "Removes <field> from yourself, if no nick is specified."],
        [ "describe <nick>", "Shortcut for `!fields <user> description`"],
        [ "fields <nick> [field]", "Lists <nick>'s fields, or show the value of [field] for <nick>"],
        [ "login <password>", "Authorizes you to use !addfield (And !password if you've set one)"],
        [ "logout", "Logs you out"],
        [ "password <password>", "Changes your password to <password>"]
]

database = "bot.sql"

# These are default specifications
# When these fields are output the value here is used as a format.
field_specs = {
"age": "{u} is {d} years old.",
"gender": "{u} is {d}."
}

# These variables determine who can access admin commands
# as well as which commands are considered "admin commands"
admins = ["Utanith", "seanc", "LeoNerd", "Dragon"]
admin = ["addspec", "pwreset", "admindel"]

# Pull field specifications from the DB and reinsert them to
# the field_specs variable
def reload_specs():
  con = sql.connect(database)
  cur = con.cursor()
  cur.execute("""SELECT * FROM specs""")
  res = cur.fetchall()
  con.close()

  for s in res:
    print("Adding spec {s} for key {k}.".format(s=s[1], k=s[0].lower()))
    field_specs[s[0].lower()] = s[1]

# Create necessary tables and indexes on the database
def db_init():
  con = sql.connect(database)
  cur = con.cursor()
  cur.execute('CREATE TABLE IF NOT EXISTS users(nick TEXT PRIMARY KEY, password TEXT)')
  cur.execute('CREATE TABLE IF NOT EXISTS fields(user INT, field TEXT, data TEXT)')
  cur.execute('CREATE TABLE IF NOT EXISTS specs(field TEXT, spec TEXT)')
  cur.execute('CREATE INDEX IF NOT EXISTS field_name ON fields (field)')
  con.commit()
  con.close()

# Adds a field format to the DB, then reloads the formats in memory
def add_spec(field, spec):
  con = sql.connect(database)
  cur = con.cursor()
  cur.execute("""INSERT INTO specs VALUES(?, ?)""", (field.lower(), spec))
  con.commit()
  con.close()
  reload_specs()

# Hash the submitted password and look for a corresponding user/pass in DB
# If no match is found, returns false, else true.
def check_password(nick, pw):
  phash = hashlib.sha512(pw).hexdigest()
  con = sql.connect(database)
  cur = con.cursor()
  cur.execute("""SELECT * FROM users WHERE nick = ? and password = ?""", (nick.lower(), phash))
  if cur.fetchone() is not None:
    con.close()
    return True
  con.close()
  return False

# Retrieves the rowid for a nick, or None if the nick doesn't exist in DB
def getUID(nick):
  con = sql.connect(database)
  cur = con.cursor()
  cur.execute("""SELECT rowid FROM users WHERE nick = ?""", (nick.lower(),))
  u = cur.fetchone()
  con.close()
  if u is None:
    return None
  else: 
    return u[0]

# Change or add a password to a nick
def update_password(nick, pw):
  phash = hashlib.sha512(pw).hexdigest()
  con = sql.connect(database)
  cur = con.cursor()
  cur.execute("""SELECT * FROM users WHERE nick = ?""", (nick.lower(),))
  r = cur.fetchone()
  if r is None:
    cur.execute("""INSERT INTO users VALUES (?, ?)""", (nick.lower(), phash))
  else:
    cur.execute("""UPDATE users SET password = ? WHERE nick = ?""", (phash, nick.lower()))
  con.commit()
  con.close()
  return True 

# Checks if the password field in DB is populated
def has_password(nick):
  con = sql.connect(database) 
  cur = con.cursor() 
  cur.execute("""SELECT * FROM users WHERE nick = ?""", (nick.lower(),))
  u = cur.fetchone()
  con.close()
  if u is not None:
    if u[1] is not "":
      return True
  return False

# Adds or updates a key-value pair for nick
def add_field(nick, field, data):
  con = sql.connect(database)
  cur = con.cursor()
  uid = getUID(nick)

  cur.execute("""SELECT COUNT(*) FROM fields WHERE user = ?""", (uid,))
  count = cur.fetchone()
  count = int(count[0])
  if count >= 100:
    return False

  # Decide if we're updating a row or inserting a new one
  cur.execute("""SELECT * FROM fields WHERE user = ? AND field = ?""", (uid, field.lower()))
  if cur.fetchone() is None:
    cur.execute("""INSERT INTO fields VALUES(?,?,?)""", (uid, field.lower(), data))
  else:
    cur.execute("""UPDATE fields SET data = ? WHERE user = ? AND field = ?""", (data, uid, field.lower()))
  con.commit()
  con.close()
  return True


def del_field(nick, field):
  con = sql.connect(database)
  cur = con.cursor()
  uid = getUID(nick) 

  cur.execute("""DELETE FROM fields WHERE user = ? AND field = ?""", (uid, field.lower()))
  con.commit()
  con.close()
  return True

def get_all_fields(nick):
  con = sql.connect(database)
  cur = con.cursor()
  uid = getUID(nick)

  cur.execute("""SELECT field FROM fields WHERE user = ?""", (uid,))
  fields = cur.fetchall()
  con.close()
  return fields

def get_field(nick, field):
  con = sql.connect(database)
  cur = con.cursor()
  uid = getUID(nick) 

  cur.execute("""SELECT data FROM fields WHERE user = ? AND field = ?""", (uid,field.lower())) 
  fields = cur.fetchone() 
  con.close() 
  return fields


class DocBot(irc.bot.SingleServerIRCBot):
  def __init__(self, chan, nick, server, port=6697):
    irc.bot.SingleServerIRCBot.__init__(self, [(server, port)], nick, "Owned by Utanith")
    self.channel = chan
    self.auth = []
    self.server = server
    self.commands = {
    "addfield": self.addfield,
    "login": self.login,
    "check": self.check_auth,
    "describe": self.describe,
    "delfield": self.delfield,
    "logout": self.deauth,
    "fields": self.fields,
    "password": self.set_password,
    "pwreset": self.reset_password,
    "addspec": self.add_spec
    }

  def authorized(self, e, action = "-"):
    nick = e.source
    if {nick.nick, nick.host} in self.auth:
      if action in admin and nick.nick in admins:
        print("Authorized {u} for admin level commands.".format(u=nick.nick))
        return True
      elif action in admin:
        print("User {u} not authorized for admin level commands.".format(u=nick.nick))
        return False
      print("Authorized {u} for user level commands.".format(u=nick.nick))
      return True
    print("User {u} not authorized.".format(u=nick.nick))
    return False

  def addfield(self, e, args = ""):
    source = e.source
    args = e.arguments[0]
    if self.authorized(e, "addfield"):
      field = args.split(" ", 2)
      nick = source.nick
      if add_field(nick, field[1], field[2]):
        self.command_reply(e, "Successfully added field {f} with data {d}.".format(f = field[1], d = field[2]))
      else:
        self.command_reply(e, "Unable to add field.")

  def delfield(self, e, args = ""):
    args = e.arguments[0].split(" ")
    if len(args) == 2 and self.authorized(e, "userdel"):
      #Assume user is target
      if del_field(e.source.nick, args[1]):
        self.command_reply(e, "Successfully delete field {f}.".format(f = args[1]))
      else:
        self.command_reply(e, "Unable to delete field {f}; perhaps it doesn't exist?".format(f = args[1]))
    elif len(args) == 3 and self.authorized(e, "admindel"):
      if del_field(args[1], args[2]):
        self.command_reply(e, "Successfully deleted field {f} on nick {n}.".format(f = args[2], n = args[1]))
      else:
        self.command_reply(e, "Unable to delete field {f} on nick {n}.".format(f = args[2], n = args[1]))

  def login(self, e, args = ""):
    source = e.source 
    args = e.arguments[0]
    pw = args.split(" ", 1)[1]
    nick = source.nick
    if len(pw) < 1:
      self.command_reply(e, "You must use your password to log in.")
    elif self.authorized(e, "-"):
      self.command_reply(e, "You're already logged in!")
    elif check_password(nick, pw):
      self.auth.append({nick, source.host})
      self.command_reply(e, "Successfully logged in.")
    else:
      self.command_reply(e, "Unable to log in.")

  def check_auth(self, e, args = ""): 
    args = e.arguments[0]
    if self.authorized(e, "-"):
      self.command_reply(e, "You are logged in.")
    else:
      self.command_reply(e, "You are not logged in.")

  def describe(self, e, args = ""):
    e.arguments[0] = "!fields {u} description".format(u = e.arguments[0].split(" ")[1])
    self.fields(e)

  def deauth(self, e, args = ""):
    source = e.source 
    args = e.arguments[0]
    if self.authorized(e, "-"):
      self.auth.remove({source.nick, source.host})
      self.command_reply(e, "You have logged out.")
    else:
      self.command_reply(e, "You aren't logged in.")

  def fields(self, e, args = ""):
    source = e.source 
    args = e.arguments[0]
    argv = args.split(" ")
    if len(argv) == 2:
      fields = get_all_fields(argv[1])

      if fields == None or fields == []:
        self.command_reply(e, "User has no fields defined.")
        return
      fields = zip(*fields)
      flist = ""
      for f in fields[0]:
        if flist == "":
          flist = f
        else:
          flist = flist + ", " + f
      self.command_reply(e, "{u} has these fields: {f}".format(u = argv[1], f = flist))
    elif len(argv) == 3:
      output = self.field_text(argv[1], argv[2])
      if output == "":
        self.command_reply(e, "{u} doesn't have a {f}.".format(u = argv[1], f = argv[2]))
      else:
        self.command_reply(e, output)
      
  def set_password(self, e, args = ""):
    source = e.source 
    args = e.arguments[0].split(" ", 1)
    if self.authorized(e, "set_password") or not has_password(source.nick):
      if update_password(source.nick, args[1]):
        self.command_reply(e, "Password changed.")
      else:
        self.command_reply(e, "Unable to update password.")
    else:
      self.command_reply(e, "You must login to change your password.")

  def reset_password(self, e, args = ""):
    source = e.source 
    args = e.arguments[0]
    if self.authorized(e, "reset_password"):
      args = args.split(" ", 2)
      user = args[1]
      password = args[2]
      if update_password(user, password):
        self.command_reply(e, "Password changed.")
      else:
        self.command_reply(e, "Unable to change password.")

  def add_spec(self, e, args = ""):
    args = e.arguments[0]
    if self.authorized(e, "addspec"):
      if len(args.split(" ")) < 2:
        self.command_reply(e, "Not enough arguments.")
      else:
        argv = args.split(" ", 2)
        field = argv[1]
        field_spec = argv[2]
        add_spec(field, field_spec)
        self.command_reply(e, "Added {s} spec for {f}.".format(s = field_spec, f = field))

  def command_reply(self, source, msg):
    c = self.connection
    target = source.target
    if target == c.get_nickname():
      target = source.nick
    c.privmsg(target, msg)

  def field_text(self, user, field):
    data = get_field(user, field)
    if data is None:
     return ""

    data = data[0]
    if field.lower() in field_specs and not data[0] == '!':
     return field_specs[field.lower()].format(u = user, f = field, d = data)
    elif not field[0] == '!':
     return "{u} has defined {f} as {d}".format(u = user, f = field, d = data)
    else:
     return field + ": " + data[1:]

  def on_nicknameinuse(self, c, e):
    c.nick(c.get_nickname() + "_")

  def on_error(self, c, e):
    print(e.arguments[0])

  def on_myinfo(self, c, e):
    print(e.arguments[0])

  def on_welcome(self, c, e):
    c.join(self.channel)
    c.mode(c.get_nickname(), "+B")

  def on_endofmotd(self, c, e):
    print("Setting modes and names...")
    c.mode(c.get_nickname(), "+B")

  def on_privmsg(self, c, e):
    #print(e.target)
    msg = e.arguments[0]
    argv = msg.split(" ", 1)
    command = argv[0][1:]
    if(msg[0] == "!" and command in self.commands):
      self.commands[command](e)
      return
    if "help" in e.arguments[0].split(" "):
      c.privmsg(e.source.nick, "I keep track of various snippets of information about users. All commands can be used in private message or in a channel. Commands:")
      for h in help_text:
        c.privmsg(e.source.nick, "!{c:25} | {t}".format(c = h[0], t = h[1]))

  def on_notice(self, c, e):
    pass
  
  def on_pubmsg(self, c, e):
    msg = e.arguments[0]
    argv = msg.split(" ", 1)
    command = argv[0][1:]
    if(msg[0] == "!" and command in self.commands):
      self.commands[command](e)
      #self.do_command(e)
    return

  def on_part(self, c, e):
    if e.source == self.server:
      return
    if {e.source.nick, e.source.host} in self.auth:
      self.auth.remove({e.source.nick, e.source.host})
      print("User {u} parted channel; destroying auth".format(u=e.source.nick))

  def on_disconnect(self, c, e):
    if e.source == self.server:
      return
    if {e.source.nick, e.source.host} in self.auth:
      self.auth.remove({e.source.nick, e.source.host})
      print("User {u} disconnected; destroying auth".format(u=e.source.nick))

  def on_nick(self, c, e):
    if e.source == self.server:
      return
    if {e.source.nick, e.source.host} in self.auth:
      self.auth.remove({e.source.nick, e.source.host})
      print("User {u} changed nick; destroying auth".format(u=e.source.nick))
      
def main():
  import sys
  if len(sys.argv) != 5:
    print("Usage: docbot <server[:port]> <channel> <nickname> <database>")
    sys.exit(1)

  s = sys.argv[1].split(":", 1)
  server = s[0]
  if len(s) == 2:
    try:
      port = int(s[1])
    except ValueError:
      print("Bad port")
      sys.exit(1)
  else:
    port = 6697
  chan = sys.argv[2]
  nick = sys.argv[3]
  database = sys.argv[4]
  
  bot = DocBot(chan, nick, server, port)
  bot.start()

if __name__ == "__main__":
  db_init()
  reload_specs()
  main()
