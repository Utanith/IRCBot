import irc.bot, irc.strings, hashlib
import sqlite3 as sql
from irc.client import ip_numstr_to_quad, ip_quad_to_numstr

help_text = [
        [ "addfield <field> <data>", "Sets <field> to <data>"],
        [ "auth <password>", "Authorizes you to use !addfield (And !password if you've set one)"],
        [ "check", "Tells you whether you're logged in or not.]"],
        [ "deauth", "Logs you out"],
        [ "fields <nick> [field]", "Lists <nick>'s fields, or show the value of [field] for <nick>"],
        [ "password <password>", "Changes your password to <password>"]
]

commands

field_specs = {
"age": "{u} is {d} years old.",
"gender": "{u} is {d}."
}

admin = ["Utanith", "seanc", "LeoNerd", "Dragon"]

def reload_specs():
  con = sql.connect('docbot.sql')
  cur = con.cursor()
  cur.execute("""SELECT * FROM specs""")
  res = cur.fetchall()
  con.close()

  for s in res:
    field_specs[s[0]] = s[1]

def db_init():
  con = sql.connect('docbot.sql')
  cur = con.cursor()
  cur.execute('CREATE TABLE IF NOT EXISTS users(nick TEXT PRIMARY KEY, password TEXT)')
  cur.execute('CREATE TABLE IF NOT EXISTS fields(user INT, field TEXT, data TEXT)')
  cur.execute('CREATE TABLE IF NOT EXISTS specs(field TEXT, spec TEXT)')
  con.commit()
  con.close()

def add_spec(field, spec):
  con = sql.connect('docbot.sql')
  cur = con.cursor()
  cur.execute("""INSERT INTO specs VALUES(?, ?)""", (field, spec))
  reload_specs()
  con.commit()
  con.close()
  print(field_specs)

def check_password(nick, pw):
  phash = hashlib.sha512(pw).hexdigest()
  con = sql.connect('docbot.sql')
  cur = con.cursor()
  cur.execute("""SELECT * FROM users WHERE nick = ? and password = ?""", (nick, phash))
  if cur.fetchone() is not None:
    con.close()
    return True
  con.close()
  return False

def getUID(nick):
  con = sql.connect('docbot.sql')
  cur = con.cursor()
  cur.execute("""SELECT rowid FROM users WHERE nick = ?""", (nick,))
  u = cur.fetchone()
  con.close()
  if u is None:
    return None
  else: 
    return u[0]

def update_password(nick, pw):
  phash = hashlib.sha512(pw).hexdigest()
  con = sql.connect('docbot.sql')
  cur = con.cursor()
  cur.execute("""SELECT * FROM users WHERE nick = ?""", (nick,))
  r = cur.fetchone()
  if r is None:
    cur.execute("""INSERT INTO users VALUES (?, ?)""", (nick, phash))
  con.commit()
  con.close()
  return True 

def has_password(nick):
  con = sql.connect('docbot.sql') 
  cur = con.cursor() 
  cur.execute("""SELECT * FROM users WHERE nick = ?""", (nick,))
  u = cur.fetchone()
  con.close()
  if u is not None:
    if u[1] is not "":
      return True
  return False

def add_field(nick, field, data):
  con = sql.connect('docbot.sql')
  cur = con.cursor()
  uid = getUID(nick)

  cur.execute("""SELECT COUNT(*) FROM fields WHERE user = ?""", (uid,))
  count = cur.fetchone()
  count = int(count[0])
  if count >= 100:
    return False

  cur.execute("""SELECT * FROM fields WHERE user = ? AND field = ?""", (uid, field))
  if cur.fetchone() is None:
    cur.execute("""INSERT INTO fields VALUES(?,?,?)""", (uid, field, data))
  else:
    cur.execute("""UPDATE fields SET data = ? WHERE user = ? AND field = ?""", (data, uid, field))
  con.commit()
  con.close()
  return True

def get_all_fields(nick):
  con = sql.connect('docbot.sql')
  cur = con.cursor()
  uid = getUID(nick)

  cur.execute("""SELECT field FROM fields WHERE user = ?""", (uid,))
  fields = cur.fetchall()
  con.close()
  return fields

def get_field(nick, field):
  con = sql.connect('docbot.sql')
  cur = con.cursor()
  uid = getUID(nick) 

  cur.execute("""SELECT data FROM fields WHERE user = ? AND field = ?""", (uid,field)) 
  fields = cur.fetchone() 
  con.close() 
  return fields


class DocBot(irc.bot.SingleServerIRCBot):
  def __init__(self, chan, nick, server, port=6697):
    irc.bot.SingleServerIRCBot.__init__(self, [(server, port)], nick, "Owned by Utanith")
    self.channel = chan
    self.auth = []

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
    print(e.arguments[0])
    self.do_command(e)
    if "help" in e.arguments[0].split(" "):
      c.privmsg(e.source.nick, "I keep track of various snippets of information about users. All commands can be used in private message or in a channel. Commds:")
      for h in help_text:
        c.privmsg(e.source.nick, "!{c:25} | {t}".format(c = h[0], t = h[1]))

  def on_notice(self, c, e):
    pass
  
  def on_pubmsg(self, c, e):
    print(e.arguments[0])
    msg = e.arguments[0]
    if(msg[0] == "!"):
      self.do_command(e)
    return

  def on_part(self, c, e):
    if({e.source.nick, e.source.host} in self.auth):
      self.auth.remove({e.source.nick, e.source.host})
      print("User {u} parted channel; destroying auth".format(u=e.source.nick))

  def on_disconnect(self, c, e):
    if({e.source.nick, e.source.host} in self.auth):
      self.auth.remove({e.source.nick, e.source.host})
      print("User {u} disconnected; destroying auth".format(u=e.source.nick))

  def on_nick(self, c, e):
    if({e.source.nick, e.source.host} in self.auth):
      self.auth.remove({e.source.nick, e.source.host})
      print("User {u} changed nick; destroying auth".format(u=e.source.nick))

  def do_command(self, e):
    nick = e.source.nick
    c = self.connection
    target = nick if e.target == c.get_nickname() else e.target   
    msg = e.arguments[0].split(" ", 1)
    
    authorized = True if {nick, e.source.host} in self.auth else False

    if msg[0] == "!auth" and len(msg) == 2:
      if check_password(nick, msg[1]):
        self.auth.append({nick, e.source.host})
        c.privmsg(target, "Successfully logged in.")
      else:
        c.privmsg(target, "Unable to log in.")

    elif msg[0] == "!check":
      if authorized:
        c.privmsg(target, "You are authorized.")
      else:
        c.privmsg(target, "You are not authorized.")

    elif msg[0] == "!deauth":
      if authorized:
        self.auth.remove({nick, e.source.host})
        c.privmsg(target, "You have logged out.")

    elif msg[0] == "!password":
      if authorized or not has_password(nick):
        if update_password(nick, msg[1]):
          c.privmsg(target, "Password changed.")
      else:
        c.privmsg(target, "You must !auth to change your password.")

    elif msg[0] == "!addfield":
      if authorized:
        field = msg[1].split(" ", 1)
        if add_field(nick, field[0], field[1]):
          c.privmsg(target, "Successfully added field {f} with data {d}.".format(f = field[0], d = field[1]))
        else:
          c.privmsg(target, "Unable to add field.")
    
    elif msg[0] == "!fields":
      args = msg[1].split(" ")
      if len(args) == 1:
        fields = get_all_fields(args[0])

        if fields == None:
          c.privmsg(target, "User has no fields defined.")
          return
        fields = zip(*fields)
        
        flist = ""
        for f in fields[0]:
          if flist == "":
            flist = f
          else:
            flist = flist + ", " + f
        c.privmsg(target, "{u} has these fields: {f}".format(u = args[0], f = flist))
      elif len(args) == 2:
        field = get_field(args[0], args[1])
        field = field[0]
        if args[1].lower() in field_specs and not field[0] == '!':
          c.privmsg(target, field_specs[args[1].lower()].format(u = args[0], f = args[1], d = field))
        elif not field[0] == '!':
          c.privmsg(target, "{u} has defined {f} as {d}".format(u = args[0], f = args[1], d = field))
        else:
          c.privmsg(target, args[1] + ": " + field[1:])

    elif msg[0] == "!addfield":
      if authorized:
        field = msg[1].split(" ", 1)
        if add_field(nick, field[0], field[1]):
          c.privmsg(target, "Successfully added field {f} with data {d}.".format(f = field[0], d = field[1]))
        else:
          c.privmsg(target, "Unable to add field.")

    elif msg[0] == "!addspec":
      if authorized and nick in admin and len(msg[1].split(" ")) > 2:
        field = msg[1].split(" ", 1)
        field_specs[field[0]] = field[1]
        add_spec(field[0], field[1])
        c.privmsg(target, "Added {s} spec for {f}".format(s = field[1], f = field[0]))
      else:
        c.privmsg(target, "Unable to add spec.")

      
def main():
  import sys
  if len(sys.argv) != 4:
    print("Usage: docbot <server[:port]> <channel> <nickname>")
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
  
  bot = DocBot(chan, nick, server, port)
  bot.start()

if __name__ == "__main__":
  db_init()
  main()
