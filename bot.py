import irc.bot, irc.strings, hashlib, os, re, sys, math, inflect
import sqlite3 as sql
from irc.client import ip_numstr_to_quad, ip_quad_to_numstr

# These strings are used only to respond to !version
version = "1.5b"
lastupdate = "October 24, 2014"

# This is put in the bot's real name field
maintainer = "Utanith"

# Store the nickserv pass in an environment variable so we're not leaving it in the repo
nick_pass = os.environ['IRCPASS']

# A dictionary of commands with syntax and help text
# The help command in private messages uses this
help_text = {
         "addfield":  ["addfield <field> <data>", "Sets <field> to <data>"],
         "check":     ["check", "Tells you whether you're logged in or not."],
         "delfield":  ["delfield [nick] <field>", "Removes <field> from yourself, if no nick is specified."],
         "describe":  ["describe <nick>", "Shortcut for `!fields <user> description`"],
         "fields":    ["fields <nick> [field]", "Lists <nick>'s fields, or show the value of [field] for <nick>"],
         "login":     ["login <password>", "Authorizes you to use !addfield (And !password if you've set one)"],
         "logout":    ["logout", "Logs you out"],
         "password":  ["password <password>", "Changes your password to <password>"],
         "Data":      ["", "Fields can generally contain any text. A field that is defined as \"@<field>\" is considered an alias, and will return data from <field>" ]
}

# Set a default database name
database = "bot.sql"

# These are default specifications
# When these fields are output the value here is used as a format.
field_specs = {
"age": "{u} is {d} years old.",
"gender": "{u} is {d}."
}

# These variables determine who can access admin commands
# as well as which commands are considered "admin commands"
super_admin = ["Utanith"]
admins = ["Utanith", "seanc", "LeoNerd"]
admin = ["addspec", "pwreset", "admindel", "raw"]

# Start the inflection engine
inf = inflect.engine()

# The nickname regex
nnregex = "([a-zA-Z][\w\-|\[\]\{\}`^\\\]{0,29})"

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

# Remove a field from a nick
def del_field(nick, field):
  con = sql.connect(database)
  cur = con.cursor()
  uid = getUID(nick) 

  cur.execute("""DELETE FROM fields WHERE user = ? AND field = ?""", (uid, field.lower()))
  con.commit()
  con.close()
  return True

# Returns all the available fields for a nick
def get_all_fields(nick):
  con = sql.connect(database)
  cur = con.cursor()
  uid = getUID(nick)

  cur.execute("""SELECT field FROM fields WHERE user = ? AND NOT (data LIKE '@%')""", (uid,))
  fields = cur.fetchall()
  con.close()
  return fields

# Returns the data in a specific field on nick
def get_field(nick, field):
  con = sql.connect(database)
  cur = con.cursor()
  uid = getUID(nick) 

  cur.execute("""SELECT data FROM fields WHERE user = ? AND field = ?""", (uid,field.lower())) 
  fields = cur.fetchone()
  if fields is None:
    return None

  # If the data is preceded with an @ it's an alias; lookup the rest of the data as a field name
  if fields[0][0] == "@":
    print("Translating alias")
    cur.execute("""SELECT data FROM fields WHERE user = ? AND field = ?""", (uid, fields[0][1:]))
    fields = cur.fetchone()
  con.close() 
  return fields

# The main class
class DocBot(irc.bot.SingleServerIRCBot):
  def __init__(self, chan, nick, server, port=6697):

    # Initialize some variables
    irc.bot.SingleServerIRCBot.__init__(self, [(server, port)], nick, "Maintained by " + maintainer)
    self.channel = chan
    self.auth = []
    self.server = server

    self.commands = { # Global commands
    "addfield": self.addfield,
    "addspec": self.add_spec,
    "check": self.check_auth,
    "delfield": self.delfield,
    "describe": self.describe,
    "fields": self.fields,
    "introduce": self.introduce,
    "logout": self.deauth,
    "raw": self.raw,
    "version": self.version
    }

    self.ccommands = {} # Channel-only commands

    self.pcommands = {  # Private message-only commands
    "login": self.login,
    "password": self.set_password,
    "pwreset": self.reset_password,
    }

  # Checks the auth dictionary to see if a user is logged in
  # This also determines if the user has admin access, but only if needed
  def authorized(self, e, action = "-"):
    nick = e.source
    if (nick.nick, nick.host) in self.auth:
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

  # Parses fields out of a message and stores them in the database under the source nick
  def addfield(self, e, args = ""):
    source = e.source
    args = e.arguments[0]

    if self.authorized(e, "addfield"):
      field = args.split(" ", 2)
      nick = source.nick
      if add_field(nick, field[1], field[2]):
        self.command_reply(e, "I will remember that your {f} {c} {d}.".format(f = field[1], d = field[2], c = "is"))
      else:
        self.command_reply(e, "I'm sorry, there was a probably storing that information.")
    else:
      self.command_reply(e, "You must login to add data to my store.")

  # Remove a field from a nick in the database
  def delfield(self, e, args = ""):
    args = e.arguments[0].split(" ")

    # The user version
    if len(args) == 2 and self.authorized(e, "userdel"):
      #Assume user is target
      if del_field(e.source.nick, args[1]):
        self.command_reply(e, "Successfully deleted field {f}.".format(f = args[1]))
      else:
        self.command_reply(e, "Unable to delete field {f}; perhaps it doesn't exist?".format(f = args[1]))

    # The admin version
    elif len(args) == 3 and self.authorized(e, "admindel"):
      if del_field(args[1], args[2]):
        self.command_reply(e, "Successfully deleted field {f} on nick {n}.".format(f = args[2], n = args[1]))
      else:
        self.command_reply(e, "Unable to delete field {f} on nick {n}.".format(f = args[2], n = args[1]))
    else:
      self.command_reply("You must login to remove data from my store.")

  # Checks a user's password against the database, and adds them to the auth dictionary if successful
  def login(self, e, args = ""):
    source = e.source 
    args = e.arguments[0]
    pw = args.split(" ", 1)[1]
    nick = source.nick

    if len(pw) < 1:
      self.command_reply(e, "You must use your password to log in.")
    elif check_password(nick, pw):
      self.auth.append((nick, source.host))
      self.command_reply(e, "Successfully logged in.")
    elif self.authorized(e, "-"):
      self.command_reply(e, "You're already logged in!")
    else:
      self.command_reply(e, "Unable to log in.")

  # Tells the user whether or not they're logged in
  def check_auth(self, e, args = ""): 
    args = e.arguments[0]
    if self.authorized(e, "-"):
      self.command_reply(e, "You are logged in.")
    else:
      self.command_reply(e, "You are not logged in.")

  # A shortcut to see a nick's description field
  def describe(self, e, args = ""):
    e.arguments[0] = "!fields {u} description".format(u = e.arguments[0].split(" ")[1])
    self.fields(e)

  # Removes the user from the auth dictionary
  def deauth(self, e, args = ""):
    source = e.source 
    args = e.arguments[0]
    if self.authorized(e, "-"):
      self.auth.remove((source.nick, source.host))
      self.command_reply(e, "You have logged out.")
    else:
      self.command_reply(e, "You aren't logged in.")

  # Parses a user message to retrieve a field or a list of fields for a nick
  def fields(self, e, args = ""):
    source = e.source 
    args = e.arguments[0]
    argv = args.split(" ")

    if len(argv) == 2:
      fields = get_all_fields(argv[1])

      # Handle the case where the user has no fields
      if fields == None or fields == []:
        self.command_reply(e, "I don't have any information on {n}.".format(n=argv[1]))
        return

      # Extract just the field names from the database result
      filtered_fields = [i[0] for i in fields]
      flist = inf.join(tuple(filtered_fields))
      self.command_reply(e, "Here is what I know about {u}: {f}".format(u = argv[1], f = flist))

    # Look up a specific field on a user
    elif len(argv) == 3:
      output = self.field_text(argv[1], argv[2])
      if output == "":
        self.command_reply(e, "I don't know {u}'s {f}.".format(u = argv[1], f = argv[2]))
      else:
        self.command_reply(e, output)
      
  # Sets the user's password. This can be done without authorizing if the user has no password
  def set_password(self, e, args = ""):
    source = e.source 
    args = e.arguments[0].split(" ", 1)
    if self.authorized(e, "set_password") or not has_password(source.nick):
      if update_password(source.nick, args[1]):
        self.command_reply(e, "Password changed.")
      else:
        self.command_reply(e, "I was unable to update your password.")
    else:
      self.command_reply(e, "You must login to change your password.")

  # Admin-only, changes another user's password
  # TODO: Generate a password and send it to the nick via PM or MemoServ
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

  # Admin-only, add a field specification
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

  # Return the current version
  # TODO: Also show the git hash
  def version(self, e, args = ""):
    self.command_reply(e, "Version {v}, last updated {d}.".format(v = version, d = lastupdate))

  # Splits a message into IRC-friendly chunks, decides where to send them, and then sends them
  # TODO: Smarter string splitting
  def command_reply(self, source, msg):
    size = sys.getsizeof(msg)
    msgs = math.ceil(size / 450.0)
    
    c = self.connection
    target = self.channel   #Default to respond in channel
    
    if target == c.get_nickname():
      target = source.source.nick   #If the command was a PM, respond in PM

    # Build each message chunk and send it
    for x in xrange(int(msgs)):
      start = 0 + 446*x
      end = start + 450
      c.privmsg(target, msg[start:end])

  # Gets the text for a user's field, applying specifications if they exist for the field
  def field_text(self, user, field):
    data = get_field(user, field)
    if data is None:
     return ""

    data = data[0]
    if field.lower() in field_specs:
     return field_specs[field.lower()].format(u = user, f = field, d = data)
    else:
     return "{u}'s {f} is {d}.".format(u = user, f = field, d = data)

  # Super-admin command. Sends a raw message to the server
  def raw(self, e, args = ""):
    if e.source.nick in super_admin:
      c = self.connection
      msg = e.arguments[0].split(" ", 1)[1]
      print(msg)
      c.send_raw(msg)

  # This is a use-specific command; it might be worthwhile to make a new branch and keep these sorts of things in that branch
  def introduce(self, e, args = ""):
    self.command_reply(e, """
      Hello! My name is {n}, and I am an artificial intelligence designed to help with record keeping around the vet's office.
      I've been integrated into the entire facility, so I'm always around to help you, but I am only allowed to store your name
      and any information you explicitly tell me to remember. If you're not sure how to use me, you can ask me for help. If I 
      can't resolve your issue, please talk to Utanith - He knows my systems inside and out.""".format(n = self.connection.get_nickname()))

  # Changes the bot's nick if the specified nick is taken
  def on_nicknameinuse(self, c, e):
    c.nick(c.get_nickname() + "_")

  # Joins the specified channel and sets mode +B (Usually indicates a bot)
  def on_welcome(self, c, e):
    c.join(self.channel)
    c.mode(c.get_nickname(), "+B")

  # Identify the bot to nickserv
  def on_endofmotd(self, c, e):
    c.privmsg('NickServ', "IDENTIFY " + nick_pass)

  # Parse and respond to commands in private messages
  def on_privmsg(self, c, e):
    msg = e.arguments[0]
    e.arguments[0] = self.natural_commands(msg, True)
    msg = e.arguments[0]   
 
    argv = msg.split(" ", 1)
    command = argv[0][1:]

    # Check to see if the message is a global command
    if(msg[0] == "!" and command in self.commands):
      self.commands[command](e)
      return
    # Check to see if the message is a PM command
    elif(msg[0] == "!" and command in self.pcommands):
      self.pcommands[command](e)
      return

    # We're in PM, so check and see if this is a help command
    if len(argv) > 1 and argv[0] == "help" and argv[1] in help_text:
      item = help_text[argv[1]]
      if item[0] == "":
        c.privmsg(e.source.nick, item[1])
      else:
        c.privmsg(e.source.nick, "!{c:25} | {t}".format(c = item[0], t = item[1]))

    elif "help" in e.arguments[0].split(" "):
      c.privmsg(e.source.nick, "I keep track of various snippets of information about users. All commands can be used in private message or in a channel. Commands:")
      c.privmsg(e.source.nick, "You can ask for further help (help <topic>) on any of the following: {c}".format(c = ", ".join(help_text.keys())))
  
  # Checks if s is a "natural language" command, and returns the !<command> equivalent with arguments if necessary
  # TODO: More regex fixes
  def natural_commands(self, s, pm = False):
    append = ""
    if not pm:
      append = self.connection.get_nickname()
    commands = {
      "(?:\, )?what do you know about {n}\??".format(n=nnregex):  "!fields \\1",
      "(?:\, )?(?:who|what|where|when) (?:is|are) (.+)'s {n}\??".format(n=nnregex):  "!fields \\1 \\2",
      "(?:\, )?remember that my (.+) (?:is|are) (.+)\.?": "!addfield \\1 \\2",
      "(?:\, )?introduce yourself[.!]?": "!introduce",
      "(?:\: )?version": "!version"
    }

    for r in commands.keys():
      m = re.match(append + r, s, re.IGNORECASE)
      if m is not None:
        return m.expand(commands[r]) 
    return s

  # Parses and responds to channel messages
  def on_pubmsg(self, c, e):
    msg = self.natural_commands(e.arguments[0])
    e.arguments[0] = msg
    argv = msg.split(" ", 1) 
    
    command = argv[0][1:]

    # Check and see if this is a global command
    if(msg[0] == "!" and command in self.commands):
      self.commands[command](e)
    # Check and see if this is a channel-only command
    elif(msg[0] == "!" and command in self.ccommands):
      self.ccommands[command](e)
    return

  # We need to take users out of the auth dictionary when they leave the channel
  def on_part(self, c, e):
    if e.source == self.server:
      return
    if (e.source.nick, e.source.host) in self.auth:
      self.auth.remove((e.source.nick, e.source.host))
      print("User {u} parted channel; destroying auth".format(u=e.source.nick))

  # We need to take users out of the auth dictionary when they disconnect
  def on_disconnect(self, c, e):
    if e.source == self.server:
      return
    if (e.source.nick, e.source.host) in self.auth:
      self.auth.remove((e.source.nick, e.source.host))
      print("User {u} disconnected; destroying auth".format(u=e.source.nick))

  #We need to take users out of the auth dictionary when they change nicks
  def on_nick(self, c, e):
    if e.source == self.server:
      return
    if (e.source.nick, e.source.host) in self.auth:
      self.auth.remove((e.source.nick, e.source.host))
      print("User {u} changed nick; destroying auth".format(u=e.source.nick))
    
# Initialize
def main():
  import sys
  if len(sys.argv) != 5:
    print("Usage: docbot <server[:port]> <channel> <nickname> <database>")
    sys.exit(1)

  database = sys.argv[4]
  db_init()
  reload_specs()

  s = sys.argv[1].split(":", 1)
  server = s[0]
  if len(s) == 2:
    try:
      port = int(s[1])
    except ValueError:
      print("Bad port")
      sys.exit(1)
  else:
    port = 6667
  chan = sys.argv[2]
  nick = sys.argv[3]
  database = sys.argv[4]
  
  bot = DocBot(chan, nick, server, port)
  bot.start()

# Start the bot
if __name__ == "__main__":
  main()
