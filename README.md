# bot2-v2.0
Xanax On Arrival 
==============================
X O A Bot2 v2.0 - How To Work 
---------------- 
Author - Frostygt123 aka Skid Larp
Date - 9/19/25 
------- 
Py backend to run discord bot when token and channel id is replaced, and there is 35 Dos, Ping, Lookups, &amp; more option's of choice....  
------ 
Download zip for REQ to setup &amp; more...  
_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_ 
Make sure to join the discord... 
-------------------

1. OVERVIEW
------------
X O A Bot2 v2.0 is a Discord bot designed for:
- Network analysis
- Domain/IP tools
- Nmap scanning
- Logging results to an SQL database

This bot stores user commands, scan results, and optional blacklist information.

-------------------------------------------------
2. SQL DATABASE 
-------------------------------------------------
Database: xoa_bot
Supported SQL engines: MySQL, MariaDB, PostgreSQL, SQLite

Tables:

1) users
- id (BIGINT PRIMARY KEY)          : Discord user ID
- username (VARCHAR(50))           : Discord username
- discriminator (VARCHAR(10))      : Discord tag
- joined_at (DATETIME)             : Default CURRENT_TIMESTAMP

2) commands_log
- id (INT AUTO_INCREMENT PRIMARY KEY)
- user_id (BIGINT)                 : References users.id
- command_name (VARCHAR(50))
- target (VARCHAR(100))
- timestamp (DATETIME)             : Default CURRENT_TIMESTAMP
- success (BOOLEAN)
- output (TEXT)

3) scan_results
- id (INT AUTO_INCREMENT PRIMARY KEY)
- user_id (BIGINT)                 : References users.id
- target (VARCHAR(100))
- scan_type (VARCHAR(50))
- result (TEXT)
- timestamp (DATETIME)             : Default CURRENT_TIMESTAMP

4) blacklist
- id (BIGINT PRIMARY KEY)
- reason (TEXT)
- added_at (DATETIME)              : Default CURRENT_TIMESTAMP

-------------------------------------------------
3. HOW IT WORKS
-------------------------------------------------
1) User Interaction
- Users run commands in Discord (e.g., /domain_lookup, /nmap_scan)
- Bot checks if the user is allowed (not blacklisted)
- Stores user info in 'users' table

2) Command Logging
- Each command is logged in 'commands_log':
  - user ID
  - command name
  - target IP/domain
  - success/failure
  - timestamp

3) Scan Results Storage
- Nmap scans, traceroutes, geolocation results stored in 'scan_results'
- Allows history retrieval (e.g., /history <user>)

4) Blacklist Handling
- Blacklisted users cannot run commands
- Admins manage blacklist via SQL or bot commands

-------------------------------------------------
4. BOT REQUIREMENTS
-------------------------------------------------
Software:
- Python >= 3.11
- discord.py 2.x         (pip install -U discord.py)
- requests               (pip install requests)
- SQL Library:
    - MySQL: mysql-connector-python
    - PostgreSQL: psycopg2-binary
    - SQLite: built-in (sqlite3)
- Nmap installed on host

Discord:
- Bot token
- Target channel ID for logs
- Permissions:
    - Send messages
    - Use slash commands
    - Read message history (optional)

Optional:
- traceroute / tracert installed
- Internet connection for geolocation API requests

-------------------------------------------------
5. EXAMPLE SQL USAGE (Python)
-------------------------------------------------
Connect to DB and log commands / scan results:

import mysql.connector
from datetime import datetime

conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="password",
    database="xoa_bot"
)
cursor = conn.cursor()

def log_command(user_id, command_name, target, success, output):
    cursor.execute(
        "INSERT INTO commands_log (user_id, command_name, target, success, output) VALUES (%s, %s, %s, %s, %s)",
        (user_id, command_name, target, success, output)
    )
    conn.commit()

def save_scan_result(user_id, target, scan_type, result):
    cursor.execute(
        "INSERT INTO scan_results (user_id, target, scan_type, result) VALUES (%s, %s, %s, %s)",
        (user_id, target, scan_type, result)
    )
    conn.commit()

Thx For Your Support :>
