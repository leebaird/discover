Databases

 
# MS-SQL

Locate
msf > use auxiliary/scanner/mssql/mssql_ping
nmap -sU -Pn -n -T4 --open -p1434 <targetRange>

nmap -p1433 --script ms-sql-info <targetIP>
nmap -p1433 --script ms-sql-brute --script-args mssql.instance-all,userdb=userlist.txt,passdb=wordlist.txt <targetIP>

msf > use auxiliary/scanner/mssql/mssql_login
msf > use auxiliary/admin/mssql/mssql_enum
msf > use auxiliary/scanner/mssql/mssql_hashdump
msf > use auxiliary/admin/mssql/mssql_escalate_dbowner

Post exploitation
msf > use auxiliary/admin/mssql/mssql_exec
------------------------------------------------------------------------------------------------------

# MySQL

mysql -h <IP> -u <username> -p

CREATE USER 'newuser'@'localhost' IDENTIFIED BY 'password';
CREATE DATABASE <database>;
GRANT ALL PRIVILEGES ON <database>.* TO 'newuser'@'localhost';
FLUSH PRIVILEGES;

SHOW DATABASES;
USE <database>;
SHOW TABLES;
SHOW FIELDS FROM <table>;

DELETE FROM <table> WHERE <field>="value";

DROP DATABASE <database>;
DROP TABLE 'table1', 'table2', 'table3';

SELECT * FROM <table>;
SELECT * FROM <table> WHERE <field>="value";
SELECT LOAD_FILE('/etc/passwd')\g;

SET PASSWORD FOR username@localhost = PASSWORD('newpassword');

UPDATE <table> SET <field>="value";

DISTINCT <field>
GROUP BY <field>
LIMIT <number>
OFFSET <number>
ORDER BY <field>
WHERE <field> IS NOT NULL
WHERE <field> LIKE

Examples:
SELECT * FROM hostvulns WHERE vulnerability LIKE "%Default%" ORDER BY vulnerability;
SELECT LENGTH(vulnerability), COUNT(*) FROM hostvulns GROUP BY LENGTH(vulnerability);
SELECT DISTINCT last_name,first_name FROM contacts WHERE first_name IS NOT NULL ORDER BY last_name;
SELECT DISTINCT email FROM contacts WHERE email LIKE "%@target.com" ORDER BY email
DELETE from profiles WHERE rowid='53';
UPDATE hostvulns SET tool="Nessus";
------------------------------------------------------------------------------------------------------

# Postgresql

psql -h <IP> -U <username> -d <database> 
-W <password>
select username, passwd from pg_shadow;
select current_database();
create table test (input TEXT); copy test from '/etc/passwd'; select input from test;
