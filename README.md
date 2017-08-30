Follow on Twitter [![Twitter Follow](https://img.shields.io/twitter/follow/discoverscripts.svg?style=social&label=Follow)](https://twitter.com/discoverscripts) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/leebaird/discover/blob/master/LICENSE)

### About
* This project is currently in the alpha stage of development.
* A central place for PMs to store information on clients, contacts, employees, and projects.

### Setup
* XAMPP (PHP 5.6.31): https://www.apachefriends.org/download.html
* Use /Applications/XAMPP/manager-osx to start MySQL and Apache.
* Open a browser to localhost/phpmyadmin.
* Create a MySQL database called assessment_manager.
* The default creds are root/blank. Modify includes/common.php as necessary.
* Import assessment_manager.sql.
* Delete everything inside of /Applications/XAMPP/htdocs/.
* Copy over index.php, includes, and public.
* Open a browser to localhost, register for a new account, then login.

### Pages
```
* Clients
* Contacts
* Employees
* Findings: create finding categories with boiler plate text for your deliverables.
* Projects: track important dates and various aspects of an engagement.
* Vulnerabilities:
    Host: import Nessus and Nexpose findings.
    Web: import Burp and Acunetix findings.
```
