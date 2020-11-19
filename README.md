# jira_user_enum auxiliary scanner Metasploit Module
metasploit module to perform user enumeration against Jira servers, only tested on Jira 8.4.1

# How to import:
```sh
copy file to /modules/auxiliary/scanner/http
run 'sudo updatedb'
exit and reopen metasploit
```


 

# How to use:
```use auxiliary/scanner/http/jira_user_enum

set RHOSTS to the jira server
set SSL true
set RPORT 443
set USERNAME admin
run

```


