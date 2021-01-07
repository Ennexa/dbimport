### Import mysql table from remote server

A database importer written in Rust for importing specified tables from a remote MySQL/MariaDB server to the local MySQL/MariaDB server over ssh.

### Usage

```
dbimport ssh_user@ssh_host.com -d db_name -u db_user -p db_pass table1 table2
```


### Configuration

The server details can be loaded from a config file.

```
server:
  db_name: example_db
  db_user: example_user
  db_pass: secret
  ssh_user: joseph
  ssh_host: example.com
anotherserver:
  db_name: example_db
  db_user: example_user
  db_pass: secret
  ssh_user: mary
  ssh_host: example.net
```

With the above configuration, the usage can be simplied to

```
dbimport server table1 table2 table2
dbimport anotherserver tablex tabley tablez
```
