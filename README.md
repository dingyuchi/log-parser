log-parser
==========
graph/ => import csv log to neo4j database

### Export DNS log:

```sh
SELECT *
FROM dns_query_log
INTO OUTFILE '/tmp/dns_query_log.csv'
FIELDS TERMINATED BY ',' 
ENCLOSED BY '"'
ESCAPED BY '"'
LINES TERMINATED BY '\n';
```

### Export Intelligence:

```sh
SELECT *
FROM virustotal_db
INTO OUTFILE '/tmp/virustotal_db.csv'
FIELDS TERMINATED BY ',' 
ENCLOSED BY '"'
ESCAPED BY '"'
LINES TERMINATED BY '\n';
```
