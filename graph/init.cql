USING PERIODIC COMMIT
LOAD CSV FROM 'file:///root/graph/output/ip.csv' AS line CREATE (:ip {name:line[0], asn:line[1], dcs_avg:toFloat(line[2]), dcs_std:toFloat(line[3]), dds_avg:toFloat(line[4]), dds_std:toFloat(line[5]), dcs_count:toInt(line[6]), udcs_count:toInt(line[7]), dds_count:toInt(line[8]), udds_count:toInt(line[9])});
CREATE INDEX ON :ip(name);
CREATE INDEX ON :ip(asn);
CREATE INDEX ON :ip(dcs_avg);
CREATE INDEX ON :ip(dcs_std);
CREATE INDEX ON :ip(dds_avg);
CREATE INDEX ON :ip(dds_std);
CREATE INDEX ON :ip(dcs_count);
CREATE INDEX ON :ip(udcs_count);
CREATE INDEX ON :ip(dds_count);
CREATE INDEX ON :ip(udds_count);

USING PERIODIC COMMIT 
LOAD CSV FROM 'file:///root/graph/output/domain.csv' AS line CREATE (:domain {name:line[0], date:line[1]});
CREATE INDEX ON :domain(name);
CREATE INDEX ON :domain(date);

USING PERIODIC COMMIT 
LOAD CSV FROM 'file:///root/graph/output/sha256.csv' AS line CREATE (:file {name:line[0], positive:toFloat(line[1]) });
CREATE INDEX ON :file(name);
CREATE INDEX ON :file(positive);

USING PERIODIC COMMIT 
LOAD CSV FROM 'file:///root/graph/output/relationship.csv' AS line
MATCH (n1:domain{name:line[0]}),(n2:ip{name:line[1]})
CREATE (n1)-[:DNS]->(n2);

USING PERIODIC COMMIT
LOAD CSV FROM 'file:///root/graph/output/dcs_relation.csv' AS line
MATCH (n1:file{name:line[0]}),(n2:ip{name:line[1]})
CREATE (n1)-[:CONNECT{type:"detected"}]->(n2);

USING PERIODIC COMMIT
LOAD CSV FROM 'file:///root/graph/output/udcs_relation.csv' AS line
MATCH (n1:file{name:line[0]}),(n2:ip{name:line[1]})
CREATE (n1)-[:CONNECT{type:"undetected"}]->(n2);

USING PERIODIC COMMIT
LOAD CSV FROM 'file:///root/graph/output/dds_relation.csv' AS line
MATCH (n1:ip{name:line[0]}),(n2:file{name:line[1]})
CREATE (n1)-[:DOWNLOAD{type:"detected"}]->(n2);

USING PERIODIC COMMIT
LOAD CSV FROM 'file:///root/graph/output/udds_relation.csv' AS line
MATCH (n1:ip{name:line[0]}),(n2:file{name:line[1]})
CREATE (n1)-[:DOWNLOAD{type:"undetected"}]->(n2);