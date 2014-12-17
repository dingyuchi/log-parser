<?php
/*
convert DNS log to neo4j import csv file
*/

$file = fopen("dns.csv","r") or die("Can't open file");

$ip_node = array();
$domain_node = array();
$relationship = array();

$i=0;
while(!feof($file))  {
    
    $data = fgetcsv($file);
    $date = date("Y-m-d", $data[1]);
    $server = $data[2];
    $domain = $data[6];
    $ip = $data[7];
    
    if(!isset($ip_node[$ip])) {
        $ip_node[$ip] = $ip;
    }
    
    if(!isset($domain_node[$domain])) {
        $domain_node[$domain] = $date;
    }    
    
    if(!isset($relationship["$domain,$ip"])) {
        $relationship["$domain,$ip"] = "$domain,$ip";
    }
    
    $i++;
    
    if($i % 1000000 == 0) {
        print $i.PHP_EOL;
    }
}

fclose($file);

# ip node
$file = fopen("output/ip_tmp.csv","w");
foreach($ip_node as $row) {
    $str = "{$row}". PHP_EOL;
    fwrite($file, $str);
}
fclose($file);

# domain node
$file = fopen("output/domain.csv","w");
foreach($domain_node as $row => $key) {
    $str = "{$row}, {$key}". PHP_EOL;
    fwrite($file, $str);
}
fclose($file);

#relationship
$file = fopen("output/relationship.csv","w");
foreach($relationship as $row) {
    $str = "{$row}". PHP_EOL;;
    fwrite($file, $str);
}
fclose($file);

?>