<?php
/*
convert DNS log to neo4j import csv file
*/

function degree($domain) {
    $level = 5;
    $a = explode(".", $domain);   
    $count = count($a);
    $tmp = '';
    
    $res = array();
    
    for($i = $count-1; $i >= 0; $i--) {
    
        $tmp = ($tmp == '') ? $a[$i] : $a[$i] . "." .$tmp;
        $res[] = $tmp;
        
        if(($count - $i) == $level) {
            break;
        }
    }   

    return $res;
}



$file = fopen("dns_query_log.csv","r") or die("Can't open file");

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
        $tmp = degree($domain);
        
        $lv1 = isset($tmp[0]) ? $tmp[0] : null;
        $lv2 = isset($tmp[1]) ? $tmp[1] : null;
        $lv3 = isset($tmp[2]) ? $tmp[2] : null;
        $lv4 = isset($tmp[3]) ? $tmp[3] : null;
        $lv5 = isset($tmp[4]) ? $tmp[4] : null;
        
        $domain_node[$domain] = "{$date},{$lv1},{$lv2},{$lv3},{$lv4},{$lv5},";
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