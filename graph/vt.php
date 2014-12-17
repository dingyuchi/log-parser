<?php
if (!function_exists('stats_standard_deviation')) {
    /**
     * This user-land implementation follows the implementation quite strictly;
     * it does not attempt to improve the code or algorithm in any way. It will
     * raise a warning if you have fewer than 2 values in your array, just like
     * the extension does (although as an E_USER_WARNING, not E_WARNING).
     * 
     * @param array $a 
     * @param bool $sample [optional] Defaults to false
     * @return float|bool The standard deviation or false on error.
     */
    function stats_standard_deviation(array $a, $sample = false) {
        $n = count($a);
        if ($n === 0) {
            return false;
        }
        if ($sample && $n === 1) {
            return false;
        }
        $mean = array_sum($a) / $n;
        $carry = 0.0;
        foreach ($a as $val) {
            $d = ((double) $val) - $mean;
            $carry += $d * $d;
        };
        if ($sample) {
           --$n;
        }
        return sqrt($carry / $n);
    }
}


$ip_list = array();
$sha256 = array();
$dcs_relation = array();    # detected communicating samples
$udcs_relation = array();   # undetected communicating samples
$dds_relation = array();    # detected downloaded samples
$udds_relation = array();   # undetected downloaded samples

#IP Node
$file = fopen("output/ip_tmp.csv","r");
while(!feof($file))  {
    $row = fgetcsv($file);
    $ip_list[$row[0]] = 0;
}
fclose($file);

$file = fopen("virustotal.csv","r");
while(!feof($file))  {
    $row = fgetcsv($file);
    $id = $row[0];
    $ip = $row[1];
    $date = $row[3];
    
    $dcs_avg = 0;    # average
    $dcs_std = 0;    # standard deviation
    $dds_avg = 0;    # average
    $dds_std = 0;    # standard deviation            
    
    $json = json_decode($row[2]);
    $asn = isset($json->asn) ? $json->asn : null;       
    $dcs = isset($json->detected_communicating_samples) ? $json->detected_communicating_samples : null;
    $udcs = isset($json->undetected_communicating_samples) ? $json->undetected_communicating_samples : null;
    $dds = isset($json->detected_downloaded_samples) ? $json->detected_downloaded_samples : null;
    $udds = isset($json->undetected_downloaded_samples) ? $json->undetected_downloaded_samples : null;

    #count
    $dcs_count = count($dcs);
    $udcs_count = count($udcs);
    $dds_count = count($dds);
    $udds_count = count($udds);
    
    # detected communicating samples
    if($dcs !== null) {
        $count = 0;       
        $positive = 0;
        $positive_summary = 0;
        $std = array();
        
        foreach($dcs as $row) {
            $positive = $row->positives / $row->total;
            $std[] = $positive;
            $positive_summary = $positive_summary + $positive;
            $count++;
            
            if(!isset($sha256[$row->sha256])) {
                $sha256[$row->sha256] = $positive;          
            }
            
            if(!isset($dcs_relation["{$row->sha256}, {$ip}"])) {
                $dcs_relation["{$row->sha256},{$ip}"] = "{$row->sha256},{$ip}";
            }    
        }

        if($count != 0) {
            $dcs_avg = $positive_summary / $count;
        }
        
        $dcs_std = stats_standard_deviation($std);        
    }
    
    # detected downloaded samples
    if($dds !== null) {
        $count = 0;       
        $positive = 0;
        $positive_summary = 0;
        $std = array();
    
        foreach($dds as $row) {
            $positive = $row->positives / $row->total;
            $std[] = $positive;
            $positive_summary = $positive_summary + $positive;
            $count++;        
        
            if(!isset($sha256[$row->sha256])) {
                $sha256[$row->sha256] = $positive;        
            }
            
            if(!isset($dds_relation["{$row->sha256}, {$ip}"])) {
                $dds_relation["{$ip},{$row->sha256}"] = "{$ip},{$row->sha256}";
            }          
        }
        
        if($count != 0) {
            $dds_avg = $positive_summary / $count;
        }
        
        $dds_std = stats_standard_deviation($std);         
    }        
    
    # undetected communicating samples
    if($udcs !== null) {
        foreach($udcs as $row) {
            if(!isset($sha256[$row->sha256])) {
                $sha256[$row->sha256] = 0;
            }
            
            if(!isset($udcs_relation["{$row->sha256}, {$ip}"])) {
                $udcs_relation["{$row->sha256},{$ip}"] = "{$row->sha256},{$ip}";
            }                      
        }
    }
    
    # undetected downloaded samples
    if($udds !== null) {
        foreach($udds as $row) {
            if(!isset($sha256[$row->sha256])) {
                $sha256[$row->sha256] = 0;
            }
            
            if(!isset($udds_relation["{$row->sha256}, {$ip}"])) {
                $udds_relation["{$ip},{$row->sha256}"] = "{$ip},{$row->sha256}";
            }                      
        }
    }      
    
    #ip info
    if(isset($ip_list[$ip])) {
        $ip_list[$ip] = "{$asn},{$dcs_avg},{$dcs_std},{$dds_avg},{$dds_std},{$dcs_count},{$udcs_count},{$dds_count},{$udds_count}";
    }
}

fclose($file);

# ip node
$file = fopen("output/ip.csv","w");
foreach($ip_list as $row => $key) {
    $str = "{$row},{$key}". PHP_EOL;
    fwrite($file, $str);
}
fclose($file);

# file node
$file = fopen("output/sha256.csv","w");
foreach($sha256 as $row => $key) {
    $str = "{$row}, {$key}". PHP_EOL;
    fwrite($file, $str);
}
fclose($file);

echo count($sha256). PHP_EOL;

# file to ip
$file = fopen("output/dcs_relation.csv","w");
foreach($dcs_relation as $row) {
    $str = "{$row}". PHP_EOL;
    fwrite($file, $str);
}
fclose($file);
echo "dcs:" . count($dcs_relation). PHP_EOL;

# file to ip
$file = fopen("output/udcs_relation.csv","w");
foreach($udcs_relation as $row) {
    $str = "{$row}". PHP_EOL;
    fwrite($file, $str);
}
fclose($file);
echo "udcs:" . count($udcs_relation). PHP_EOL;

# file to ip
$file = fopen("output/dds_relation.csv","w");
foreach($dds_relation as $row) {
    $str = "{$row}". PHP_EOL;
    fwrite($file, $str);
}
fclose($file);
echo "dds:" . count($dds_relation). PHP_EOL;

# file to ip
$file = fopen("output/udds_relation.csv","w");
foreach($udds_relation as $row) {
    $str = "{$row}". PHP_EOL;
    fwrite($file, $str);
}
fclose($file);
echo "udds:" . count($udds_relation). PHP_EOL;

?>