<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');

// ------------------------------------------------------------------------
function time_stamp($date)
{
    if(empty($date)) {
        return "No date provided";
    }
    
    $periods         = array("segundo", "minuto", "hora", "dia", "semana", "mes", "año", "decada");
    $lengths         = array("60","60","24","7","4.35","12","10");
    
    $now             = time();
    $unix_date         = strtotime($date);
    
       // check validity of date
    if(empty($unix_date)) {    
        return "Bad date";
    }

    // is it future date or past date
    if($now > $unix_date) {    
        $difference     = $now - $unix_date;
        $tense         = "";
        
    } else {
        $difference     = $unix_date - $now;
        $tense         = "faltan";
    }
    
    for($j = 0; $difference >= $lengths[$j] && $j < count($lengths)-1; $j++) {
        $difference /= $lengths[$j];
    }
    
    $difference = round($difference);
    
    if($difference != 1) {
        $periods[$j].= "s";
    }
    
    return "$difference $periods[$j] {$tense}";
}

function date_system($date)

{
    $newDate = date("Y-m-d", strtotime($date));
    return $newDate;
}

function date_user($date)

{
    $newDate = date("d-m-Y", strtotime($date));
    return $newDate;
}

function conversor_segundos($seg_ini) {

$horas = floor($seg_ini/3600);
$minutos = floor(($seg_ini-($horas*3600))/60);
$segundos = $seg_ini-($horas*3600)-($minutos*60);
return $horas.'h:'.$minutos.'m:'.$segundos.'s'; 
}