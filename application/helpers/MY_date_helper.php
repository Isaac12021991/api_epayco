<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');

// ------------------------------------------------------------------------

/**
 * Extensión del CodeIgniter Date Helpers
 *
 * @package	CodeIgniter
 * @subpackage	Helpers
 * @category	Helpers
 * @author		Juan Romero
 */

// ------------------------------------------------------------------------

if ( ! function_exists('mysql_date_to_input'))
{
	function mysql_date_to_input($time = '')
	{
        // If the date is blank, return ''
        if (empty($time)) {
            return '';
        }
        
		// We'll remove certain characters for backward compatibility
		// since the formatting changed with MySQL 4.1
		// YYYY-MM-DD HH:MM:SS

		$time = str_replace('-', '', $time);
		$time = str_replace(':', '', $time);
		$time = str_replace(' ', '', $time);
                $salida_mysql = substr($time, 0, 4).'-'.substr($time, 4, 2).'-'.substr($time, 6, 2);
                $salida = substr($time, 6, 2).'-'.substr($time, 4, 2).'-'.substr($time, 0, 4);
                if ($salida_mysql == NULL) $salida = ''; // Esto se utiliza para mostrar en blanco una fecha nula
		return $salida;
	}
}

if ( ! function_exists('minutos_to_hora_textual'))
{
    function minutos_to_hora_textual($minutos) {
        $ampm = "am";
        $horas = intval($minutos/60);
        $minutos = $minutos - ($horas*60);
        if ($horas>11) $ampm = "pm";
        if ($horas>12) $horas -= 12;
        $horas = str_pad($horas,2,"0",STR_PAD_LEFT);
        $minutos = str_pad($minutos,2,"0",STR_PAD_LEFT);
        return "$horas:$minutos $ampm";
    }
}

if ( ! function_exists('input_to_mysql_date'))
{
	function input_to_mysql_date($date = '')
	{
        // If the date is blank, return NULL
        if (empty($date)) {
            return NULL;
        }
        
	
                $time = strtotime($date);
                
		return  mdate("%Y-%m-%d",$time);
	}
}

if ( ! function_exists('fecha_minuto'))
{
    
	function fecha_minuto($date = '')
	{
        // If the date is blank, return NULL
        if (empty($date)) {
            return NULL;
        }
        
	
                $time = strtotime($date);
                
		return  mdate("%d-%m-%Y  %h:%i %a",$time);
	}
}


if ( ! function_exists('fecha_hora'))
{
    
	function fecha_hora($date = '')
	{
        // If the date is blank, return NULL
        if (empty($date)) {
            return NULL;
        }
        
	
                $time = strtotime($date);
                //return  mdate("%Y-%m-%d",$time);
		return  mdate("%y-%m-%d  %H:%i:%s",$time);
	}
}


/* End of file date_helper.php */
/* Location: ./applicacion/helpers/date_helper.php */
