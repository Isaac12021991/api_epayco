<?php
defined('BASEPATH') OR exit('No direct script access allowed');
class Inicio extends CI_Controller {
    function __construct() {
        parent::__construct();
        $this->load->model('inicio_model');
         $this->load->library('excel');
         $this->load->library('encrypt');
         $this->load->library('authjwt');

    }
    function getRemoteFile($url, $timeout = 3) {
        $ch = curl_init();
        curl_setopt ($ch, CURLOPT_URL, $url);
        curl_setopt ($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt ($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
        $file_contents = curl_exec($ch);
        curl_close($ch);
        return ($file_contents) ? $file_contents : FALSE;
}


    public function index() {
        
       if (!$this->ion_auth->logged_in()) {
            redirect('auth/login');
            return;
        }


        // redirect('biomercado/cartelera');

            $data['dolar_paralelo'] = $this->inicio_model->get_last_dolar_model();
            $data['info_empresa_documentacion'] = $this->inicio_model->get_info_empresa_documentacion();
            $data['info_actividad_plataforma'] = $this->inicio_model->get_info_actividad_plataforma();
            $data['class_body'] = 'page-full-width';

            $data["info_nuevos_producto"] = $this->inicio_model->get_info_nuevos_producto();
            $data["list_categoria"] = $this->inicio_model->get_list_categoria();
            $data["list_empresas_certificadas"] = $this->inicio_model->get_list_empresas_certificadas();

            $data["productos_mas_solicitados"] = $this->inicio_model->get_productos_mas_solicitados_model();

            $this->load->view('layout/header_view', $data);
            //$this->load->view('inicio/left_sidebar_inicio_view');
            $this->load->view('inicio/inicio_view');
            $this->load->view('layout/footer_view');



    }


    function info_php()

    {
        print_r(phpinfo());
    }


function import_excel()

{

            $this->load->view('layout/header_view');
            $this->load->view('inicio/excel_view');     
            $this->load->view('layout/footer_view');

}

function cargar_excel()

{

//Ruta donde se guardan los ficheros
        $archivo = $_FILES['file'];
        $temp = $archivo["tmp_name"];
        $name = $archivo["name"];
        $conca = 'archivo_' . $name;
        move_uploaded_file($temp, "archivos/importar/$conca");


        $inputFileName = "archivos/importar/$conca";

//  Read your Excel workbook
try {
    $inputFileType = PHPExcel_IOFactory::identify($inputFileName);
    $objReader = PHPExcel_IOFactory::createReader($inputFileType);
    $objPHPExcel = $objReader->load($inputFileName);
} catch(Exception $e) {
    die('Error loading file "'.pathinfo($inputFileName,PATHINFO_BASENAME).'": '.$e->getMessage());
}

$sheetData = $objPHPExcel->getActiveSheet()->toArray(null,true,true,true);

$this->db->trans_start();

foreach ($sheetData as $key) {

        $data_listado['nb_plan_contable']     = trim($key['L']);
        $data_listado['code']    = trim($key['C']);
        $data_listado['co_usuario'] = 1;
        $data_listado['in_reconcile']     = trim($key['E']);
        $data_listado['in_deprecated']     = trim($key['F']);
        $data_listado['internal_type']     = trim($key['J']);
        $data_listado['co_tipo_plan_contable']     = trim($key['K']);
        $this->db->insert("j045t_plan_contable", $data_listado);
}

    $this->db->trans_complete();

echo "Bien";
die();



    
    

}


function json()

{   

    $url = base_url().'ajax_json.php';
    $json = $this->getRemoteFile($url);


    $file = json_decode($json);
    $file = json_decode($file);

           print_r($file);
    die();

}

function sicm_guia($co_documento)

{   

        $this->load->model('facturacion_cliente_model', 'facturacion_cliente');

        $error                   = 0;
        $message                 = '';


        $this->facturacion_cliente->generar_guia_scim_model($co_documento, '1', 0);


        $this->load->library(array('authjwt', 'ciqrcode'));
        $params['data'] = base_url().'inicio/sicm_guia/'.$co_documento;
        $params['level'] = 'S';

        $config['cacheable']    = false; //boolean, the default is true
        $config['cachedir']     = ''; //string, the default is application/cache/
        $config['errorlog']     = ''; //string, the default is application/logs/
        $config['quality']      = true; //boolean, the default is true
        $config['black']        = array(224,255,255); // array, default is array(255,255,255)
        $config['white']        = array(70,130,180); // array, default is array(0,0,0)
        $this->ciqrcode->initialize($config);

        //decimos el directorio a guardar el codigo qr, en este 
        //caso una carpeta en la raíz llamada qr_code
        $params['savename'] = FCPATH . "qr_code/qr_".$co_documento.".png";
        //generamos el código qr
        $this->ciqrcode->generate($params);

        $info_documento_general = $this->facturacion_cliente->get_row_documento_model($co_documento);
        $data['info_documento_general']    = $info_documento_general;
        $data['info_documento_cliente']    = $this->facturacion_cliente->get_info_cliente_documento_model($co_documento);
        $data['info_documento_detalle']    = $this->facturacion_cliente->get_info_documento_detalle_model($co_documento);

        $data['img'] = "qr_".$co_documento.".png";
        $this->load->view('inicio/generar_sicm', $data);    


}

function sincronizar_dolar_bolivar()

{


 /*$url = "https://s3.amazonaws.com/dolartoday/data.json";

    $jsonfile = $this->getRemoteFile($url);

    if($jsonfile):



    $jsonencode = utf8_encode($jsonfile);
    $arrayjson = json_decode($jsonencode, true); 
    
        foreach ($arrayjson as $key => $value1) {


           if ($key == 'USD'):

              foreach ($value1 as $key2 => $value2) {

              if($key2 == 'promedio_real'):


        $sql   = "SELECT a.ca_tasa_cambio, a.co_moneda
        FROM
        x00t_moneda_paralela AS a
        left join i00t_monedas as b on b.id = a.co_moneda_tasa_cambio
        where a.in_activo = true and a.ca_tasa_cambio = '$value2' and a.co_moneda = '2' and a.co_moneda_tasa_cambio = '1' limit 1";
        $query = $this->db->query($sql);

        if ($query->num_rows() == 0) {

        $this->db->trans_start();
        $data_listado['co_moneda'] = '2';
        $data_listado['co_moneda_tasa_cambio'] = '1';
        $data_listado['ca_tasa_cambio'] = $value2;
        $this->db->insert("x00t_moneda_paralela", $data_listado);
        $this->db->trans_complete();




        }


           endif;
            }
   

            endif;


    }


    */

    $url = "http://www.bcv.org.ve/tasas-informativas-sistema-bancario";
    $file = $this->getRemoteFile($url);

    if($file):

    $test = strip_tags($file);
    $posicion_coincidencia = strpos($test, 'Bs/USD'); $posicion_coincidencia += 6;
    $resultado = substr($test, $posicion_coincidencia, 80);
    $resp = str_replace(".", "", $resultado); $resp = str_replace(",", ".", $resp);
    $resp = trim($resp); $myfloat = (float) $resp;

     $sql   = "SELECT a.ca_tasa_cambio, a.co_moneda
        FROM
        x00t_moneda_paralela AS a
        left join i00t_monedas as b on b.id = a.co_moneda_tasa_cambio
        where a.in_activo = true and a.ca_tasa_cambio = '$myfloat' and a.co_moneda = '2' and a.co_moneda_tasa_cambio = '1' limit 1";
        $query = $this->db->query($sql);

        if ($query->num_rows() == 0) {

        $this->db->trans_start();
        $data_listado['co_moneda'] = '2';
        $data_listado['co_moneda_tasa_cambio'] = '1';
        $data_listado['ca_tasa_cambio'] = $myfloat;
        $this->db->insert("x00t_moneda_paralela", $data_listado);
        $this->db->trans_complete();




        }




endif;

}


 function encriptar()
{

    $msg = 'My secret message';

$msg = 'My secret message';
$key = 'bio';

echo $encrypted_string = $this->encrypt->encode($msg);


    // code...
}


 function prueba_fierbase()
{




        $this->sendGCM('Hola','Descripcion', 'imagen');


    


    // code...
}



public function sendGCM($title,$description,$urlToImage) {


$severKey="AAAAukvrZV4:APA91bHc49gsdUOPfWSV3rRDQayru2OQp6t2pI9Mm_2_ccls7lmsMfXFh-6HN2ZZi2gvsBkGnN-5qQMgMDbJJUlm6i5qYSctzcOglCL0ZJ__3KWMVQ3lu5puE3ICcd7AOXujmnNy8nZB";
$url="https://fcm.googleapis.com/fcm/send";

$tokenId='dWVgYfV7B-QrqTqj19rOFM:APA91bExRMh1idNXnjfoDVVXiVf9u1-jWM9xdrvVvupNO7u9v2weiGnoj4llSZyDSYZZTG86-M_IcGSDs3LHY6I3HnmrNrvbalHQ1DBRKsLYl2ZvUGFySaTZawxGY2mi9LvAVg9D2d_Y';


$field=array(
    'data'=>array(
        'notification'=>array(
            'title'=>$title,
            'body'=>$description,
            'icon'=>$urlToImage
        )
        ),
    'to'=>$tokenId    
);
$fields=json_encode($field);

$header=array(
    'Authorization: key='.$severKey,
    'Content-Type: application/json'
);
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL,$url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $fields);

$result=curl_exec($ch);
echo $result;
curl_close($ch);



/*




            define('API_ACCESS_KEY','AAAAukvrZV4:APA91bHc49gsdUOPfWSV3rRDQayru2OQp6t2pI9Mm_2_ccls7lmsMfXFh-6HN2ZZi2gvsBkGnN-5qQMgMDbJJUlm6i5qYSctzcOglCL0ZJ__3KWMVQ3lu5puE3ICcd7AOXujmnNy8nZB   
');
            $fcmUrl = 'https://fcm.googleapis.com/fcm/send';

                $notification = [
                    'title'  => ''.$title.'',
                    'body'   => ''.$description.'',
                    'image'  => ''.$urlToImage.''
                ];
                $extraNotificationData = ["message" => $notification,"moredata" =>'dd'];

                $fcmNotification = [
                    'to'            => 'dWVgYfV7B-QrqTqj19rOFM:APA91bExRMh1idNXnjfoDVVXiVf9u1-jWM9xdrvVvupNO7u9v2weiGnoj4llSZyDSYZZTG86-M_IcGSDs3LHY6I3HnmrNrvbalHQ1DBRKsLYl2ZvUGFySaTZawxGY2mi9LvAVg9D2d_Y',
                    'notification'  => $notification,
                    'data'          => $extraNotificationData
                ];

                $headers = [
                    'Authorization: key=' . API_ACCESS_KEY,
                    'Content-Type: application/json'
                ];


                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL,$fcmUrl);
                curl_setopt($ch, CURLOPT_POST, true);
                curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($fcmNotification));
                $result = curl_exec($ch);
                curl_close($ch);

                echo $result;
                echo 'Bien';
                */
        }



    public function token_notificacion() {
        
            $token     = trim($this->input->post('token'));
            $this->inicio_model->token_notificacion_model($token);

    }

public function crear_imagen()
{

    $font_size = 50;
    $wm_vrt_offset = 150;

        $texto = "Hay muchas variaciones de los pasajes de Lorem Ipsum disponibles, pero la mayoría sufrió alteraciones en alguna manera, ya sea porque se le agregó humor, o palabras aleatorias que no parecen ni un poco creíbles. Si vas a utilizar un pasaje de Lorem Ipsum, necesitás estar seguro de que no hay nada avergonzante escondido en el medio del texto. Todos los generadores de Lorem Ipsum que se .";
    $longito_texto = strlen($texto);

    if ($longito_texto < 40):

        $wm_vrt_offset = 250;
        $font_size = 50;
        $texto = wordwrap($texto, 15, "\n");

    endif;

    if ($longito_texto >= 40 and $longito_texto <= 100):

        $font_size = 40;
         $wm_vrt_offset = 200;
        $texto = wordwrap($texto, 16, "\n");

    endif;


        if ($longito_texto >= 100 and $longito_texto <= 200):

        $font_size = 28;
        $texto = wordwrap($texto, 22, "\n");

    endif;

                if ($longito_texto >= 200 and $longito_texto <= 300):

        $font_size = 22;
        $wm_vrt_offset = 120;
        $texto = wordwrap($texto, 28, "\n");

    endif;

            if ($longito_texto >= 300 and $longito_texto <= 400):

        $font_size = 20;
        $wm_vrt_offset = 100;
        $texto = wordwrap($texto, 25, "\n", TRUE);

    endif;

    echo $longito_texto;





    $this->load->library('image_lib');
    $config['image_library'] = 'NetPBM';
    $config['source_image'] = 'img/estado_rose/plantillas/verde_rose.png';
    $config['wm_text'] = $texto;
    $config['wm_type'] = 'text';
    $config['wm_font_path'] = realpath('arial-black.ttf');
    $config['wm_font_size'] = $font_size;
    $config['wm_font_color'] = 'ffffff';
   //  $config['wm_shadow_color'] = 'ffffff';

    $config['wm_vrt_alignment'] = 'top';
    $config['wm_hor_alignment'] = 'center';
   // $config['wm_hor_offset'] = '100';

    $config['wm_vrt_offset'] = $wm_vrt_offset;

    

    $config['wm_padding'] = '10';
    $config['quality'] = '100';
    $config['new_image'] = './new_image.jpg';

    $this->image_lib->initialize($config);
    if (!$this->image_lib->watermark()) {
        echo $this->image_lib->display_errors();
    }


}


function prueba_todo()

{

            $this->load->view('layout/header_view');
            $this->load->view('inicio/prueba_todo_view');     
            $this->load->view('layout/footer_view');

}




}
