<?php

class Inicio_model extends CI_Model {


    function __construct()
    {
                parent::__construct();
        
    }


function get_productos_mas_solicitados_model()  {   

   $ff_sistema_time_last = time() - 432000;
   $time = time();

   $ff_sistema_time_date_last = date('Y-m-d', $ff_sistema_time_last);
   $date_actual = date('Y-m-d');



    $sql  = "SELECT sum(a.ca_producto) as ca_producto, a.nb_producto FROM j072t_guia_movilizacion as a WHERE a.in_activo = true and a.ff_sistema BETWEEN '$ff_sistema_time_date_last' AND '$date_actual' GROUP by 2 ORDER by 1 DESC limit 5";

    $query = $this->db->query($sql);
    return $query;
 }

function get_last_dolar_model()  {       

    $sql  = "SELECT ca_tasa_cambio, ff_sistema FROM x00t_moneda_paralela
             WHERE in_activo = true
            ORDER BY ff_sistema desc
            limit 1";
    $query = $this->db->query($sql);
    return $query;
 }

 function get_info_empresa_documentacion()  {     

 $co_partner = $this->ion_auth->co_partner();  

    $sql  = "SELECT a.* FROM j080t_documentos_partner as a
             WHERE a.in_activo = true and a.co_partner = '$co_partner' and a.nb_estatus = 'aprobado'
            ORDER BY a.id desc";
    $query = $this->db->query($sql);
    return $query;
 }

 function get_info_actividad_plataforma()  {    

 $ff_sistema_time = time();
 $co_usuario = $this->ion_auth->user_id();

    $sql  = "SELECT
(SELECT COUNT(a.id) FROM e002t_producto_publicaciones as a WHERE a.co_usuario = '$co_usuario' and a.ff_vence_publicacion > '$ff_sistema_time' and a.nb_estatus = 'Publicado' AND a.in_activo = true) as ca_publicaciones,
(SELECT COUNT(a.id) FROM j076t_orden_compra as a WHERE a.co_usuario_vendedor = '$co_usuario' and a.nb_estatus = 'Confirmado por el comprador' AND a.in_activo = true) as ca_venta";
    $query = $this->db->query($sql);
    return $query->row();
 }

             function get_info_nuevos_producto()
    {




      $ff_sistema_time = time();
      $co_partner = $this->ion_auth->co_partner();
      $tipo_empresa = $this->ion_auth->tipo_empresa();
      $mi_estado = $this->ion_auth->ubicacion_estado();

      // ubicacion que puede buscar el comprador

     // $info_estado_buscar = $this->get_estados_ubicacion();


    $this->db->trans_start(); 

    $sql = "SELECT a.*, b.nb_moneda, b.nb_acronimo, c.nb_empresa, c.nb_tipo_empresa, c.nb_estado, a.in_activo, a.ff_vence_publicacion, d.username
        FROM
        e002t_producto_publicaciones AS a
        left join i00t_monedas as b on b.id = a.co_moneda
        join j049t_empresas_farmaceuticas_todas as c on c.id = a.co_partner
        join lu_users as d on d.id = a.co_usuario
        where a.in_activo = true and a.nb_estatus = 'Publicado'
        and (case WHEN a.co_partner != '$co_partner' then a.nb_dirigido_ubicacion REGEXP '$mi_estado' end)
        and (case WHEN a.co_partner != '$co_partner' then a.nb_dirigido REGEXP '$tipo_empresa' end)
        HAVING id > 0 and in_activo = true and ff_vence_publicacion > '$ff_sistema_time' order by a.id desc
        limit 30";

    $query = $this->db->query($sql);

    $this->db->trans_complete();
    return $query;  

        
    }

              function get_list_categoria()
    {




      $ff_sistema_time = time();
      $co_partner = $this->ion_auth->co_partner();
      $tipo_empresa = $this->ion_auth->tipo_empresa();
      $mi_estado = $this->ion_auth->ubicacion_estado();

      // ubicacion que puede buscar el comprador

     // $info_estado_buscar = $this->get_estados_ubicacion();


    $this->db->trans_start(); 

    $sql = "SELECT a.nb_categoria
        FROM
        e002t_producto_publicaciones AS a
        left join i00t_monedas as b on b.id = a.co_moneda
        join j049t_empresas_farmaceuticas_todas as c on c.id = a.co_partner
        join lu_users as d on d.id = a.co_usuario
        where a.in_activo = true and a.nb_estatus = 'Publicado'
        and (case WHEN a.co_partner != '$co_partner' then a.nb_dirigido_ubicacion REGEXP '$mi_estado' end)
        and (case WHEN a.co_partner != '$co_partner' then a.nb_dirigido REGEXP '$tipo_empresa' end) and (a.in_activo = true and a.ff_vence_publicacion > '$ff_sistema_time') group by a.nb_categoria
        limit 10";

    $query = $this->db->query($sql);

    $this->db->trans_complete();
    return $query;  

        
    }



              function get_list_empresas_certificadas()
    {




      $ff_sistema_time = time();
      $co_partner = $this->ion_auth->co_partner();
      $tipo_empresa = $this->ion_auth->tipo_empresa();
      $mi_estado = $this->ion_auth->ubicacion_estado();

      // ubicacion que puede buscar el comprador

     // $info_estado_buscar = $this->get_estados_ubicacion();


    $this->db->trans_start(); 

    $sql = "SELECT d.username, a.co_usuario, a.co_partner, c.nb_empresa, c.nb_estado
        FROM
        e002t_producto_publicaciones AS a
        left join i00t_monedas as b on b.id = a.co_moneda
        join j049t_empresas_farmaceuticas_todas as c on c.id = a.co_partner
        join lu_users as d on d.id = a.co_usuario
        where a.in_activo = true and a.nb_estatus = 'Publicado'
        and (case WHEN a.co_partner != '$co_partner' then a.nb_dirigido_ubicacion REGEXP '$mi_estado' end)
        and (case WHEN a.co_partner != '$co_partner' then a.nb_dirigido REGEXP '$tipo_empresa' end) and (a.in_activo = true and a.ff_vence_publicacion > '$ff_sistema_time') group by d.username, a.co_usuario, a.co_partner, c.nb_empresa, c.nb_estado
        limit 10";

    $query = $this->db->query($sql);

    $this->db->trans_complete();
    return $query;  

        
    }

    

     function token_notificacion_model($token) {
        $this->db->trans_start();

        $co_usuario = $this->ion_auth->user_id();
        
        $data_listado['token_firebase']       = $token;
        $this->db->where("id", $co_usuario);
        $this->db->update("lu_users", $data_listado);
        $this->db->trans_complete();
        return true;
    }




}
?>