<?php
defined('BASEPATH') or exit('No direct script access allowed');
class Register_user extends CI_Controller
{
  function __construct()
  {
    parent::__construct();
    $this->load->library(array(
      'ion_auth',
      'form_validation'
    ));
    $this->load->model('register_user_model');
  }

  function register()
  {

    $this->load->view('register_user/register_view');

  }

  public function add_user()
  {

    header("Content-Type:application/json");
    $strErrorDesc = '';
    $requestMethod = $_SERVER["REQUEST_METHOD"];

    if ($requestMethod == 'POST'):

      $error = 0;
      $message = '';

      $datos = file_get_contents('php://input');
      $datos = json_decode($datos);

      $first_name = $datos->first_name;
      $last_name = $datos->last_name;
      $nu_celular = $datos->nu_celular;
      $nu_documento = $datos->nu_documento;
      $email = $datos->email;
      $password = $datos->password;

      // Validar Email
      $resp_existente = $this->register_user_model->get_email_existente_model($email);
      if ($resp_existente->num_rows() > 0)
      {
        $message .= 'El email: ' . $email . ' ya esta registrado en sistema';
        $error++;
      }

      // Validacion 1
      if ($error == 0)
      {

        $bool = $this->register_user_model->newUserModel($nu_documento, $email, $first_name, $last_name, $nu_celular, $password);
        $message .= 'Agregado';

      }
      $arreglo = array(
        'error' => $error,
        'message' => $message
      );
      echo json_encode($arreglo);

    endif;

  }
  // Editar Usuario
  

  
}
?>
