<?php
defined('BASEPATH') OR exit('No direct script access allowed');
class Home extends CI_Controller {
    function __construct() {
        parent::__construct();
        $this->load->model('Home_model', 'home');

        if (!$this->ion_auth->logged_in()) {
            redirect('auth/login');
            return;
        }

    }
    public function index() {

        $coUsuario = $this->ion_auth->user_id();
        $data['InfoUserWallet'] = $this->home->getInfoUserWalletModel($coUsuario);
        $data['InfowalletLinea'] = $this->home->InfoWalletLineaModel($coUsuario);
        $this->load->view('layout/header_view', $data);
        $this->load->view('home/home_main_view');
        $this->load->view('layout/footer_view');
    }

    public function recharge() {
        $this->load->view('layout/header_view');
        $this->load->view('home/add/recharge_view');
        $this->load->view('layout/footer_view');
    }

    public function pay() {
        $this->load->view('layout/header_view');
        $this->load->view('home/add/pay_view');
        $this->load->view('layout/footer_view');
    }

    public function consult() {
        $this->load->view('layout/header_view');
        $this->load->view('home/form_consult_view');
        $this->load->view('layout/footer_view');
    }


    public function sendToken() {
        $ca_monto = trim($this->input->post('ca_monto'));

        if ($ca_monto <= 0): redirect('home/index'); endif;

        $coUsuario = $this->ion_auth->user_id();
        $infoUser = $this->ion_auth->infoUserAll($coUsuario);

        $token = openssl_random_pseudo_bytes(3);
        $token = bin2hex($token);

        $this->home->generateTokenModel($coUsuario, $token);
        
        $data['ca_monto'] = $ca_monto;

        $this->email->to($infoUser->email);
        $this->email->reply_to('isaacfonsi@gmail.com');
        $this->email->from('isaacfonsi@gmail.com', 'Epayco C.A');
        $this->email->subject('[Epayco]');
        $this->email->message('Codigo temporal de Epayco '.$token);
        $this->email->send();

        $this->load->view('layout/header_view', $data);
        $this->load->view('home/add/pay_token_view');
        $this->load->view('layout/footer_view');
    }


    public function sendPay() {

        $error           = 0;
        $message         = '';

        $ca_monto = trim($this->input->post('ca_monto'));
        $tx_token = trim($this->input->post('tx_token'));
        $coUsuario = $this->ion_auth->user_id();

        if ($ca_monto ==  ''):
            $message .= 'El monto es invalido';
            $error++;
        endif;


        $infoWallet= $this->home->getInfoUserWalletModel($coUsuario);
        if ($infoWallet->ca_saldo < $ca_monto):
            $message .= 'No tiene saldo suficiente';
            $error++;
        endif;

        $infoUser= $this->ion_auth->infoUserAll($coUsuario);
        if ($infoUser->tx_token != $tx_token):
            $message .= 'Token invalido';
            $error++;
        endif;

        if ($error == 0) {
            $info = $this->home->sendPayModel($ca_monto, $infoWallet, $coUsuario);
            $message .= 'Agregado';
        }
        $arreglo = array(
            'error' => $error,
            'message' => $message
        );
        echo json_encode($arreglo);
    }

    

    public function rechargeWallet() {
        $error           = 0;
        $message         = '';
        $nu_documento       = trim($this->input->post('nu_documento'));
        $nu_celular       = trim($this->input->post('nu_celular'));
        $ca_monto  = trim($this->input->post('ca_monto'));

        if ($nu_celular ==  ''):
                $message .= 'Numero de cuenta ya registrado';
                $error++;
        endif;

        $infoCelular = $this->home->getInfoCelularDocumento($nu_celular, $nu_documento);
        if ($infoCelular->num_rows() == 0):
            $message .= 'El documento o numero de celular es invalido';
            $error++;
        endif;


        if ($error == 0) {
            $info = $this->home->rechargeWalletModel($nu_celular, $ca_monto);
            $message .= 'Agregado';
        }
        $arreglo = array(
            'error' => $error,
            'message' => $message
        );
        echo json_encode($arreglo);
    }


    
    public function sendConsult() {
        $error           = 0;
        $message         = '';
        $ca_saldo = '';

        $nu_documento       = trim($this->input->post('nu_documento'));
        $nu_celular       = trim($this->input->post('nu_celular'));

        if ($nu_celular ==  ''):
                $message .= 'Numero de cuenta ya registrado';
                $error++;
        endif;

        $infoCelularDocumento = $this->home->getInfoCelularDocumento($nu_celular, $nu_documento);
        if ($infoCelularDocumento->num_rows() == 0):
            $message .= 'El documento o numero de celular es invalido';
            $error++;
        endif;

        $infoUser = $infoCelularDocumento->row();

        if ($error == 0) {
            $infoWallet = $this->home->getInfoUserWalletModel($infoUser->id);
            $message .= 'Agregado';
            $ca_saldo = $infoWallet->ca_saldo;
        }

        $arreglo = array(
            'error' => $error,
            'message' => $message,
            'ca_saldo' => $ca_saldo
        );
        echo json_encode($arreglo);



    }

    
    
}
?>