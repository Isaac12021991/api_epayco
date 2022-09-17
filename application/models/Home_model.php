<?php
class Home_model extends CI_Model
{
  function __construct()
  {
    parent::__construct();
  }

  function getInfoUserWalletModel($coUsuario)
  {

    $sql = "SELECT * FROM j081t_wallet as a where a.co_usuario = $coUsuario";
    $query = $this->db->query($sql);
    return $query->row();
  }

  function InfoWalletLineaModel($coUsuario)
  {

    $sql = "SELECT * FROM x001t_wallet_linea as a where a.co_usuario = $coUsuario";
    $query = $this->db->query($sql);
    return $query->row();
  }

  function getUserModel()
  {

    $sql = "SELECT * FROM lu_users as a";
    $query = $this->db->query($sql);
    return $query;
  }

  function getInfoCelularDocumento($nu_celular, $nu_documento)
  {
    $sql = "SELECT * FROM lu_users as a
                where a.nu_celular = '$nu_celular' and a.nu_documento = '$nu_documento'";
    $query = $this->db->query($sql);
    return $query;
  }

  function rechargeWalletModel($nu_celular, $ca_monto)
  {
    $this->db->trans_start();

    $coUsuario = $this->ion_auth->user_id();

    $infoWallet = $this->getInfoUserWalletModel($coUsuario);

    $x001t_wallet_linea['co_wallet'] = $infoWallet->id;
    $x001t_wallet_linea['ca_monto'] = $ca_monto;
    $x001t_wallet_linea['co_usuario'] = $coUsuario;
    $x001t_wallet_linea['nb_operacion'] = 'CREDITO';
    $this->db->insert("x001t_wallet_linea", $x001t_wallet_linea);

    $j081t_wallet['ca_saldo'] = $infoWallet->ca_saldo + $ca_monto;
    $this->db->where("co_usuario", $coUsuario);
    $this->db->where("id", $infoWallet->id);
    $this->db->update("j081t_wallet", $j081t_wallet);
    $this->db->trans_complete();

    return true;
  }

  function generateTokenModel($coUsuario, $token)
  {
    $this->db->trans_start();
    $lu_users['tx_token'] = $token;
    $this->db->where("id", $coUsuario);
    $this->db->update("lu_users", $lu_users);
    $this->db->trans_complete();
    return true;
  }

  function sendPayModel($ca_monto, $infoWallet, $coUsuario)
  {
    $this->db->trans_start();

    $x001t_wallet_linea['co_wallet'] = $infoWallet->id;
    $x001t_wallet_linea['ca_monto'] = $ca_monto;
    $x001t_wallet_linea['co_usuario'] = $coUsuario;
    $x001t_wallet_linea['nb_operacion'] = 'DEBITO';
    $this->db->insert("x001t_wallet_linea", $x001t_wallet_linea);

    $j081t_wallet['ca_saldo'] = $infoWallet->ca_saldo - $ca_monto;
    $this->db->where("co_usuario", $coUsuario);
    $this->db->where("id", $infoWallet->id);
    $this->db->update("j081t_wallet", $j081t_wallet);
    $this->db->trans_complete();

    return true;
  }

}
?>
