<?php
class Register_user_model extends CI_Model
{
  protected $_ion_hooks;
  protected $esquema = array();
  public $tables = array();
  function __construct()
  {
    parent::__construct();
    $this->tables = $this->config->item('tables', 'ion_auth');
    $this->esquema = $this->config->item('esquema_db', 'ion_auth');
    $this->hash_method = $this->config->item('hash_method', 'ion_auth');
  }
  public function hash_password_db($id, $password, $use_sha1_override = false)
  {
    if (empty($id) || empty($password))
    {
      return false;
    }
    $this->trigger_events('extra_where');
    $query = $this->db->select('password, salt')->where('id', $id)->limit(1)->order_by('id', 'desc')->get($this->tables['users']);
    $hash_password_db = $query->row();
    if ($query->num_rows() !== 1)
    {
      return false;
    }
    // bcrypt
    if ($use_sha1_override === false && $this->hash_method == 'bcrypt')
    {
      if ($this->bcrypt->verify($password, $hash_password_db->password))
      {
        return true;
      }
      return false;
    }
    // sha1
    if ($this->store_salt)
    {
      $db_password = sha1($password . $hash_password_db->salt);
    }
    else
    {
      $salt = substr($hash_password_db->password, 0, $this->salt_length);
      $db_password = $salt . substr(sha1($salt . $password) , 0, -$this->salt_length);
    }
    if ($db_password == $hash_password_db->password)
    {
      return true;
    }
    else
    {
      return false;
    }
  }
  public function trigger_events($events)
  {
    if (is_array($events) && !empty($events))
    {
      foreach ($events as $event)
      {
        $this->trigger_events($event);
      }
    }
    else
    {
      if (isset($this->_ion_hooks->$events) && !empty($this->_ion_hooks->$events))
      {
        foreach ($this->_ion_hooks->$events as $name => $hook)
        {
          $this->_call_hook($events, $name);
        }
      }
    }
  }
  public function salt()
  {
    $raw_salt_len = 16;
    $buffer = '';
    $buffer_valid = false;
    if (function_exists('mcrypt_create_iv') && !defined('PHALANGER'))
    {
      $buffer = mcrypt_create_iv($raw_salt_len, MCRYPT_DEV_URANDOM);
      if ($buffer)
      {
        $buffer_valid = true;
      }
    }
    if (!$buffer_valid && function_exists('openssl_random_pseudo_bytes'))
    {
      $buffer = openssl_random_pseudo_bytes($raw_salt_len);
      if ($buffer)
      {
        $buffer_valid = true;
      }
    }
    if (!$buffer_valid && @is_readable('/dev/urandom'))
    {
      $f = fopen('/dev/urandom', 'r');
      $read = strlen($buffer);
      while ($read < $raw_salt_len)
      {
        $buffer .= fread($f, $raw_salt_len - $read);
        $read = strlen($buffer);
      }
      fclose($f);
      if ($read >= $raw_salt_len)
      {
        $buffer_valid = true;
      }
    }
    if (!$buffer_valid || strlen($buffer) < $raw_salt_len)
    {
      $bl = strlen($buffer);
      for ($i = 0;$i < $raw_salt_len;$i++)
      {
        if ($i < $bl)
        {
          $buffer[$i] = $buffer[$i] ^ chr(mt_rand(0, 255));
        }
        else
        {
          $buffer .= chr(mt_rand(0, 255));
        }
      }
    }
    $salt = $buffer;
    // encode string with the Base64 variant used by crypt
    $base64_digits = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    $bcrypt64_digits = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    $base64_string = base64_encode($salt);
    $salt = strtr(rtrim($base64_string, '=') , $base64_digits, $bcrypt64_digits);
    $salt = substr($salt, 0, $this->salt_length);
    return $salt;
  }
  public function hash_password($password, $use_sha1_override = false)
  {
    if (empty($password))
    {
      return false;
    }
    // bcrypt
    if ($use_sha1_override === false && $this->hash_method == 'bcrypt')
    {
      return $this->bcrypt->hash($password);
    }
  }
  function get_user_usuario()
  {
    $sql = "SELECT * from lu_users WHERE NOT id in(1,2)";
    $query = $this->db->query($sql);
    return $query->result();
  }
  // Usuarios Inactivos o con problemas
  function get_user_usuario_id($co_usuario)
  {
    $sql = "SELECT a.* FROM lu_users as a
        WHERE NOT id = 1 and a.id = '$co_usuario'";
    $query = $this->db->query($sql);
    return $query->row();
  }
  function active_user_model($co_usuario)
  {
    $this->db->trans_start();
    $data['active'] = '1';
    $this->db->where("id", $co_usuario);
    $this->db->update("lu_users", $data);
    $this->db->trans_complete();
    return "Usuario activado";
  }
  function desactive_user_model($co_usuario)
  {
    $this->db->trans_start();
    $data['active'] = '0';
    $this->db->where("id", $co_usuario);
    $this->db->update("lu_users", $data);
    $this->db->trans_complete();
    return "Usuario desactivado";
  }
  // Agregar nuevo usuario
  function newUserModel($nu_documento, $email, $first_name, $last_name, $nu_celular, $password)
  {
    $this->db->trans_start();
    // Encriptar password
    $new_password = $this->hash_password($password);
    $lu_users['first_name'] = strtoupper($first_name);
    $lu_users['last_name'] = strtoupper($last_name);
    $lu_users['nu_celular'] = $nu_celular;
    $lu_users['nu_documento'] = $nu_documento;
    $lu_users['email'] = $email;
    $lu_users['active'] = '1';
    $lu_users['password'] = $new_password;
    $lu_users['created_on'] = time();
    $this->db->insert("lu_users", $lu_users);
    $co_new_usuario = $this->db->insert_id();
    $lu_users_groups['user_id'] = $co_new_usuario;
    $lu_users_groups['group_id'] = 7;
    $this->db->insert("lu_users_groups", $lu_users_groups);
    $j081t_wallet['co_usuario'] = $co_new_usuario;
    $this->db->insert("j081t_wallet", $j081t_wallet);
    $this->db->trans_complete();
    $this->ion_auth->login(trim($email) , trim($password) , 1);
    return true;
  }

}
?>
