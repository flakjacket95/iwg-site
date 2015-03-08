<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');

class Login_model extends CI_Model {
	function validate($pass)
	{
		$username = $this->input->post('user'); 
		$password = $this->input->post('pass');
		$this->db->where('username', $username);
		$query = $this->db->get('users');
		if($query->num_rows() == 1)
		{
			foreach($query->result() as $row)
			{
				$password = $this->passCreate($pass, $row->salt);
			}
			$this->db->where('password', $password);
			$query2 = $this->db->get('users');
			if($this->date_check($username))
			{
				if($query2->num_rows() == 1)
				{
					$this->zero_date_attempts($username);
					return true;
				}
				else
				{
					if($this->inc_attempt($username, true))
					{
						$this->date_set($username);
						return false;
					}
				}
			}
		}
		return false;
	}
	function date_check($username) {
		$this->db->where('username',$username);
		$query = $this->db->get('users');
		$olddate = 0;
		foreach($query->result() as $row)
		{
			$olddate = new DateTime($row->attempt_date);
		}
		$olddate = $olddate->add(new DateInterval('PT1H20M17S'));
		$newdate = new DateTime(date('Y-m-d H:i:s'));
		if($newdate > $olddate)
			return true;
		else
			return false;
	}
	function zero_date_attempts($username){
		$this->db->where('username',$username);
		$info = array (
			'login_attps' => 0,
			'attempt_date' => '0000-00-00 00:00:00',
			);
		$this->db->update('users', $info);
	}
	function inc_attempt($username, $increment){
		$this->db->where('username',$username);
		$query = $this->db->get('users');
		$attempts = 0;
		foreach($query->result() as $row)
		{
			$attempts = $row->login_attps;
		}
		if($increment == true)
		{
			$attempts++;
			$info = array (
				'login_attps' => $attempts,
				);
			$this->db->where('username', $username);
			$this->db->update('users',$info);
		}
		return ($attempts >= 6);
	}
	function date_set($username){
		$info = array (
			'attempt_date' => date('Y-m-d H:i:s'),
			);
		$this->db->where('username',$username);
		$this->db->update('users',$info);
	}
	private function create_member($password)
	{	
		$new_member_insert_data = array(
			'username' => 'admin',
			'password' => $password,
			'salt' => 'admin'					
		);
		
		$insert = $this->db->insert('users', $new_member_insert_data);
				return true;
	}
	function set_login($user){
		$this->db->where('u_id', $user);
		$query = $this->db->get('users');
		foreach ($query->result() as $s){
			$num = $s->logins + 1;
		}
		$data = array (
			'logins' => $num
			);
		$this->db->update('users', $data, array( 'u_id' => $user));
		return $num - 1;

	}
	function select_userinfo(){
		$this->db->where('username', $this->input->post('user'));
		$this->db->join('personal', 'personal.u_id = users.u_id');
		$query = $this->db->get('users');
		foreach ($query->result() as $row):
			$info = $row->f_name;
		    $info2 = $row->l_name;
		    $info = $info . " " . $info2;
		endforeach;
		return $info;

	}
	function select_level(){
		$this->db->where('username', $this->input->post('user'));
		$query = $this->db->get('users');
		foreach ($query->result() as $row):
			$info = $row->level;
		endforeach;
		return $info;

	}
	function select_id(){
		$this->db->where('username', $this->input->post('user'));
		$query = $this->db->get('users');
		foreach ($query->result() as $row):
			$info = $row->u_id;
		endforeach;
		return $info;

	}
	function select_rank(){
		$this->db->where('username', $this->input->post('user'));
		$this->db->join('personal', 'personal.u_id = users.u_id');
		$query = $this->db->get('users');
		foreach ($query->result() as $row):
			$info = $row->rank;
		endforeach;
		return $info;

	}
	function passCreate($password, $salt){
		if($password == "")
		{
			return false;
		}
		$global = "a7b&t4n*53e98BHJL:P:U";
		$global2 = "HJK6554645hg545^T&546HGr545FRE&3VYUyiuYTYII^&*%bHgvcmsvmn";
		$password = stripslashes($password); 
		$salt2 = md5(md5($global) . md5($password) . md5($global2) . md5($global));
		$hashofsalt = md5($salt);
		$passhash = "";
		for($k = 0; $k < 100; $k++)
		{
			for($i = 0; $i < 32; $i++)
			{
				if(is_numeric(substr($hashofsalt, $i, 1)))
				{
					for($j = 0; $j < 32; $j++)
					{
						$passhash = md5(substr($passhash,0,$j) . $salt2 . $global2 . substr($passhash,-1,$j) . $global);
					}
				}
				else
				{
					for($j = 0; $j < 32; $j++)
					{
						$passhash = md5(substr($passhash,0,$j) . $salt . $global2 . substr($passhash,-1,$j) . $global);
					}
				}
			}
			$hashofsalt = $passhash;
		}
		$i=0;
		while ($i <= 100)
		{
		$hashofsalt = substr_replace($hashofsalt ,"",-1);
		$hashofsalt = md5($hashofsalt);
		$i++;
		} 
		return $hashofsalt;
    }
}