<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');

class Session extends CI_Controller {
	function __construct(){
		parent::__construct();
		$this->load->model('login_model');
	}
	public function index(){
		$this->load->view('welcome_message');
	}
	public function login(){
		$pass = $this->input->post('pass');
		$result = $this->login_model->validate($pass);
		if($result == true)
		{
			$name = $this->login_model->select_userinfo();
			$access = $this->login_model->select_level();
			$rank = $this->login_model->select_rank();
			$id = $this->login_model->select_id();
			$num = $this->login_model->set_login($id);
			$data = array(
				'username' => $this->input->post('username'),
				'session_valid' => true,
				'name' => $name,
				'access' => $access,
				'rank' => $rank,
				'user_id' => $id
			);
			$this->session->set_userdata($data);
			redirect('http://' . site_url('welcome/home'));
		}
		else
		{
			redirect('http://' . base_url(''));
		}
	}

	public function logout()
	{
		$this->session->sess_destroy();
		redirect('http://' . base_url(''));
	}
}