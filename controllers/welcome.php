<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');

class Welcome extends CI_Controller {
	function __construct(){
		parent::__construct();
		//$this->load->model('info_model');
		$this->is_logged_in();
	}
	private function is_logged_in(){
		if ($this->session->userdata('session_valid') == false)
		{
			redirect('http://' . base_url(''));
		}
	}
	//public function index()
	//{
	//	$this->load->view('welcome_message');
	//}
	public function template()
	{
		$this->load->view('template');
	}
	public function home() {
		$this->load->model('training_model');
		$data['word'] = "";
		$data['firstpage'] = true;
		$data['articles']['web'] = $this->training_model->selectTag("web");
		$data['articles']['db'] = $this->training_model->selectTag("database");
		$data['articles']['binary'] = $this->training_model->selectTag("binary");
		$data['articles']['foren'] = $this->training_model->selectTag("forensic");
		$this->load->view('home',$data);
	}
	public function begin_binary(){
		$data['level'] = "basic";
		$this->load->view('beg_bin',$data);
	}
	public function adv_binary(){
		$data['level'] = "advanced";
		$this->load->view('beg_bin',$data);
	}
	public function begin_web(){
		$data['level'] = "basic";
		$this->load->view('web',$data);
	}
	public function adv_web(){
		$data['level'] = "advanced";
		$this->load->view('web',$data);
	}
	public function begin_foren(){
		$data['level'] = "basic";
		$this->load->view('foren',$data);
	}
	public function adv_foren(){
		$data['level'] = "advanced";
		$this->load->view('foren',$data);
	}
	public function begin_exp(){
		$data['level'] = "basic";
		$this->load->view('exp',$data);
	}
	public function adv_exp(){
		$data['level'] = "advanced";
		$this->load->view('exp',$data);
	}
	public function policy(){
		$data['level'] = "basic";
		$this->load->view('policy',$data);
	}
	public function downloads(){
		$this->load->view('vm_dwnlds');
	}
	public function academy(){
		$this->load->view('vm_acad');
	}
	public function servers(){
		$this->load->view('servers');
	}
	public function comput(){
		$this->load->view('comput');
	}
	public function apps(){
		$this->load->view('apps');
	}
	public function leaders(){
		$this->load->view('leaders');
	}
	public function schedule(){
		$this->load->view('schedule');
	}
	public function cdx(){
		$this->load->view('cdx');
	}
	public function cyberstakes(){
		$this->load->view('cyberstakes');
	}
	public function info(){
		$this->load->view('information');
	}
	public function articles(){
		$this->load->model('training_model');
		$data['test'] = $this->training_model->articles();
		$this->load->view('articles', $data);
	}
	public function article(){
		$this->load->model('training_model');
		$id = $this->uri->segment(3);
		if($id > 0)
		{
			$data['test'] = $this->training_model->articles($id);
			$data['single'] = false;
		}
		else
		{
			$data['test'] = $this->training_model->articles(false);
			$data['single'] = true;
		}
		$this->load->view('articles', $data);
	}
	/*private function runpass(){
		$this->load->model('login_model');
		//$passhash = $this->ac_model->new_password_hash("admin", "admin");
		//echo "Your new hash is: " . $passhash;
		$filecontent = file_get_contents('C:\Users\m171818\Desktop\pswds.txt');

		$words = preg_split('/[\s]+/', $filecontent, -1, PREG_SPLIT_NO_EMPTY);
		$info = array();
		for($i = 0; $i < count($words); $i = $i + 5)
		{
			$newsalt = $words[$i + 2];
			$password = $this->login_model->passCreate($words[$i + 1], $newsalt);
			$data = array(
				'username' => $words[$i],
				'password' => $password,
				'level' => 0,
				'salt' => $newsalt
				);
			$this->db->insert('users', $data); 
			$this->db->where('password', $password);
			$query = $this->db->get('users');
			foreach($query->result() as $rows)
			{
				$data2 = array(
					'f_name' => $words[$i + 4],
					'email' => $words[$i + 3],
					'u_id' => $rows->u_id
					);
				$this->db->insert('personal', $data2);
			}
			$info[] = $data;
		}
		echo "<pre>";
		print_r ($info);
		echo "</pre>";
	}*/
	public function passchange(){
		$this->load->model('training_model');
		$id = $this->session->userdata('user_id');
		$data['user'] = $this->session->userdata('name');
		$data['id'] = $id;
		$data['admin'] = $this->session->userdata('access');
		if($this->input->post('newpassword') == "")
		{
			$this->load->view('pass', $data);
		}
		else
		{
			$old = $this->training_model->validateoldpswd($id, $this->input->post('oldpassword'));
			if($old == "Same")
			{
				if($this->input->post('newpassword') === $this->input->post('newpassword2'))
				{
					$special = 0;
					$charu = 0;
					$charl = 0;
					$num = 0;
					$pass = $this->input->post('newpassword');
					for ($i=0; $i < strlen($pass); $i++) { 
						$individual = substr($pass, $i,1);
						if($individual > 'z' || ($individual < 'a' && $individual > 'Z'))
							$special++;
						else if($individual < '0' || ($individual < 'A' && $individual > '9'))
							$special++;
						else if(($individual >= 'A' && $individual <= 'Z'))
							$charu++;
						else if(($individual >= 'a' && $individual <= 'z'))
							$charl++;
						else if(($individual >= '0' && $individual <= '9'))
							$num++;
					}
					$same = $this->training_model->validateoldpswd($id, $this->input->post('newpassword'));
					if(strlen($pass) < 10)
						$data['success'] = "Your password is not long enough.";
					else if($same == "Same")
						$data['success'] = "You did not change your password.";
					else if($special >= 1 && $charu >= 2 && $num >= 2)
						$data['success'] = $this->training_model->passchange($id, $this->input->post('newpassword'));
					else
						$data['success'] = "Your new password does not meet the password complexity requirements.";
				}
				else
				{
					$data['success'] = "New Passwords Do Not Match";
				}
			}
			else
			{
				$data['success'] = "Old Password Is Incorrect!";
			}
			$this->load->view('pass',$data);
		}
	}
	public function ins_article(){
		if($this->session->userdata('access') >= 4)
		{
			if($this->input->post('title') == "")
			{
				$this->load->view('edit');
			}
			else
			{
				$this->load->model('training_model');
				$info = array();
				$info['title'] = $this->input->post('title');
				$info['author'] = $this->session->userdata('rank') . " " . $this->session->userdata('name');
				$info['tags'] = $this->input->post('tags');
				$info['content'] = htmlentities($this->input->post('content'));
				$info['update_date'] = date('Y-m-d H:i:s');
				$info['views'] = 0;
				$info['links'] = $this->input->post('links');
				$this->training_model->insertArticle($info);
				$this->load->view('edit');
			}
		}
		else
		{
			echo "You do not authorization to view this resource!";
		}
	}
}

/* End of file welcome.php */
/* Location: ./application/controllers/welcome.php */