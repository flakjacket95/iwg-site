<?php
class Training_model extends CI_Model {
	public function articles($id){
		if($id == false)
		{
			$query = $this->db->get('training', 10);
		}
		else
		{
			$this->db->where('t_id',$id);
			$query = $this->db->get('training');
			//Change Views
			$sql = "UPDATE `training` SET `views`=views + 1 WHERE t_id=?";
			$this->db->query($sql, $id);
		}
		$info = array();
		foreach($query->result() as $row)
		{
			$info[$row->t_id]['t_id'] = $row->t_id;
			$info[$row->t_id]['title'] = $row->title;
			$info[$row->t_id]['content'] = $row->content;
			$info[$row->t_id]['author'] = $row->author;
			$info[$row->t_id]['date'] = $row->update_date;
			$info[$row->t_id]['links'] = $row->links;
			$info[$row->t_id]['tags'] = $row->tags;
		}
		return $info;
	}
	public function selectTag($tag)
	{
		$this->db->like('tags',$tag);
		$query = $this->db->get('training');
		$info = array();
		foreach($query->result() as $row)
		{
			$info[$row->t_id]['t_id'] = $row->t_id;
			$info[$row->t_id]['title'] = $row->title;
			$info[$row->t_id]['author'] = $row->author;
		}
		return $info;
	}
	public function passchange($u_id,$password){
      $this->load->model('login_model');
      $this->db->where('u_id',$u_id);
      $query = $this->db->get('users');
      $salt = "";
      foreach($query->result() as $row)
      {
        $salt = $row->salt;
      }
      $data = array(
        'password' => $this->login_model->passCreate($password, $salt),
        );
      $this->db->where('u_id',$u_id);
      $this->db->update('users',$data);
      return "Success!";
    }

    public function validateoldpswd($u_id, $password){
      $this->load->model('login_model');
      $this->db->where('u_id',$u_id);
      $query = $this->db->get('users');
      $salt = "";
      $pass = "";
      foreach($query->result() as $row)
      {
        $salt = $row->salt;
        $pass = $row->password;
      }
      $passnew = $this->login_model->passCreate($password, $salt);
      if($passnew == $pass)
      {
        return "Same";
      }
      else
      {
      	return "Diff";
      }
    }
    public function insertArticle($data){
    	$sql = "INSERT INTO `training` (`t_id`, `title`, `author`, `tags`, `content`, `update_date`, `views`, `links`) VALUES (NULL, ?, ?, ?, ?, ?, 0, ?);";
    	$this->db->query($sql, $data);
    }
}