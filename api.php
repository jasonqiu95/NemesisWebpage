<?php


if(!file_exists("config.php")){
	header("Location: install/");
}

$base = dirname($_SERVER['PHP_SELF']);
$pagePath = substr($_SERVER['REQUEST_URI'], strlen($base)+1);

include('config.php');

//start
header('Content-Type: application/json');
$content = file_get_contents('php://input');
$data = json_decode($content, true);

$op = $_GET["op"];

if ($op == "login") {

	$data = new nemesis\Collection($data);
	$user->login($data->email, $data->password);


	if($user->log->hasError()){
		echo json_encode(array(
			'error' => $user->log->getErrors(),
		));
	} else {
		echo json_encode(array(
			'error' => $user->log->getErrors(),
			'confirm' => "You are now login as <b>$user->email</b>",
			'accessToken' => $user->accessToken,
		));
	}
} else if ($op == "register") {

	/*
     * If the form fields names match your DB columns then you can reduce the collection
     * to only those expected fields using the filter() function
     */
	$data = new nemesis\Collection($data);
	$data->filter('email', 'password');
	/*
     * Register the user
     * The register method takes either an array or a Collection
     */
	$user->register($data);

	if(!$user->log->hasError()){
		$filename = 'uploads/' . $data->email . '.json';
		copy('uploads/default.json', $filename);
	}

	echo json_encode(
		array(
			'error'   => $user->log->getErrors(),
			'confirm' => 'User Registered Successfully. You may login now!',
		)
	);
} else if ($op == "log") {
	
	$input = new nemesis\Collection($data);

	$user->validateLogin($input->email, $input->accessToken);
	
	if($user->log->hasError()){
	
	} else {
		$user->logOperation("save");

		$fp = fopen('uploads/' . $input->email . '.json', 'w');
		fwrite($fp, $content);
		fclose($fp);
	}

	echo json_encode(
		array(
			'error'   => $user->log->getErrors(),
			'confirm' => 'log success!',
		)
	);
} else if ($op == "load") {

	$input = new nemesis\Collection($data);

	$user->validateLogin($input->email, $input->accessToken);

	if($user->log->hasError()){
		echo json_encode(
			array(
				'error'   => $user->log->getErrors(),
			)
		);
	} else {
		$filename = 'uploads/' . $input->email . '.json';
		$fp = fopen($filename, 'r');
		$content = fread($fp,filesize($filename));
		fclose($fp);
		echo json_encode(
			array(
				'error'   => $user->log->getErrors(),
				'data'	  => json_decode($content, true),
			)
		);
	}
}


?>
