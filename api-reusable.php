<?php
ini_set("display_errors",1);
error_reporting(E_ALL);

//slimphp's auto load here
require '../vendor/autoload.php';
$app = new Slim\App();

/* -------------------- Routes --------------------- */
// --> GET ROUTES
$app->get('/messages/{name}', 'getChatroomMessages');
$app->get('/whosonline/{name}', 'getOnlineUsers');
$app->get('/logout/{name}', 'logOut');
$app->post('/login', function($request, $response, $args) { checkLogin($request->getParsedBody()); });
$app->post('/send', function($request, $response, $args) { sendMessage($request->getParsedBody()); });



/* ---------------- App Initiation ----------------- */
$app->run();


/* ---------------- Route Functions ----------------- */
function sendMessage($s) {

		function base64url_encode($data) {
		  return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
		}

		function base64url_decode($data) {
		  return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
		}

		// post requests
		$dbCon = getConnection();
		$messbx = htmlentities($s['messBox']);
		$dateT = date("Y-m-d H:i:s");
		//$dateT = isset($_POST['dateTime']) ? mysql_real_escape_string($_POST['dateTime']) : "";
		//$unamep = $app->request()->params('username');
		$unamep = $_GET['username'];
		$lnn = $s['lon'];
		$ltt = $s['lat'];
		$rolefound = $s['roleFound'];

		$sqlpic = "SELECT imgURL FROM profiletbl WHERE user = :usr";
		$st = $dbCon->prepare($sqlpic);
		$st->bindValue(':usr', $unamep, PDO::PARAM_STR);
		$st->execute();
		$row = $st->fetch();

		if($row){
		    	$url = $row['imgURL'];
		    } else {
		    	$url = "http://xxxxxx.com/xxx/images/square.jpg";
		}

		try {

			if($messbx){
				//insert message data
				$sql = "INSERT INTO messageBox (user,message,datetime,imgURL,longitude,latitude,role) VALUES (?,?,?,?,?,?,?)";
				$statement = $dbCon->prepare($sql);
				$insSt = $statement->execute(array($unamep,$messbx,$dateT,$url,"$lnn","$ltt","$rolefound"));

				if($insSt){
				    	echo "message inserted";
				    } else {
				    	echo "not inserted... oops!";
				}
			} else {
				echo "oops, something went a doosey!";
			}

		} catch(PDOException $e) {
		  		echo $e->getMessage();
		}
}


function logOut($request, $response, $args) {

	$xperson =  $args['name'];

	$db = getConnection();
	$person = $db->prepare('SELECT id, user, pass, email, role, name FROM profiletbl WHERE user = :username OR email = :username');
	$person->bindValue(':username', $xperson);
	$person->execute();
	$logoutresults = $person->fetch(PDO::FETCH_ASSOC);

	//echo $logoutresults['id'];

	$userfound = $logoutresults['id'];

	if($logoutresults === false){
        die('couldnt log you out!');
    } else {
    	setOnlineStatus($userfound, 0, null);
    }
}

function checkLogin($u) {

		$errMsg = '';
		$username = $u['username'];
		$password = $u['password'];



		if($username == '') {
			$errMsg .= 'You must enter your Username<br />';
		}

		if($password == '') {
			$errMsg .= 'You must enter your Password<br />';
		}

		if($errMsg == ''){
			$db = getConnection();
			$records = $db->prepare('SELECT id, user, pass, email, role, name FROM profiletbl WHERE user = :username OR email = :username');
			$records->bindValue(':username', $username);
			$records->execute();
			$results = $records->fetch(PDO::FETCH_ASSOC);

			if($results === false){
		        die('Incorrect username / password combination');
		    } else {
		        $pass =  hash('sha256', $password);

		        if($results['pass'] === $pass){
		        	//Generate a random string.
					$token = openssl_random_pseudo_bytes(16);
					//Convert the binary data into hexadecimal representation.
					$token = bin2hex($token);

					$_SESSION['username'] = $results['user'];
					//print(json_encode('Login Successful'));
					//print(json_encode($results['user']));
					$foundrole = (empty($results['role']) ? 'basic' : $results['role']);

					$data = array('name' => $results['user'], 'role' => $foundrole,  'msg' => 'Authenticated', 'token' => $token);

					setOnlineStatus($results['id'], 1, $token);
					echo json_encode($data);

					exit;
		        } else{
		            die('Incorrect password!');
		        }
			}

		} else {
			$errMsg .= 'Username and Password are not found<br>';
		}
}

function setOnlineStatus($usersID, $status, $tk) {

		$dbCon = getConnection();
		$tokenfound = $tk;

		if($status === 0) {
			$loggedInTimeNow = ' ';
			$tokenfound = null;
		} else {
			$loggedInTimeNow = date('Y-m-d H:i:s');
			$tokenfound = $tk;
		}

		$sql = "UPDATE profiletbl SET isLoggedIn = ?, isLoggedInTime = ?, authToken = ? WHERE id = ?";
		$statement = $dbCon->prepare($sql);
		$insSt = $statement->execute(array($status,$loggedInTimeNow,$tokenfound,$usersID));

		if($status) {
	    	return;
	    }


}




function getOnlineUsers($request, $response, $args) {
	try {
	    $dbCon = getConnection();

	    $stmt = $dbCon->prepare("SELECT profiletbl.* FROM profiletbl WHERE profiletbl.isLoggedIn = 1 AND profiletbl.user NOT IN (SELECT blockedUsr FROM blockRequests WHERE reportedBy = :myusername AND block IS NOT NULL) LIMIT 10");
	    $stmt->bindParam(":myusername", $args['name']);
		//$stmt->execute(array($args['name']));
		$stmt->execute();
		$result = $stmt->fetchAll(PDO::FETCH_ASSOC);
		//now echo json results
		//$dbCon = null;
		print json_encode($result);
	} catch(PDOException $e) {
	    echo '{"error":{"text":'. $e->getMessage() .'}}';
	}
}



function getChatroomMessages($request, $response, $args) {
	try {
	    $dbCon = getConnection();
	    $stmt = $dbCon->prepare("SELECT messageBox.* FROM messageBox WHERE messageBox.user NOT IN (SELECT blockedUsr FROM blockRequests WHERE reportedBy = :myusername AND block IS NOT NULL) ORDER BY datetime DESC LIMIT 50");
	    $stmt->bindParam(":myusername", $args['name']);
			$stmt->execute();
			$result = $stmt->fetchAll(PDO::FETCH_ASSOC);
			print json_encode($result);
	} catch(PDOException $e) {
	    echo '{"error":{"text":'. $e->getMessage() .'}}';
	}
}




/* -------------- Database Connection -------------- */
function getConnection() {
    $databasehost = 'localhost';
    $databaseuser = 'xxxxx';
    $databasepass = 'xxxxx';
    $databasename = 'xxxxx';
    $mysql_conn_string = "mysql:host=$databasehost;dbname=$databasename";
    $dbConnection = new PDO($mysql_conn_string, $databaseuser, $databasepass);
    $dbConnection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    return $dbConnection;
}


?>
