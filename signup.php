<?php include("includes/session.php"); ?>
<?php
// session_start();
require_once('includes/conn.php');
if (isset($_SESSION['user'])) {
	header('location: index.php');
}
if (isset($_POST['submit'])) {
	if (isset($_POST['first_name'], $_POST['last_name'], $_POST['email'], $_POST['password'], $_POST['repassword']) && !empty($_POST['first_name']) && !empty($_POST['last_name']) && !empty($_POST['email']) && !empty($_POST['password'])) {
		$firstName = trim($_POST['first_name']);
		$lastName = trim($_POST['last_name']);
		$email = trim($_POST['email']);
		$password = trim($_POST['password']);
		$repassword = trim($_POST['repassword']);

		$options = array("cost" => 4);
		$hashPassword = password_hash($password, PASSWORD_BCRYPT, $options);
		$hashRePassword = password_hash($repassword, PASSWORD_BCRYPT, $options);
		$date = date('Y-m-d H:i:s');
		//generate code
		$set = '123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
		$code = substr(str_shuffle($set), 0, 12);

		if ($password != $repassword) {
			$_SESSION['error'] = 'Passwords did not match';
			header('location:register.php');
		}
		if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
			$conn = $pdo->open();
			$sql = 'select * from users where email = :email';
			$stmt = $conn->prepare($sql);
			$p = ['email' => $email];
			$stmt->execute($p);

			if ($stmt->rowCount() == 0) {
				$sql = "insert into users (firstname, lastname, email,password , activate_code,created_on) values(:fname,:lname,:email,:pass,:code,:created_on)";

				try {
					$handle = $conn->prepare($sql);
					$params = [
						':fname' => $firstName,
						':lname' => $lastName,
						':email' => $email,
						':pass' => $hashPassword,
						':code' => $code,
						':created_on' => $date

					];

					$handle->execute($params);

					$success = 'User has been created successfully';
				} catch (PDOException $e) {
					$errors[] = $e->getMessage();
				}
			} else {
				$valFirstName = $firstName;
				$valLastName = $lastName;
				$valEmail = '';
				$valPassword = $password;
				$valREPassword = $repassword;
				$errors[] = 'Email address already registered';
			}
		} else {
			$errors[] = "Email address is not valid";
		}
	} else {
		if (!isset($_POST['first_name']) || empty($_POST['first_name'])) {
			$errors[] = 'First name is required';
		} else {
			$valFirstName = $_POST['first_name'];
		}
		if (!isset($_POST['last_name']) || empty($_POST['last_name'])) {
			$errors[] = 'Last name is required';
		} else {
			$valLastName = $_POST['last_name'];
		}

		if (!isset($_POST['email']) || empty($_POST['email'])) {
			$errors[] = 'Email is required';
		} else {
			$valEmail = $_POST['email'];
		}

		if (!isset($_POST['password']) || empty($_POST['password'])) {
			$errors[] = 'Password is required';
		}
		if (!isset($_POST['repassword']) || empty($_POST['repassword'])) {
			$errors[] = 'RE Password is required';
		} else {
			$valPassword = $_POST['password'];
			$valREPassword = $_POST['repassword'];
		}
	}
}
?>

<?php
include('includes/header.php');
?>


<body class="hold-transition register-page">
	<div class="container h-100">
		<div class="register-box">
			<div class="row h-100 mt-5 justify-content-center align-items-center">
				<div class="register-box-body">

					<p class="login-box-msg">
					<h1 class="mx-auto w-25">Create a New Account</h1>
					</p>

					<?php
					if (isset($errors) && count($errors) > 0) {
						foreach ($errors as $error_msg) {
							echo '<div class="alert alert-danger">' . $error_msg . '</div>';
						}
					}

					if (isset($success)) {

						echo '<div class="alert alert-success">' . $success . '</div>';
					}
					?>
					<form method="POST" action="<?php echo $_SERVER['PHP_SELF']; ?>">
						<div class="form-group">
							<label for="email">First Name:</label>
							<input type="text" name="first_name" placeholder="Enter First Name" class="form-control" value="<?php echo ($valFirstName ?? '') ?>">
						</div>
						<div class="form-group">
							<label for="email">Last Name:</label>
							<input type="text" name="last_name" placeholder="Enter Last Name" class="form-control" value="<?php echo ($valLastName ?? '') ?>">
						</div>

						<div class="form-group">
							<label for="email">Email:</label>
							<input type="text" name="email" placeholder="Enter Email" class="form-control" value="<?php echo ($valEmail ?? '') ?>">
						</div>
						<div class="form-group">
							<label for="email">Password:</label>
							<input type="password" name="password" placeholder="Enter Password" class="form-control" value="<?php echo ($valPassword ?? '') ?>">
						</div>
						<div class="form-group">
							<label for="password">Repeat Password:</label>
							<input type="password" name=" repassword" placeholder="Enter Password agian" class="form-control" value="<?php echo ($valREPassword ?? '') ?>">
						</div>

						<button type="submit" name="submit" class="btn btn-primary">Register</button>
						<p class="pt-2"><a href=" login.php"> I Already Have a Account</a></p>
						<a href="index.php"><i class="fa fa-home"></i> Move To Home</a>
					</form>
				</div>
			</div>
		</div>
	</div>
</body>

</html>
