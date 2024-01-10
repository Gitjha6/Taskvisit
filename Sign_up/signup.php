
<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST["username"];
    $email = $_POST["email"];
    $password = password_hash($_POST["password"], PASSWORD_BCRYPT); // Hash the password

    // Basic validation (you should do more robust validation in a real scenario)
    if (!empty($username) && !empty($email) && !empty($password)) {
        // Connect to the database (replace these details with your database credentials)
        $servername = "your_mysql_server";
        $dbname = "your_database_name";
        $dbusername = "your_database_username";
        $dbpassword = "your_database_password";

        try {
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // Insert user data into the database
            $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (:username, :email, :password)");
            $stmt->bindParam(':username', $username);
            $stmt->bindParam(':email', $email);
            $stmt->bindParam(':password', $password);
            $stmt->execute();

            // Redirect to a success page or perform other actions as needed
            header("Location: success.php");
            exit();
        } catch (PDOException $e) {
            echo "Connection failed: " . $e->getMessage();
        }
    } else {
        $error_message = "All fields are required.";
    }
}
?>
