<?php

/**
 * EasyAuthentication - Created in August, 2015.
 *
 * Author: Nick Stuer
 * Contact: nickstuer@gmail.com
 *
 * License: MIT
 *
 */

namespace Blurpa\EasyAuthentication;

use Blurpa\EasySession\Session;
use PDO;

use Blurpa\EasyValidator\Validator;

/**
 * Class Authentication
 * @package Blurpa\EasyAuthentication
 *
 * TODO:
 *      login DDOS protection.
 *      recover password by email
 */

class Authentication
{
    /**
     * @var Session
     */
    private $session;

    /**
     * @var PDO
     */
    private $pdo;

    /**
     * @var array
     */
    private $messages = array();

    /**
     * @var int
     */
    private $userId;

    /**
     * Constructor
     *
     * @param Session   $session
     * @param PDO       $pdo
     */
    public function __construct(Session $session, PDO $pdo)
    {
        $this->session = $session;
        $this->pdo = $pdo;
    }

    /**
     * @return array
     */
    public function getMessages()
    {
        return $this->messages;
    }

    /**
     * @param string    $email
     * @param string    $password
     * @return bool
     */
    public function loginWithEmail($email, $password)
    {
        $stmt = $this->pdo->prepare("SELECT id,password FROM users WHERE email=:email LIMIT 1");
        $stmt->execute(array(':email' => $email));

        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (count($row) < 1) {
            $this->messages[] = "Provided email or password do not match our records.";
            return false;
        }

        if (!password_verify($password, $row['password'])) {
            $this->messages[] = "Provided email or password do not match our records.";
            return false;
        }

        $this->userId = $row['id'];
        return $this->performLogin($this->userId);
    }

    /**
     * @param array     $data
     *
     * @return bool
     */
    public function register($data)
    {
        $csrfToken = $data['csrfToken'];

        $email = $data['email'];
        $username = $data['username'];
        $password = $data['password'];

        $validator = new Validator();
        $validator->validate('email', $email)
            ->applyStop('Required')
            ->applyRule('Email')
            ->applyRule('MaxLength', 70);

        $validator->validate('username', $username)
            ->applyStop('Required')
            ->applyRule('MinLength', 3)
            ->applyRule('MaxLength', 22);

        $validator->validate('password', $password)
            ->applyStop('Required')
            ->applyRule('MinLength', 8);

        /**
         * If the validator failed any step, return false.
         * No need to check database for email and username duplicates.
         */
        if (!$validator->getValidationStatus()) {
            $this->messages = $validator->getMessages();
            return false;
        }

        if ($this->findByEmail($email)) {
            $this->messages[] = "Email already exists in our records";
        }

        if ($this->findByUsername($username)) {
            $this->messages[] = "Username already exists.";
        }

        $passwordHash = password_hash($password, PASSWORD_BCRYPT, array("cost" => 10));
        if (strlen($passwordHash) <= 20) {
            $this->messages[] = "Unexpected error, password invalid.";
        }

        if ($this->isError()) {
            return false;
        }

        $stmt = $this->pdo->prepare("INSERT INTO users
                  ('username', 'email', 'password', 'timestamp')
                  VALUES (:username, :email, :password, :timestamp)");

        if (!$stmt->execute(array(':username' => $username, ':email' => $email, ':password' => $passwordHash, 'timestamp' => time())))
        {
            $this->messages[] = "Database error occurred, Unknown";
            return false;
        }

        $userId = $this->pdo->lastInsertId();
        if (!$this->performLogin($userId)) {
            $this->messages[] = "Unexpected error occurred during login. Account created successfully though.";
            return false;
        }

        return true;
    }

    /**
     * @param $userId
     *
     * @return bool
     */
    public function performLogin($userId)
    {
        $authToken = $this->session->generateToken();

        $this->session->setCookie('authToken', $authToken);

        $stmt = $this->pdo->prepare("INSERT INTO auth_tokens
                  ('token', 'userid')
                  VALUES (:token, :userid)");

        return $stmt->execute(array(':token' => $authToken, ':userid' => $userId));
    }

    /**
     * Checks if an email is in the database
     *
     * @param string    $email
     * @return bool
     */
    public function findByEmail($email)
    {
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM users WHERE email=:email LIMIT 1");
        $stmt->execute(array(':email' => $email));

        $rowCount = $stmt->fetch(PDO::FETCH_NUM);

        return ($rowCount[0] >= 1);
    }

    /**
     * Checks if a username is in the database
     *
     * @param string    $username
     * @return bool
     */
    public function findByUsername($username)
    {
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM users WHERE username=:username LIMIT 1");
        $stmt->execute(array(':username' => $username));

        $rowCount = $stmt->fetch(PDO::FETCH_NUM);

        return ($rowCount[0] >= 1);
    }

    /**
     * @return bool
     */
    public function isError()
    {
        return (count($this->messages) >= 1);
    }


}
