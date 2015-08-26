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

use Blurpa\EasyAuthentication\Validator;

class Authentication
{
    private $session;
    private $pdo;
    private $lang;

    private $messages = array();
    private $userId;

    public function __construct(Session $session, PDO $pdo)
    {
        $this->session = $session;
        $this->pdo = $pdo;

        $this->lang = require(__DIR__ . '/Languages/english.php');
    }

    public function boot()
    {

    }

    public function getErrorMessages()
    {
        return $this->messages;
    }

    public function loginWithEmail($email, $password)
    {
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM users WHERE email=:email AND password=:password LIMIT 1");
        $stmt->execute(array(':email' => $email, ':password' => $password));

        $rowCount = $stmt->fetch(PDO::FETCH_NUM);

        if ($rowCount[0] < 1) {
            $this->messages[] = $this->lang['login_withEmail_invalid'];
            return false;
        }

        return true;
    }

    public function register()
    {
        $email = "12345678@test.com";
        $password = "12345678";
        $age = "18";

        $validator = new Validator();
        $validator->validate('email', $email)
            ->applyStop('Required')
            ->applyStop('Email')
            ->applyRule('MaxLength', 70);

        $validator->validate('password', $password)
            ->applyStop('Required')
            ->applyRule('MinLength', 8);

        $validator->validate('age', $age)
            ->applyStop('Number')
            ->applyStop('MinNumber', 18);

        $this->messages = $validator->getErrors();
        return $validator->getStatus();
    }

    public function validateEmail($email)
    {
        if (strlen($email) > 70) {
            $this->messages[] = $this->lang['email_length_long'];
            return false;
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->messages[] = $this->lang['email_format_invalid'];
            return false;
        }

        return true;
    }

    public function validatePassword($password)
    {
        if (strlen($password) < 8) {
            $this->messages[] = $this->lang['password_length_short'];
            return false;
        }
    }

    public function isError()
    {
        if (count($this->messages) >= 1) {
            return true;
        } else {
            return false;
        }
    }


}
