<?php

namespace Blurpa\EasyAuthentication\Rules;

class Email
{
    public function getErrorMessage()
    {
        return 'The email field is an invalid format.';
    }

    public function validate($item, $options)
    {
        if (!filter_var($item, FILTER_VALIDATE_EMAIL)) {
            return false;
        } else
        {
            return true;
        }
    }
}