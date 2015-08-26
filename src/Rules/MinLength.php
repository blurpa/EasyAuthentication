<?php

namespace Blurpa\EasyAuthentication\Rules;

class MinLength
{
    public function getErrorMessage()
    {
        return 'The (*) field must be (**) characters or more.';
    }

    public function validate($item, $minLength)
    {
        if (strlen($item) < $minLength) {
            return false;
        } else {
            return true;
        }
    }
}