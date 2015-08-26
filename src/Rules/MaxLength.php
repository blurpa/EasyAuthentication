<?php

namespace Blurpa\EasyAuthentication\Rules;

class MaxLength
{
    public function getErrorMessage()
    {
        return 'The (*) field must be (**) characters or less.';
    }

    public function validate($item, $maxLength)
    {
        if (strlen($item) > $maxLength) {
            return false;
        } else {
            return true;
        }
    }
}