<?php

namespace Blurpa\EasyAuthentication\Rules;

class Number
{
    public function getErrorMessage()
    {
        return 'The (*) field must be a number.';
    }

    public function validate($item)
    {
        return is_numeric($item);
    }
}