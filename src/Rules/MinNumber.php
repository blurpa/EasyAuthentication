<?php

namespace Blurpa\EasyAuthentication\Rules;

class MinNumber
{
    public function getErrorMessage()
    {
        return 'The (*) field must be greater than or equal to (**).';
    }

    public function validate($item, $minNumber)
    {
        return $item >= $minNumber;
    }
}