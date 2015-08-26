<?php

namespace Blurpa\EasyAuthentication\Rules;

class Required
{
    public function getErrorMessage()
    {
        return 'The {*} field is required.';
    }

    public function validate($item, $options)
    {
        return (!empty($item));
    }
}