<?php

namespace Blurpa\EasyAuthentication;

class Validator
{

    private $validated;

    private $itemValidated;
    private $itemStopApplyingRules;
    private $fieldName;
    private $item;


    private $errors = array();

    public function __construct()
    {
        $this->validated = true;

    }

    public function validate($fieldName, $item)
    {
        $this->itemValidated = true;
        $this->itemStopApplyingRules = false;
        $this->fieldName = $fieldName;
        $this->item = $item;

        return $this;
    }

    public function applyRule($ruleName, $options = '')
    {
        if ($this->itemStopApplyingRules) {
            return $this;
        }

        $this->processRule($ruleName, $options);

        return $this;
    }

    public function applyStop($ruleName, $options = '')
    {
        if ($this->itemStopApplyingRules) {
            return $this;
        }

        $this->processRule($ruleName, $options);

        if ($this->itemValidated === false) {
            $this->itemStopApplyingRules = true;
        }

        return $this;
    }

    private function processRule($ruleName, $options)
    {
        $ruleName = '\Blurpa\EasyAuthentication\Rules\\' . $ruleName;
        $rule = new $ruleName;
        if (!$rule->validate($this->item, $options)) {
            $this->validated = false;
            $this->itemValidated = false;

            $errorMessage = $rule->getErrorMessage();
            $errorMessage = str_replace('(*)', $this->fieldName, $errorMessage);
            $errorMessage = str_replace('(**)', $options, $errorMessage);
            $this->errors[] = $errorMessage;
        }
    }

    public function getStatus()
    {
        return $this->validated;
    }

    public function getErrors()
    {
        return $this->errors;
    }
}