<?php
declare(strict_types=1);

/**
 * Validator
 * Lightweight rule-based input validator. Does not mutate input
 * (see Sanitizer for cleaning) — only reports pass/fail + messages.
 *
 * Usage:
 *   $v = new Validator($_POST, [
 *       'email'    => 'required|email',
 *       'password' => 'required|min:8',
 *   ]);
 *   if (!$v->passes()) { $errors = $v->errors(); }
 */
final class Validator
{
    private array $data;
    private array $rules;
    private array $errors = [];

    public function __construct(array $data, array $rules)
    {
        $this->data = $data;
        $this->rules = $rules;
    }

    public function passes(): bool
    {
        $this->errors = [];
        foreach ($this->rules as $field => $ruleString) {
            $rulesForField = explode('|', $ruleString);
            $value = $this->data[$field] ?? null;

            foreach ($rulesForField as $rule) {
                [$name, $param] = array_pad(explode(':', $rule, 2), 2, null);
                $method = 'rule' . str_replace('_', '', ucwords($name, '_'));
                if (!method_exists($this, $method)) {
                    continue;
                }
                if (!$this->{$method}($field, $value, $param)) {
                    // required already recorded its own message; stop at first failure per field
                    break;
                }
            }
        }
        return empty($this->errors);
    }

    public function fails(): bool
    {
        return !$this->passes();
    }

    public function errors(): array
    {
        return $this->errors;
    }

    public function firstError(): ?string
    {
        foreach ($this->errors as $fieldErrors) {
            return $fieldErrors[0] ?? null;
        }
        return null;
    }

    private function addError(string $field, string $message): void
    {
        $this->errors[$field][] = $message;
    }

    // ---- Rule implementations -------------------------------------------------

    private function ruleRequired(string $field, mixed $value, ?string $param): bool
    {
        if ($value === null || (is_string($value) && trim($value) === '')) {
            $this->addError($field, ucfirst($field) . ' is required.');
            return false;
        }
        return true;
    }

    private function ruleEmail(string $field, mixed $value, ?string $param): bool
    {
        if ($value === null || $value === '') {
            return true; // let 'required' handle empties
        }
        if (!filter_var($value, FILTER_VALIDATE_EMAIL)) {
            $this->addError($field, 'Please provide a valid email address.');
            return false;
        }
        return true;
    }

    private function ruleMin(string $field, mixed $value, ?string $param): bool
    {
        $min = (int) $param;
        $len = is_string($value) ? mb_strlen($value) : (is_numeric($value) ? (float) $value : 0);
        if ($len < $min) {
            $this->addError($field, ucfirst($field) . " must be at least {$min} characters/units.");
            return false;
        }
        return true;
    }

    private function ruleMax(string $field, mixed $value, ?string $param): bool
    {
        $max = (int) $param;
        $len = is_string($value) ? mb_strlen($value) : (is_numeric($value) ? (float) $value : 0);
        if ($len > $max) {
            $this->addError($field, ucfirst($field) . " must not exceed {$max} characters/units.");
            return false;
        }
        return true;
    }

    private function ruleNumeric(string $field, mixed $value, ?string $param): bool
    {
        if ($value !== null && $value !== '' && !is_numeric($value)) {
            $this->addError($field, ucfirst($field) . ' must be numeric.');
            return false;
        }
        return true;
    }

    private function ruleAlpha(string $field, mixed $value, ?string $param): bool
    {
        if ($value !== null && $value !== '' && !preg_match('/^[a-zA-Z]+$/', (string) $value)) {
            $this->addError($field, ucfirst($field) . ' must contain only letters.');
            return false;
        }
        return true;
    }

    private function ruleAlphanumeric(string $field, mixed $value, ?string $param): bool
    {
        if ($value !== null && $value !== '' && !preg_match('/^[a-zA-Z0-9]+$/', (string) $value)) {
            $this->addError($field, ucfirst($field) . ' must contain only letters and numbers.');
            return false;
        }
        return true;
    }

    private function ruleAlphaDash(string $field, mixed $value, ?string $param): bool
    {
        if ($value !== null && $value !== '' && !preg_match('/^[a-zA-Z0-9_-]+$/', (string) $value)) {
            $this->addError($field, ucfirst($field) . ' may only contain letters, numbers, dashes and underscores.');
            return false;
        }
        return true;
    }

    private function ruleRegex(string $field, mixed $value, ?string $param): bool
    {
        if ($value !== null && $value !== '' && !preg_match($param, (string) $value)) {
            $this->addError($field, ucfirst($field) . ' has an invalid format.');
            return false;
        }
        return true;
    }

    private function ruleMatches(string $field, mixed $value, ?string $param): bool
    {
        if ($value !== ($this->data[$param] ?? null)) {
            $this->addError($field, ucfirst($field) . " must match {$param}.");
            return false;
        }
        return true;
    }

    private function ruleIn(string $field, mixed $value, ?string $param): bool
    {
        $options = explode(',', (string) $param);
        if ($value !== null && $value !== '' && !in_array((string) $value, $options, true)) {
            $this->addError($field, ucfirst($field) . ' is not a valid option.');
            return false;
        }
        return true;
    }

    private function ruleBoolean(string $field, mixed $value, ?string $param): bool
    {
        if ($value !== null && filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) === null) {
            $this->addError($field, ucfirst($field) . ' must be true or false.');
            return false;
        }
        return true;
    }

    private function ruleDate(string $field, mixed $value, ?string $param): bool
    {
        if ($value === null || $value === '') {
            return true;
        }
        $format = $param ?: 'Y-m-d';
        $d = DateTime::createFromFormat($format, (string) $value);
        if (!$d || $d->format($format) !== $value) {
            $this->addError($field, ucfirst($field) . ' is not a valid date.');
            return false;
        }
        return true;
    }

    private function ruleUrl(string $field, mixed $value, ?string $param): bool
    {
        if ($value !== null && $value !== '' && !filter_var($value, FILTER_VALIDATE_URL)) {
            $this->addError($field, ucfirst($field) . ' must be a valid URL.');
            return false;
        }
        return true;
    }

    /** Strong password policy: >=8 chars, upper, lower, digit, special char. */
    private function rulePasswordStrength(string $field, mixed $value, ?string $param): bool
    {
        $value = (string) $value;
        $ok = strlen($value) >= 8
            && preg_match('/[A-Z]/', $value)
            && preg_match('/[a-z]/', $value)
            && preg_match('/[0-9]/', $value)
            && preg_match('/[^A-Za-z0-9]/', $value);
        if (!$ok) {
            $this->addError($field, 'Password must be at least 8 characters and include upper/lowercase letters, a number, and a special character.');
            return false;
        }
        return true;
    }

    private function ruleTotpCode(string $field, mixed $value, ?string $param): bool
    {
        if ($value !== null && $value !== '' && !preg_match('/^\d{6}$/', (string) $value)) {
            $this->addError($field, 'Authentication code must be 6 digits.');
            return false;
        }
        return true;
    }
}
