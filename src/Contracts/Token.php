<?php

namespace Dracarys\Jwt\Contracts;

use DateTimeInterface;
use Dracarys\Jwt\Token\TokenSegment;

interface Token
{
    public function headers(): TokenSegment;

    public function isPermittedFor(string $audience): bool;

    public function isIdentifiedBy(string $id): bool;

    public function isRelatedTo(string $subject): bool;

    public function hasBeenIssuedBy(string ...$issuers): bool;

    public function hasBeenIssuedBefore(DateTimeInterface $now): bool;

    public function isMinimumTimeBefore(DateTimeInterface $now): bool;

    public function isExpired(DateTimeInterface $now): bool;

    public function toString(): string;
}