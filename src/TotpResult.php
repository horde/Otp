<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Ralf Lang <ralf.lang@ralf-lang.de>
 */

namespace Horde\Otp;

final class TotpResult
{
    public function __construct(
        public readonly string $code,
        public readonly int $timeStep,
        public readonly int $expiresAt,
    ) {}

    public function __toString(): string
    {
        return $this->code;
    }

    public function secondsRemaining(int $now): int
    {
        return max(0, $this->expiresAt - $now);
    }
}
