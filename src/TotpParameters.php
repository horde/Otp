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

use Horde\Otp\Exception\OtpException;

final class TotpParameters
{
    public readonly Algorithm $algorithm;
    public readonly int $digits;
    public readonly int $period;
    public readonly int $epoch;

    public function __construct(
        Algorithm $algorithm = Algorithm::Sha1,
        int $digits = 6,
        int $period = 30,
        int $epoch = 0,
    ) {
        if ($digits < 6 || $digits > 8) {
            throw new OtpException(
                sprintf('Digits must be between 6 and 8, got %d', $digits)
            );
        }
        if ($period < 1) {
            throw new OtpException(
                sprintf('Period must be positive, got %d', $period)
            );
        }
        $this->algorithm = $algorithm;
        $this->digits = $digits;
        $this->period = $period;
        $this->epoch = $epoch;
    }
}
