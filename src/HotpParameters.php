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

final class HotpParameters
{
    public readonly Algorithm $algorithm;
    public readonly int $digits;

    public function __construct(
        Algorithm $algorithm = Algorithm::Sha1,
        int $digits = 6,
    ) {
        if ($digits < 6 || $digits > 8) {
            throw new OtpException(
                sprintf('Digits must be between 6 and 8, got %d', $digits)
            );
        }
        $this->algorithm = $algorithm;
        $this->digits = $digits;
    }
}
