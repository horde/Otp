<?php

declare(strict_types=1);

/**
 * RFC 6238 Time-Based One-Time Password calculator.
 *
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Ralf Lang <ralf.lang@ralf-lang.de>
 */

namespace Horde\Otp;

use DateTimeInterface;

final class Totp
{
    private readonly TotpParameters $parameters;
    private readonly Hotp $hotp;

    public function __construct(
        ?TotpParameters $parameters = null,
    ) {
        $this->parameters = $parameters ?? new TotpParameters();
        $this->hotp = new Hotp(new HotpParameters(
            $this->parameters->algorithm,
            $this->parameters->digits,
        ));
    }

    public function generate(Secret $secret, int $timestamp): TotpResult
    {
        $step = $this->counter($timestamp);
        $code = $this->hotp->compute($secret->toRaw(), $step);
        return new TotpResult(
            $code,
            $step,
            ($step + 1) * $this->parameters->period + $this->parameters->epoch,
        );
    }

    public function generateAt(Secret $secret, DateTimeInterface $time): TotpResult
    {
        return $this->generate($secret, $time->getTimestamp());
    }

    public function verify(Secret $secret, string $code, int $timestamp, int $window = 1): ?TotpResult
    {
        $step = $this->counter($timestamp);
        for ($i = -$window; $i <= $window; $i++) {
            $candidate = $this->hotp->compute($secret->toRaw(), $step + $i);
            if (hash_equals($candidate, $code)) {
                return new TotpResult(
                    $candidate,
                    $step + $i,
                    ($step + $i + 1) * $this->parameters->period + $this->parameters->epoch,
                );
            }
        }
        return null;
    }

    public function verifyAt(Secret $secret, string $code, DateTimeInterface $time, int $window = 1): ?TotpResult
    {
        return $this->verify($secret, $code, $time->getTimestamp(), $window);
    }

    public function counter(int $timestamp): int
    {
        return (int) floor(($timestamp - $this->parameters->epoch) / $this->parameters->period);
    }
}
