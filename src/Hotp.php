<?php

declare(strict_types=1);

/**
 * RFC 4226 HMAC-Based One-Time Password calculator.
 *
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Ralf Lang <ralf.lang@ralf-lang.de>
 */

namespace Horde\Otp;

final class Hotp
{
    private readonly HotpParameters $parameters;

    public function __construct(
        ?HotpParameters $parameters = null,
    ) {
        $this->parameters = $parameters ?? new HotpParameters();
    }

    public function generate(Secret $secret, int $counter): HotpResult
    {
        $code = $this->compute($secret->toRaw(), $counter);
        return new HotpResult($code, $counter);
    }

    public function verify(Secret $secret, int $counter, string $code, int $lookAhead = 0): ?HotpResult
    {
        for ($i = 0; $i <= $lookAhead; $i++) {
            $candidate = $this->compute($secret->toRaw(), $counter + $i);
            if (hash_equals($candidate, $code)) {
                return new HotpResult($candidate, $counter + $i);
            }
        }
        return null;
    }

    /**
     * @internal Exposed for Totp to delegate to without constructing HotpResult.
     */
    public function compute(string $rawSecret, int $counter): string
    {
        $packed = pack('J', $counter);
        $hash = hash_hmac(
            $this->parameters->algorithm->value,
            $packed,
            $rawSecret,
            true,
        );
        return $this->truncate($hash);
    }

    private function truncate(string $hash): string
    {
        $offset = ord($hash[strlen($hash) - 1]) & 0x0f;
        $binary = (ord($hash[$offset]) & 0x7f) << 24
            | (ord($hash[$offset + 1]) & 0xff) << 16
            | (ord($hash[$offset + 2]) & 0xff) << 8
            | (ord($hash[$offset + 3]) & 0xff);
        $otp = $binary % (10 ** $this->parameters->digits);
        return str_pad((string) $otp, $this->parameters->digits, '0', STR_PAD_LEFT);
    }
}
