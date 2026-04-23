<?php

declare(strict_types=1);

/**
 * Builder for otpauth:// provisioning URIs (Google Authenticator Key URI format).
 *
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Ralf Lang <ralf.lang@ralf-lang.de>
 */

namespace Horde\Otp;

use Horde\Otp\Exception\OtpException;

final class ProvisioningUri
{
    public function __construct(
        private readonly Secret $secret,
        private readonly string $accountName,
        private readonly string $issuer,
        private readonly TotpParameters|HotpParameters $parameters,
        private readonly ?int $counter = null,
    ) {
        if ($parameters instanceof HotpParameters && $counter === null) {
            throw new OtpException('Counter is required for HOTP provisioning URIs');
        }
    }

    public function __toString(): string
    {
        $type = $this->parameters instanceof TotpParameters ? 'totp' : 'hotp';
        $label = rawurlencode($this->issuer) . ':' . rawurlencode($this->accountName);

        $params = [
            'secret' => $this->secret->toBase32(),
            'issuer' => $this->issuer,
        ];

        if ($this->parameters->algorithm !== Algorithm::Sha1) {
            $params['algorithm'] = $this->parameters->algorithm->otpauthName();
        }
        if ($this->parameters->digits !== 6) {
            $params['digits'] = (string) $this->parameters->digits;
        }

        if ($this->parameters instanceof TotpParameters && $this->parameters->period !== 30) {
            $params['period'] = (string) $this->parameters->period;
        }
        if ($this->parameters instanceof HotpParameters) {
            $params['counter'] = (string) $this->counter;
        }

        return 'otpauth://' . $type . '/' . $label . '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }
}
