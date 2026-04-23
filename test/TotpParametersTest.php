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

namespace Horde\Otp\Test;

use Horde\Otp\Algorithm;
use Horde\Otp\Exception\OtpException;
use Horde\Otp\TotpParameters;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(TotpParameters::class)]
class TotpParametersTest extends TestCase
{
    public function testDefaults(): void
    {
        $params = new TotpParameters();
        $this->assertSame(Algorithm::Sha1, $params->algorithm);
        $this->assertSame(6, $params->digits);
        $this->assertSame(30, $params->period);
        $this->assertSame(0, $params->epoch);
    }

    public function testCustomValues(): void
    {
        $params = new TotpParameters(Algorithm::Sha512, 8, 60, 100);
        $this->assertSame(Algorithm::Sha512, $params->algorithm);
        $this->assertSame(8, $params->digits);
        $this->assertSame(60, $params->period);
        $this->assertSame(100, $params->epoch);
    }

    public function testRejectsDigitsTooLow(): void
    {
        $this->expectException(OtpException::class);
        new TotpParameters(digits: 5);
    }

    public function testRejectsDigitsTooHigh(): void
    {
        $this->expectException(OtpException::class);
        new TotpParameters(digits: 9);
    }

    public function testRejectsZeroPeriod(): void
    {
        $this->expectException(OtpException::class);
        new TotpParameters(period: 0);
    }

    public function testRejectsNegativePeriod(): void
    {
        $this->expectException(OtpException::class);
        new TotpParameters(period: -1);
    }
}
