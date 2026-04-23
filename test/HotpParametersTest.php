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
use Horde\Otp\HotpParameters;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(HotpParameters::class)]
class HotpParametersTest extends TestCase
{
    public function testDefaults(): void
    {
        $params = new HotpParameters();
        $this->assertSame(Algorithm::Sha1, $params->algorithm);
        $this->assertSame(6, $params->digits);
    }

    public function testCustomValues(): void
    {
        $params = new HotpParameters(Algorithm::Sha256, 8);
        $this->assertSame(Algorithm::Sha256, $params->algorithm);
        $this->assertSame(8, $params->digits);
    }

    public function testRejectsDigitsTooLow(): void
    {
        $this->expectException(OtpException::class);
        new HotpParameters(digits: 5);
    }

    public function testRejectsDigitsTooHigh(): void
    {
        $this->expectException(OtpException::class);
        new HotpParameters(digits: 9);
    }
}
