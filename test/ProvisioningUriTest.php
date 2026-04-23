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
use Horde\Otp\ProvisioningUri;
use Horde\Otp\Secret;
use Horde\Otp\TotpParameters;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ProvisioningUri::class)]
class ProvisioningUriTest extends TestCase
{
    private function secret(): Secret
    {
        return new Secret('12345678901234567890');
    }

    public function testTotpDefaultParameters(): void
    {
        $uri = new ProvisioningUri(
            $this->secret(),
            'user@example.com',
            'Horde',
            new TotpParameters(),
        );
        $str = (string) $uri;
        $this->assertStringStartsWith('otpauth://totp/', $str);
        $this->assertStringContainsString('Horde:user%40example.com', $str);
        $this->assertStringContainsString('secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', $str);
        $this->assertStringContainsString('issuer=Horde', $str);
        $this->assertStringNotContainsString('algorithm=', $str);
        $this->assertStringNotContainsString('digits=', $str);
        $this->assertStringNotContainsString('period=', $str);
    }

    public function testTotpNonDefaultParameters(): void
    {
        $uri = new ProvisioningUri(
            $this->secret(),
            'user@example.com',
            'Horde',
            new TotpParameters(Algorithm::Sha256, 8, 60),
        );
        $str = (string) $uri;
        $this->assertStringContainsString('algorithm=SHA256', $str);
        $this->assertStringContainsString('digits=8', $str);
        $this->assertStringContainsString('period=60', $str);
    }

    public function testHotpUri(): void
    {
        $uri = new ProvisioningUri(
            $this->secret(),
            'user@example.com',
            'Horde',
            new HotpParameters(),
            counter: 42,
        );
        $str = (string) $uri;
        $this->assertStringStartsWith('otpauth://hotp/', $str);
        $this->assertStringContainsString('counter=42', $str);
    }

    public function testHotpRequiresCounter(): void
    {
        $this->expectException(OtpException::class);
        new ProvisioningUri(
            $this->secret(),
            'user@example.com',
            'Horde',
            new HotpParameters(),
        );
    }

    public function testSpecialCharactersInLabel(): void
    {
        $uri = new ProvisioningUri(
            $this->secret(),
            'user name@example.com',
            'My Issuer',
            new TotpParameters(),
        );
        $str = (string) $uri;
        $this->assertStringContainsString('My%20Issuer:user%20name%40example.com', $str);
        $this->assertStringContainsString('issuer=My%20Issuer', $str);
    }
}
