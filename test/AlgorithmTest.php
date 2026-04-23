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
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Algorithm::class)]
class AlgorithmTest extends TestCase
{
    public function testHashLengths(): void
    {
        $this->assertSame(20, Algorithm::Sha1->hashLength());
        $this->assertSame(32, Algorithm::Sha256->hashLength());
        $this->assertSame(64, Algorithm::Sha512->hashLength());
    }

    public function testOtpauthNames(): void
    {
        $this->assertSame('SHA1', Algorithm::Sha1->otpauthName());
        $this->assertSame('SHA256', Algorithm::Sha256->otpauthName());
        $this->assertSame('SHA512', Algorithm::Sha512->otpauthName());
    }

    public function testBackedValues(): void
    {
        $this->assertSame('sha1', Algorithm::Sha1->value);
        $this->assertSame('sha256', Algorithm::Sha256->value);
        $this->assertSame('sha512', Algorithm::Sha512->value);
    }

    public function testFromString(): void
    {
        $this->assertSame(Algorithm::Sha256, Algorithm::from('sha256'));
    }
}
