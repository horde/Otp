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
use Horde\Otp\Base32;
use Horde\Otp\Exception\InvalidSecretException;
use Horde\Otp\Secret;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Secret::class)]
class SecretTest extends TestCase
{
    public function testConstructFromRawBytes(): void
    {
        $raw = str_repeat('a', 20);
        $secret = new Secret($raw);
        $this->assertSame($raw, $secret->toRaw());
        $this->assertSame(20, $secret->length());
    }

    public function testRejectsShortSecret(): void
    {
        $this->expectException(InvalidSecretException::class);
        new Secret('short');
    }

    public function testMinimum16Bytes(): void
    {
        $secret = new Secret(str_repeat('x', 16));
        $this->assertSame(16, $secret->length());
    }

    public function testFromBase32(): void
    {
        $raw = '12345678901234567890';
        $encoded = Base32::encode($raw);
        $secret = Secret::fromBase32($encoded);
        $this->assertSame($raw, $secret->toRaw());
    }

    public function testToBase32Roundtrip(): void
    {
        $secret = new Secret('12345678901234567890');
        $encoded = $secret->toBase32();
        $decoded = Base32::decode($encoded);
        $this->assertSame($secret->toRaw(), $decoded);
    }

    public function testGenerate(): void
    {
        $secret = Secret::generate(32);
        $this->assertSame(32, $secret->length());
    }

    public function testGenerateDefaultIs20Bytes(): void
    {
        $secret = Secret::generate();
        $this->assertSame(20, $secret->length());
    }

    public function testGenerateRejectsShortLength(): void
    {
        $this->expectException(InvalidSecretException::class);
        Secret::generate(8);
    }

    public function testForAlgorithm(): void
    {
        $this->assertSame(20, Secret::forAlgorithm(Algorithm::Sha1)->length());
        $this->assertSame(32, Secret::forAlgorithm(Algorithm::Sha256)->length());
        $this->assertSame(64, Secret::forAlgorithm(Algorithm::Sha512)->length());
    }
}
