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

use Horde\Otp\Base32;
use Horde\Otp\Exception\OtpException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Base32::class)]
class Base32Test extends TestCase
{
    public function testEncodeDecodeRoundtrip(): void
    {
        $data = random_bytes(20);
        $this->assertSame($data, Base32::decode(Base32::encode($data)));
    }

    public function testRfc4648Vectors(): void
    {
        $this->assertSame('', Base32::encode(''));
        $this->assertSame('MY', Base32::encode('f'));
        $this->assertSame('MZXQ', Base32::encode('fo'));
        $this->assertSame('MZXW6', Base32::encode('foo'));
        $this->assertSame('MZXW6YQ', Base32::encode('foob'));
        $this->assertSame('MZXW6YTB', Base32::encode('fooba'));
        $this->assertSame('MZXW6YTBOI', Base32::encode('foobar'));
    }

    public function testDecodeRfc4648Vectors(): void
    {
        $this->assertSame('', Base32::decode(''));
        $this->assertSame('f', Base32::decode('MY======'));
        $this->assertSame('fo', Base32::decode('MZXQ===='));
        $this->assertSame('foo', Base32::decode('MZXW6==='));
        $this->assertSame('foob', Base32::decode('MZXW6YQ='));
        $this->assertSame('fooba', Base32::decode('MZXW6YTB'));
        $this->assertSame('foobar', Base32::decode('MZXW6YTBOI======'));
    }

    public function testDecodeCaseInsensitive(): void
    {
        $this->assertSame('foobar', Base32::decode('mzxw6ytboi'));
    }

    public function testDecodeWithoutPadding(): void
    {
        $this->assertSame('f', Base32::decode('MY'));
    }

    public function testDecodeInvalidCharacterThrows(): void
    {
        $this->expectException(OtpException::class);
        Base32::decode('MFRGG0');
    }

    public function testEncodeKnownSecret(): void
    {
        $encoded = Base32::encode('12345678901234567890');
        $this->assertSame('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', $encoded);
    }

    public function testDecodeKnownSecret(): void
    {
        $decoded = Base32::decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
        $this->assertSame('12345678901234567890', $decoded);
    }
}
