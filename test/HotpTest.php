<?php

declare(strict_types=1);

/**
 * RFC 4226 Appendix D test vectors.
 *
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Ralf Lang <ralf.lang@ralf-lang.de>
 */

namespace Horde\Otp\Test;

use Horde\Otp\Hotp;
use Horde\Otp\HotpParameters;
use Horde\Otp\HotpResult;
use Horde\Otp\Secret;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(Hotp::class)]
#[CoversClass(HotpResult::class)]
class HotpTest extends TestCase
{
    private static function secret(): Secret
    {
        return new Secret('12345678901234567890');
    }

    /**
     * @return array<int, array{int, string}>
     */
    public static function rfc4226Vectors(): array
    {
        return [
            [0, '755224'],
            [1, '287082'],
            [2, '359152'],
            [3, '969429'],
            [4, '338314'],
            [5, '254676'],
            [6, '287922'],
            [7, '162583'],
            [8, '399871'],
            [9, '520489'],
        ];
    }

    #[DataProvider('rfc4226Vectors')]
    public function testRfc4226AppendixD(int $counter, string $expected): void
    {
        $hotp = new Hotp();
        $result = $hotp->generate(self::secret(), $counter);
        $this->assertSame($expected, $result->code);
        $this->assertSame($counter, $result->counter);
    }

    public function testResultToString(): void
    {
        $hotp = new Hotp();
        $result = $hotp->generate(self::secret(), 0);
        $this->assertSame('755224', (string) $result);
    }

    public function testVerifyExactMatch(): void
    {
        $hotp = new Hotp();
        $result = $hotp->verify(self::secret(), 5, '254676');
        $this->assertNotNull($result);
        $this->assertSame(5, $result->counter);
    }

    public function testVerifyWithLookAhead(): void
    {
        $hotp = new Hotp();
        $result = $hotp->verify(self::secret(), 3, '254676', lookAhead: 5);
        $this->assertNotNull($result);
        $this->assertSame(5, $result->counter);
    }

    public function testVerifyReturnsNullOnMismatch(): void
    {
        $hotp = new Hotp();
        $result = $hotp->verify(self::secret(), 0, '000000');
        $this->assertNull($result);
    }

    public function testVerifyLookAheadBoundary(): void
    {
        $hotp = new Hotp();
        $result = $hotp->verify(self::secret(), 0, '254676', lookAhead: 4);
        $this->assertNull($result);
        $result = $hotp->verify(self::secret(), 0, '254676', lookAhead: 5);
        $this->assertNotNull($result);
    }

    public function test8DigitHotp(): void
    {
        $hotp = new Hotp(new HotpParameters(digits: 8));
        $result = $hotp->generate(self::secret(), 0);
        $this->assertSame(8, strlen($result->code));
    }
}
