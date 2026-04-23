<?php

declare(strict_types=1);

/**
 * RFC 6238 Appendix B test vectors.
 *
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Ralf Lang <ralf.lang@ralf-lang.de>
 */

namespace Horde\Otp\Test;

use DateTimeImmutable;
use DateTimeZone;
use Horde\Otp\Algorithm;
use Horde\Otp\Secret;
use Horde\Otp\Totp;
use Horde\Otp\TotpParameters;
use Horde\Otp\TotpResult;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(Totp::class)]
#[CoversClass(TotpResult::class)]
class TotpTest extends TestCase
{
    private static function sha1Secret(): Secret
    {
        return new Secret('12345678901234567890');
    }

    private static function sha256Secret(): Secret
    {
        return new Secret('12345678901234567890123456789012');
    }

    private static function sha512Secret(): Secret
    {
        return new Secret('1234567890123456789012345678901234567890123456789012345678901234');
    }

    /**
     * @return array<string, array{Algorithm, Secret, int, string}>
     */
    public static function rfc6238Vectors(): array
    {
        $sha1 = new Secret('12345678901234567890');
        $sha256 = new Secret('12345678901234567890123456789012');
        $sha512 = new Secret('1234567890123456789012345678901234567890123456789012345678901234');

        return [
            'sha1-59' => [Algorithm::Sha1, $sha1, 59, '94287082'],
            'sha256-59' => [Algorithm::Sha256, $sha256, 59, '46119246'],
            'sha512-59' => [Algorithm::Sha512, $sha512, 59, '90693936'],
            'sha1-1111111109' => [Algorithm::Sha1, $sha1, 1111111109, '07081804'],
            'sha256-1111111109' => [Algorithm::Sha256, $sha256, 1111111109, '68084774'],
            'sha512-1111111109' => [Algorithm::Sha512, $sha512, 1111111109, '25091201'],
            'sha1-1111111111' => [Algorithm::Sha1, $sha1, 1111111111, '14050471'],
            'sha256-1111111111' => [Algorithm::Sha256, $sha256, 1111111111, '67062674'],
            'sha512-1111111111' => [Algorithm::Sha512, $sha512, 1111111111, '99943326'],
            'sha1-1234567890' => [Algorithm::Sha1, $sha1, 1234567890, '89005924'],
            'sha256-1234567890' => [Algorithm::Sha256, $sha256, 1234567890, '91819424'],
            'sha512-1234567890' => [Algorithm::Sha512, $sha512, 1234567890, '93441116'],
            'sha1-2000000000' => [Algorithm::Sha1, $sha1, 2000000000, '69279037'],
            'sha256-2000000000' => [Algorithm::Sha256, $sha256, 2000000000, '90698825'],
            'sha512-2000000000' => [Algorithm::Sha512, $sha512, 2000000000, '38618901'],
            'sha1-20000000000' => [Algorithm::Sha1, $sha1, 20000000000, '65353130'],
            'sha256-20000000000' => [Algorithm::Sha256, $sha256, 20000000000, '77737706'],
            'sha512-20000000000' => [Algorithm::Sha512, $sha512, 20000000000, '47863826'],
        ];
    }

    #[DataProvider('rfc6238Vectors')]
    public function testRfc6238AppendixB(Algorithm $algo, Secret $secret, int $time, string $expected): void
    {
        $totp = new Totp(new TotpParameters($algo, 8));
        $result = $totp->generate($secret, $time);
        $this->assertSame($expected, $result->code);
    }

    public function testCounter(): void
    {
        $totp = new Totp();
        $this->assertSame(1, $totp->counter(59));
        $this->assertSame(37037036, $totp->counter(1111111109));
    }

    public function testGenerateAt(): void
    {
        $totp = new Totp(new TotpParameters(Algorithm::Sha1, 8));
        $dt = new DateTimeImmutable('@59');
        $result = $totp->generateAt(self::sha1Secret(), $dt);
        $this->assertSame('94287082', $result->code);
    }

    public function testResultSecondsRemaining(): void
    {
        $totp = new Totp();
        $result = $totp->generate(self::sha1Secret(), 59);
        $this->assertSame(1, $result->secondsRemaining(59));
        $this->assertSame(0, $result->secondsRemaining(60));
    }

    public function testResultExpiresAt(): void
    {
        $totp = new Totp();
        $result = $totp->generate(self::sha1Secret(), 59);
        $this->assertSame(60, $result->expiresAt);
    }

    public function testResultToString(): void
    {
        $totp = new Totp(new TotpParameters(Algorithm::Sha1, 8));
        $result = $totp->generate(self::sha1Secret(), 59);
        $this->assertSame('94287082', (string) $result);
    }

    public function testVerifyExactMatch(): void
    {
        $totp = new Totp(new TotpParameters(Algorithm::Sha1, 8));
        $result = $totp->verify(self::sha1Secret(), '94287082', 59);
        $this->assertNotNull($result);
        $this->assertSame(1, $result->timeStep);
    }

    public function testVerifyWithWindow(): void
    {
        $totp = new Totp(new TotpParameters(Algorithm::Sha1, 8));
        $result = $totp->verify(self::sha1Secret(), '94287082', 61, window: 1);
        $this->assertNotNull($result);
    }

    public function testVerifyReturnsNullOnMismatch(): void
    {
        $totp = new Totp(new TotpParameters(Algorithm::Sha1, 8));
        $result = $totp->verify(self::sha1Secret(), '00000000', 59);
        $this->assertNull($result);
    }

    public function testVerifyAt(): void
    {
        $totp = new Totp(new TotpParameters(Algorithm::Sha1, 8));
        $dt = new DateTimeImmutable('@59');
        $result = $totp->verifyAt(self::sha1Secret(), '94287082', $dt);
        $this->assertNotNull($result);
    }

    public function testCustomPeriod(): void
    {
        $totp = new Totp(new TotpParameters(period: 60));
        $this->assertSame(0, $totp->counter(59));
        $this->assertSame(1, $totp->counter(60));
    }

    public function testCustomEpoch(): void
    {
        $totp = new Totp(new TotpParameters(epoch: 30));
        $this->assertSame(0, $totp->counter(30));
        $this->assertSame(0, $totp->counter(59));
        $this->assertSame(1, $totp->counter(60));
    }
}
