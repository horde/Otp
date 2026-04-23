<?php

declare(strict_types=1);

/**
 * Immutable shared secret for OTP generation.
 *
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Ralf Lang <ralf.lang@ralf-lang.de>
 */

namespace Horde\Otp;

use Horde\Otp\Exception\InvalidSecretException;

final class Secret
{
    private readonly string $raw;

    public function __construct(string $rawBytes)
    {
        if (strlen($rawBytes) < 16) {
            throw new InvalidSecretException(
                sprintf('Secret must be at least 128 bits (16 bytes), got %d bytes', strlen($rawBytes))
            );
        }
        $this->raw = $rawBytes;
    }

    public static function fromBase32(string $encoded): self
    {
        return new self(Base32::decode($encoded));
    }

    public static function generate(int $bytes = 20): self
    {
        if ($bytes < 16) {
            throw new InvalidSecretException(
                sprintf('Cannot generate secret shorter than 16 bytes, requested %d', $bytes)
            );
        }
        return new self(random_bytes($bytes));
    }

    public static function forAlgorithm(Algorithm $algorithm): self
    {
        return self::generate($algorithm->hashLength());
    }

    public function toRaw(): string
    {
        return $this->raw;
    }

    public function toBase32(): string
    {
        return Base32::encode($this->raw);
    }

    public function length(): int
    {
        return strlen($this->raw);
    }
}
