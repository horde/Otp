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

namespace Horde\Otp;

enum Algorithm: string
{
    case Sha1 = 'sha1';
    case Sha256 = 'sha256';
    case Sha512 = 'sha512';

    public function hashLength(): int
    {
        return match ($this) {
            self::Sha1 => 20,
            self::Sha256 => 32,
            self::Sha512 => 64,
        };
    }

    public function otpauthName(): string
    {
        return match ($this) {
            self::Sha1 => 'SHA1',
            self::Sha256 => 'SHA256',
            self::Sha512 => 'SHA512',
        };
    }
}
