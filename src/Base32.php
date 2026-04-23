<?php

declare(strict_types=1);

/**
 * RFC 4648 Base32 encoding and decoding.
 *
 * Uses the standard alphabet (A-Z, 2-7). Encodes without padding per the
 * Google Authenticator convention. Decodes case-insensitively, with or
 * without padding.
 *
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Ralf Lang <ralf.lang@ralf-lang.de>
 */

namespace Horde\Otp;

final class Base32
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function encode(string $data): string
    {
        if ($data === '') {
            return '';
        }

        $binary = '';
        foreach (str_split($data) as $char) {
            $binary .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }

        $result = '';
        foreach (str_split($binary, 5) as $chunk) {
            $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            $result .= self::ALPHABET[bindec($chunk)];
        }

        return $result;
    }

    public static function decode(string $data): string
    {
        $data = strtoupper(rtrim($data, "=\n\r\t "));

        if ($data === '') {
            return '';
        }

        $binary = '';
        for ($i = 0, $len = strlen($data); $i < $len; $i++) {
            $pos = strpos(self::ALPHABET, $data[$i]);
            if ($pos === false) {
                throw new Exception\OtpException(
                    sprintf('Invalid Base32 character: %s', $data[$i])
                );
            }
            $binary .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }

        $result = '';
        foreach (str_split($binary, 8) as $byte) {
            if (strlen($byte) < 8) {
                break;
            }
            $result .= chr((int) bindec($byte));
        }

        return $result;
    }
}
