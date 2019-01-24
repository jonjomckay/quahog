<?php

declare(strict_types = 1);

namespace Xenolope\Quahog\Tests;

use PHPUnit\Framework\TestCase;
use Xenolope\Quahog\Result;

class ResultTest extends TestCase
{
    public function testCleanResult(): void
    {
        $result = new Result('OK', 'filename', null, null);

        self::assertSame('filename', $result->getFilename());
        self::assertTrue($result->ok());
        self::assertNull($result->getId());
        self::assertNull($result->getReason());
        self::assertFalse($result->error());
        self::assertFalse($result->found());
    }

    public function testVirusFound(): void
    {
        $result = new Result('FOUND', 'filename', 'evilvirus', '1');

        self::assertSame('filename', $result->getFilename());
        self::assertSame('evilvirus', $result->getReason());
        self::assertSame('1', $result->getId());
        self::assertFalse($result->ok());
        self::assertTrue($result->failed());
        self::assertFalse($result->error());
        self::assertTrue($result->found());
    }

    public function testError(): void
    {
        $result = new Result('ERROR', 'filename', 'broken', '1');

        self::assertSame('filename', $result->getFilename());
        self::assertSame('broken', $result->getReason());
        self::assertSame('1', $result->getId());
        self::assertFalse($result->ok());
        self::assertTrue($result->failed());
        self::assertTrue($result->error());
        self::assertFalse($result->found());
    }

    public function testUndefinedFailure(): void
    {
        $result = new Result('WHAT', 'filename', 'text', '1');

        self::assertSame('filename', $result->getFilename());
        self::assertSame('text', $result->getReason());
        self::assertSame('1', $result->getId());
        self::assertFalse($result->ok());
        self::assertTrue($result->failed());
        self::assertFalse($result->error());
        self::assertFalse($result->found());
    }
}
