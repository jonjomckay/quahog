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
        self::assertTrue($result->isOk());
        self::assertNull($result->getId());
        self::assertNull($result->getReason());
        self::assertFalse($result->isError());
        self::assertFalse($result->isFound());
    }

    public function testVirusFound(): void
    {
        $result = new Result('FOUND', 'filename', 'evilvirus', '1');

        self::assertSame('filename', $result->getFilename());
        self::assertSame('evilvirus', $result->getReason());
        self::assertSame('1', $result->getId());
        self::assertFalse($result->isOk());
        self::assertTrue($result->hasFailed());
        self::assertFalse($result->isError());
        self::assertTrue($result->isFound());
    }

    public function testError(): void
    {
        $result = new Result('ERROR', 'filename', 'broken', '1');

        self::assertSame('filename', $result->getFilename());
        self::assertSame('broken', $result->getReason());
        self::assertSame('1', $result->getId());
        self::assertFalse($result->isOk());
        self::assertTrue($result->hasFailed());
        self::assertTrue($result->isError());
        self::assertFalse($result->isFound());
    }

    public function testUndefinedFailure(): void
    {
        $result = new Result('WHAT', 'filename', 'text', '1');

        self::assertSame('filename', $result->getFilename());
        self::assertSame('text', $result->getReason());
        self::assertSame('1', $result->getId());
        self::assertFalse($result->isOk());
        self::assertTrue($result->hasFailed());
        self::assertFalse($result->isError());
        self::assertFalse($result->isFound());
    }
}
