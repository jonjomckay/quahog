<?php

declare(strict_types=1);

namespace Xenolope\Quahog\Tests;

use PHPUnit\Framework\TestCase;
use Socket\Raw\Factory;
use Xenolope\Quahog\Client;

use function assert;
use function chmod;
use function file_put_contents;
use function fopen;
use function is_resource;
use function is_string;
use function mkdir;
use function rmdir;
use function sys_get_temp_dir;
use function tempnam;
use function umask;
use function unlink;

use const DIRECTORY_SEPARATOR;

class QuahogITTest extends TestCase
{
    public const EICAR = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        umask(0);
    }

    /** @return array<string, list<string>> */
    public function addresses(): array
    {
        $addresses = [];

        if (isset($_SERVER['CLAM_UNIX_ADDRESS']) && ! empty($_SERVER['CLAM_UNIX_ADDRESS'])) {
            $addresses['unix'] = [$_SERVER['CLAM_UNIX_ADDRESS']];
        } else {
            $addresses['unix'] = ['unix:///var/run/clamav/clamd.ctl'];
        }

        if (isset($_SERVER['CLAM_TCP_ADDRESS']) && ! empty($_SERVER['CLAM_TCP_ADDRESS'])) {
            $addresses['tcp'] = [$_SERVER['CLAM_TCP_ADDRESS']];
        } else {
            $addresses['tcp'] = ['tcp://127.0.0.1:3310'];
        }

        return $addresses;
    }

    /** @dataProvider addresses */
    public function testScanStreamClean(string $address): void
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30);

        $result = $quahog->scanStream('ABC');

        self::assertSame('stream', $result->getFilename());
        self::assertNull($result->getReason());
        self::assertTrue($result->isOk());
    }

    /** @dataProvider addresses */
    public function testScanStreamEicar(string $address): void
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30);

        $result = $quahog->scanStream(self::EICAR);

        self::assertSame('stream', $result->getFilename());
        self::assertSame('Win.Test.EICAR_HDB-1', $result->getReason());
        self::assertTrue($result->isFound());
    }

    /** @dataProvider addresses */
    public function testScanFileClean(string $address): void
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30);

        $name = $this->createTestFile('ABC');

        try {
            $result = $quahog->scanFile($name);

            self::assertSame($name, $result->getFilename());
            self::assertNull($result->getReason());
            self::assertTrue($result->isOk());
        } finally {
            unlink($name);
        }
    }

    /** @dataProvider addresses */
    public function testScanFileEicar(string $address): void
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30);

        $name = $this->createTestFile(self::EICAR);

        try {
            $result = $quahog->scanFile($name);

            self::assertSame($name, $result->getFilename());
            self::assertSame('Win.Test.EICAR_HDB-1', $result->getReason());
            self::assertTrue($result->isFound());
        } finally {
            unlink($name);
        }
    }

    /** @dataProvider addresses */
    public function testScanResourceEicar(string $address): void
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30);

        $name = $this->createTestFile(self::EICAR);

        try {
            $fileRessource = fopen($name, 'r');
            assert(is_resource($fileRessource));
            $result = $quahog->scanResourceStream($fileRessource);

            self::assertSame('stream', $result->getFilename());
            self::assertSame('Win.Test.EICAR_HDB-1', $result->getReason());
            self::assertTrue($result->isFound());
        } finally {
            unlink($name);
        }
    }

    /** @dataProvider addresses */
    public function testScanMultiScanEicar(string $address): void
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30);

        $name = tempnam(sys_get_temp_dir(), '');
        assert(is_string($name));
        unlink($name);
        mkdir($name);
        $file1 = $name . DIRECTORY_SEPARATOR . 'text';
        $file2 = $name . DIRECTORY_SEPARATOR . 'eicar1';
        file_put_contents($file1, 'ABC');
        file_put_contents($file2, self::EICAR);
        chmod($name, 0777);
        chmod($file1, 0777);
        chmod($file2, 0777);
        try {
            $result = $quahog->multiscanFile($name);

            self::assertSame($file2, $result->getFilename());
            self::assertSame('Win.Test.EICAR_HDB-1', $result->getReason());
            self::assertTrue($result->isFound());
        } finally {
            unlink($file1);
            unlink($file2);
            rmdir($name);
        }
    }

    /** @dataProvider addresses */
    public function testScanContScanEicar(string $address): void
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30);

        $name = tempnam(sys_get_temp_dir(), '');
        assert(is_string($name));
        unlink($name);
        mkdir($name);
        $file1 = $name . DIRECTORY_SEPARATOR . 'text';
        $file2 = $name . DIRECTORY_SEPARATOR . 'eicar1';
        file_put_contents($file1, 'ABC');
        file_put_contents($file2, self::EICAR);
        chmod($name, 0777);
        chmod($file1, 0777);
        chmod($file2, 0777);
        try {
            $result = $quahog->contScan($name);

            self::assertSame($file2, $result->getFilename());
            self::assertSame('Win.Test.EICAR_HDB-1', $result->getReason());
            self::assertTrue($result->isFound());
        } finally {
            unlink($file1);
            unlink($file2);
            rmdir($name);
        }
    }

    /** @dataProvider addresses */
    public function testScanStreamSessionEicar(string $address): void
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30);

        $quahog->startSession();
        $result = $quahog->scanStream(self::EICAR);

        self::assertSame('stream', $result->getFilename());
        self::assertSame('Win.Test.EICAR_HDB-1', $result->getReason());
        self::assertSame('1', $result->getId());
        self::assertTrue($result->isFound());

        $result = $quahog->scanStream(self::EICAR);
        self::assertSame('stream', $result->getFilename());
        self::assertSame('Win.Test.EICAR_HDB-1', $result->getReason());
        self::assertSame('2', $result->getId());
        self::assertTrue($result->isFound());

        $result = $quahog->scanStream('ABC');
        self::assertSame('stream', $result->getFilename());
        self::assertSame('3', $result->getId());
        self::assertTrue($result->isOk());

        $quahog->endSession();
        $quahog->disconnect();
    }

    /** @dataProvider addresses */
    public function testStatus(string $address): void
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30);
        self::assertStringEndsWith('END', $quahog->stats());
    }

    /** @dataProvider addresses */
    public function testPing(string $address): void
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30);
        self::assertTrue($quahog->ping());
    }

    /** @dataProvider addresses */
    public function testVersion(string $address): void
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30);
        self::assertNotEmpty($quahog->version());
    }

    /**
     * Creates a physical temporary file and returns the filename
     */
    private function createTestFile(string $content): string
    {
        $name = tempnam(sys_get_temp_dir(), '');
        assert(is_string($name));
        file_put_contents($name, $content);
        chmod($name, 0777);

        return $name;
    }
}
