<?php
namespace Xenolope\Quahog\Tests;

use PHPUnit\Framework\TestCase;
use Socket\Raw\Factory;
use Xenolope\Quahog\Client;

class QuahogITTest extends TestCase
{
    const EICAR = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

    public static function setUpBeforeClass()
    {
        parent::setUpBeforeClass();
        umask(0);
    }

    public function addresses()
    {
        $addresses = [];

        if (isset($_SERVER['CLAM_UNIX_ADDRESS']) && !empty($_SERVER['CLAM_UNIX_ADDRESS'])) {
            $addresses['unix'] = [$_SERVER['CLAM_UNIX_ADDRESS']];
        } else {
            $addresses['unix'] = ['unix:///var/run/clamav/clamd.ctl'];
        }

        if (isset($_SERVER['CLAM_TCP_ADDRESS']) && !empty($_SERVER['CLAM_TCP_ADDRESS'])) {
            $addresses['tcp'] = [$_SERVER['CLAM_TCP_ADDRESS']];
        } else {
            $addresses['tcp'] = ['tcp://127.0.0.1:3310'];
        }

        return $addresses;
    }

    /**
     * @dataProvider addresses
     */
    public function testScanStreamClean($address)
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30, PHP_NORMAL_READ);

        $result = $quahog->scanStream("ABC");
        self::assertSame(
            ['filename' => 'stream', 'reason' => null, 'status' => 'OK'],
            $result
        );
    }

    /**
     * @dataProvider addresses
     */
    public function testScanStreamEicar($address)
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30, PHP_NORMAL_READ);

        $result = $quahog->scanStream(self::EICAR);
        self::assertSame(
            ['filename' => 'stream', 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'],
            $result
        );
    }

    /**
     * @dataProvider addresses
     */
    public function testScanFileClean($address)
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30, PHP_NORMAL_READ);


        $name = $this->createTestFile('ABC');

        try {
            $result = $quahog->scanFile($name);
            self::assertSame(
                ['filename' => $name, 'reason' => null, 'status' => 'OK'],
                $result
            );
        } finally {
            unlink($name);
        }
    }

    /**
     * @dataProvider addresses
     */
    public function testScanFileEicar($address)
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30, PHP_NORMAL_READ);

        $name = $this->createTestFile(self::EICAR);

        try {
            $result = $quahog->scanFile($name);
            self::assertSame(
                ['filename' => $name, 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'],
                $result
            );
        } finally {
            unlink($name);
        }
    }

    /**
     * @dataProvider addresses
     */
    public function testScanResourceEicar($address)
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30, PHP_NORMAL_READ);

        $name = $this->createTestFile(self::EICAR);

        try {
            $result = $quahog->scanResourceStream(fopen($name, "r"));
            self::assertSame(
                ['filename' => 'stream', 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'],
                $result
            );
        } finally {
            unlink($name);
        }
    }

    /**
     * @dataProvider addresses
     */
    public function testScanMultiScanEicar($address)
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30, PHP_NORMAL_READ);

        $name = tempnam(sys_get_temp_dir(), "");
        unlink($name);
        mkdir($name);
        $file1 = $name . DIRECTORY_SEPARATOR . "text";
        $file2 = $name . DIRECTORY_SEPARATOR . "eicar1";
        file_put_contents($file1, "ABC");
        file_put_contents($file2, self::EICAR);
        chmod($name, 0777);
        chmod($file1, 0777);
        chmod($file2, 0777);
        try {
            $result = $quahog->multiscanFile($name);
            self::assertSame(
                ['filename' => $file2, 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'],
                $result
            );
        } finally {
            unlink($file1);
            unlink($file2);
            rmdir($name);
        }
    }

    /**
     * @dataProvider addresses
     */
    public function testScanContScanEicar($address)
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30, PHP_NORMAL_READ);

        $name = tempnam(sys_get_temp_dir(), "");
        unlink($name);
        mkdir($name);
        $file1 = $name . DIRECTORY_SEPARATOR . "text";
        $file2 = $name . DIRECTORY_SEPARATOR . "eicar1";
        file_put_contents($file1, "ABC");
        file_put_contents($file2, self::EICAR);
        chmod($name, 0777);
        chmod($file1, 0777);
        chmod($file2, 0777);
        try {
            $result = $quahog->contScan($name);
            self::assertSame(
                ['filename' => $file2, 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'],
                $result
            );
        } finally {
            unlink($file1);
            unlink($file2);
            rmdir($name);
        }
    }

    /**
     * @dataProvider addresses
     */
    public function testScanStreamSessionEicar($address)
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30, PHP_NORMAL_READ);

        $quahog->startSession();
        $result = $quahog->scanStream(self::EICAR);
        self::assertSame(
            ['id' => '1', 'filename' => "stream", 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'],
            $result
        );
        $result = $quahog->scanStream(self::EICAR);
        self::assertSame(
            ['id' => '2', 'filename' => "stream", 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'],
            $result
        );
        $result = $quahog->scanStream('ABC');
        self::assertSame(
            ['id' => '3', 'filename' => "stream", 'reason' => null, 'status' => 'OK'],
            $result
        );
        $quahog->endSession();
        $quahog->disconnect();
    }

    /**
     * @dataProvider addresses
     */
    public function testStatus($address)
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30, PHP_NORMAL_READ);
        self::assertStringEndsWith("END", $quahog->stats());
    }

    /**
     * @dataProvider addresses
     */
    public function testPing($address)
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30, PHP_NORMAL_READ);
        self::assertTrue($quahog->ping());
    }

    /**
     * @dataProvider addresses
     */
    public function testVersion($address)
    {
        $socket = (new Factory())->createClient($address);
        $quahog = new Client($socket, 30, PHP_NORMAL_READ);
        self::assertNotEmpty($quahog->version());
    }

    /**
     * Creates a physical temporary file and returns the filename
     *
     * @param string $content
     * @return string
     */
    private function createTestFile($content)
    {
        $name = tempnam(sys_get_temp_dir(), "");
        file_put_contents($name, $content);
        chmod($name, 0777);

        return $name;
    }
}
