<?php
namespace Xenolope\Quahog\Tests;


class QuahogITTest extends \PHPUnit_Framework_TestCase {
    const EICAR = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STAND' . 'ARD-ANTIVIRUS-TEST-FILE!$H+H*';
    protected $address = 'unix:///var/run/clamav/clamd.ctl';

    public function setUp() {
        parent::setUp();
        if (isset($_SERVER['CLAM_UNIX_ADDRESS'])) {
            $this->address = $_SERVER['CLAM_UNIX_ADDRESS'];
        }
    }

    public function addresses() {
        $addresses = [];
        if (array_key_exists('CLAM_UNIX_ADDRESS', $_SERVER)) {
            if (!empty($_SERVER['CLAM_UNIX_ADDRESS'])) {
                $addresses['unix'] = [$_SERVER['CLAM_UNIX_ADDRESS']];
            }
        } else {
            $addresses['unix'] = ['unix:///var/run/clamav/clamd.ctl'];
        }
        if (array_key_exists('CLAM_TCP_ADDRESS', $_SERVER)) {
            if (!empty($_SERVER['CLAM_TCP_ADDRESS'])) {
                $addresses['tcp'] = [$_SERVER['CLAM_TCP_ADDRESS']];
            }
        } else {
            $addresses['tcp'] = ['tcp://127.0.0.1:3310'];
        }

        return $addresses;
    }

    /** @dataProvider addresses */
    public function testScanStreamClean($address) {
        $socket = (new \Socket\Raw\Factory())->createClient($address);
        $quahog = new \Xenolope\Quahog\Client($socket);

        $result = $quahog->scanStream("ABC");
        $this->assertSame(
            ['filename' => 'stream', 'reason' => null, 'status' => 'OK'],
            $result
        );
    }

    /** @dataProvider addresses */
    public function testScanStreamEicar($address) {
        $socket = (new \Socket\Raw\Factory())->createClient($address);
        $quahog = new \Xenolope\Quahog\Client($socket);

        $result = $quahog->scanStream(self::EICAR);
        $this->assertSame(
            ['filename' => 'stream', 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'],
            $result
        );
    }

    /** @dataProvider addresses */
    public function testScanFileClean($address) {
        $socket = (new \Socket\Raw\Factory())->createClient($address);
        $quahog = new \Xenolope\Quahog\Client($socket);


        $name = tempnam(sys_get_temp_dir(), "");
        file_put_contents($name, "ABC");

        try {
            $result = $quahog->scanFile($name);
            $this->assertSame(
                ['filename' => $name, 'reason' => null, 'status' => 'OK'],
                $result
            );
        } finally {
            unlink($name);
        }
    }

    /** @dataProvider addresses */
    public function testScanFileEicar($address) {
        $socket = (new \Socket\Raw\Factory())->createClient($address);
        $quahog = new \Xenolope\Quahog\Client($socket);

        $name = tempnam(sys_get_temp_dir(), "");
        file_put_contents($name, self::EICAR);

        try {
            $result = $quahog->scanFile($name);
            $this->assertSame(
                ['filename' => $name, 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'],
                $result
            );
        } finally {
            unlink($name);
        }
    }

    /** @dataProvider addresses */
    public function testScanStreamSessionEicar($address) {
        $socket = (new \Socket\Raw\Factory())->createClient($address);
        $quahog = new \Xenolope\Quahog\Client($socket);

        $quahog->startSession();
        $result = $quahog->scanStream(self::EICAR);
        $this->assertSame(
            ['id' => '1', 'filename' => "stream", 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'],
            $result
        );
        $result = $quahog->scanStream(self::EICAR);
        $this->assertSame(
            ['id' => '2', 'filename' => "stream", 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'],
            $result
        );
        $result = $quahog->scanStream('ABC');
        $this->assertSame(
            ['id' => '3', 'filename' => "stream", 'reason' => null, 'status' => 'OK'],
            $result
        );
        $quahog->endSession();
    }
}
