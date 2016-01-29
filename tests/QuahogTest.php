<?php
use Quahog\Client;

include_once __DIR__ . '/../vendor/autoload.php';
include_once __DIR__ . '/function_overrides.php';

/**
 * Class QuahogTest
 */
class QuahogTest extends \PHPUnit_Framework_TestCase
{

    /**
     * @var \Socket\Raw\Socket|\PHPUnit_Framework_MockObject_MockObject
     */
    private $socket;

    /**
     * @var \Quahog\Client|\PHPUnit_Framework_MockObject_MockObject
     */
    private $quahog;

    public function setUp()
    {
        $this->socket = $this->getMockBuilder('Socket\Raw\Socket')->disableOriginalConstructor()->getMock();
        $this->quahog = new Client($this->socket);
    }

    public function testPingOK()
    {
        $this->socket->expects($this->any())->method('read')->will($this->returnValue('PONG'));

        $result = $this->quahog->ping();

        $this->assertTrue($result);
    }

    public function testPingFail()
    {
        $this->setExpectedException('Quahog\Exception\ConnectionException');

        $this->socket->expects($this->any())->method('read')->will($this->returnValue(null));

        $result = $this->quahog->ping();

        $this->assertTrue($result);
    }

    public function testVersion()
    {
        $this->socket->expects($this->any())->method('read')->will($this->returnValue('ClamAV 1.2.3'));

        $result = $this->quahog->version();

        $this->assertStringStartsWith('ClamAV', $result);
    }

    public function testStats()
    {
        $this->socket->expects($this->any())->method('read')->will($this->returnValue('POOLS:'));

        $result = $this->quahog->stats();

        $this->assertStringStartsWith('POOLS:', $result);
    }

    public function testReload()
    {
        $this->socket->expects($this->any())->method('read')->will($this->returnValue('RELOADING'));

        $result = $this->quahog->reload();

        $this->assertSame('RELOADING', $result);
    }

    public function testScanFile()
    {
        $this->socket->expects($this->any())->method('read')->will(
            $this->returnValue('/tmp/quahog/EICAR: Eicar-Test-Signature FOUND')
        );

        $result = $this->quahog->scanFile('/tmp/quahog/EICAR');

        $this->assertSame(
            array('filename' => '/tmp/quahog/EICAR', 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'),
            $result
        );
    }

    public function testMultiscanFile()
    {
        $this->socket->expects($this->any())->method('read')->will(
            $this->returnValue('/tmp/quahog/EICAR: Eicar-Test-Signature FOUND')
        );

        $result = $this->quahog->multiscanFile('/tmp/quahog');

        $this->assertSame('Eicar-Test-Signature', $result['reason']);
        $this->assertSame('FOUND', $result['status']);
    }

    public function testContScan()
    {
        $this->socket->expects($this->any())->method('read')->will(
            $this->returnValue('/tmp/quahog/EICAR: Eicar-Test-Signature FOUND')
        );

        $result = $this->quahog->contScan('/tmp/quahog');

        $this->assertSame(
            array('filename' => '/tmp/quahog/EICAR', 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'),
            $result
        );
    }

    public function testScanLocalFile()
    {
        $file = tmpfile();
        fwrite($file, 'Some test text to scan.');
        $fileMeta = stream_get_meta_data($file);

        $this->socket->expects($this->any())->method('read')->will(
            $this->returnValue($fileMeta['uri'] . ': Eicar-Test-Signature FOUND')
        );

        $result = $this->quahog->scanLocalFile($fileMeta['uri']);

        fclose($file);

        $this->assertSame(
            array('filename' => $fileMeta['uri'], 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'),
            $result
        );
    }

    public function testScanStream()
    {
        $this->socket->expects($this->any())->method('read')->will(
            $this->returnValue('stream: Eicar-Test-Signature FOUND')
        );

        $result = $this->quahog->scanStream('stream');

        $this->assertSame(
            array('filename' => 'stream', 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'),
            $result
        );
    }

    public function testScanResource()
    {
        $this->socket->expects($this->any())->method('read')->will(
          $this->returnValue('stream: Eicar-Test-Signature FOUND')
        );

        $file = tmpFile();
        fwrite($file, 'Some test text to scan.');

        $result = $this->quahog->scanResource($file, 2);

        fclose($file);

        $this->assertSame(
          array('filename' => 'stream', 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'),
          $result
        );
    }

    public function testShutdown()
    {
        $result = $this->quahog->shutdown();

        $this->assertSame('', $result);
    }
}
