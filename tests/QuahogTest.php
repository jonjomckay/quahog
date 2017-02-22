<?php

namespace Xenolope\Quahog\Tests;

use Socket\Raw\Socket;
use Xenolope\Quahog\Client;
use org\bovigo\vfs\vfsStream;
use org\bovigo\vfs\vfsStreamDirectory;
use Xenolope\Quahog\Exception\ConnectionException;

class QuahogTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \Socket\Raw\Socket|\PHPUnit_Framework_MockObject_MockObject
     */
    private $socket;

    /**
     * @var Client|\PHPUnit_Framework_MockObject_MockObject
     */
    private $quahog;

    /**
     * @var vfsStreamDirectory
     */
    private $root;

    public function setUp()
    {
        $this->socket = $this->getMockBuilder(Socket::class)->disableOriginalConstructor()->getMock();
        $this->quahog = new Client($this->socket, 30, PHP_NORMAL_READ);
        $this->root = vfsStream::setup('tmp');
    }

    public function testPingOK()
    {
        $this->socket->expects($this->once())->method('selectRead')->willReturn(true);
        $this->socket->expects($this->any())->method('read')->will($this->returnValue("PONG\n"));

        $result = $this->quahog->ping();

        $this->assertTrue($result);
    }

    public function testPingFail()
    {
        $this->setExpectedException(ConnectionException::class);

        $this->socket->expects($this->once())->method('selectRead')->willReturn(true);
        $this->socket->expects($this->any())->method('read')->will($this->returnValue(''));

        $result = $this->quahog->ping();

        $this->assertTrue($result);
    }

    public function testVersion()
    {
        $this->socket->expects($this->once())->method('selectRead')->willReturn(true);
        $this->socket->expects($this->any())->method('read')->will($this->returnValue("ClamAV 1.2.3\n"));

        $result = $this->quahog->version();

        $this->assertStringStartsWith('ClamAV', $result);
    }

    public function testStats()
    {
        $this->socket->expects($this->any())->method('selectRead')->will($this->onConsecutiveCalls(true, true, true, false));
        $this->socket->expects($this->any())->method('read')->will($this->onConsecutiveCalls("POOLS:\n", "BLA\n", "END\n"));

        $result = $this->quahog->stats();

        $this->assertStringStartsWith('POOLS:', $result);
    }

    public function testReload()
    {
        $this->socket->expects($this->once())->method('selectRead')->willReturn(true);
        $this->socket->expects($this->any())->method('read')->will($this->returnValue("RELOADING\n"));

        $result = $this->quahog->reload();

        $this->assertSame('RELOADING', $result);
    }

    public function testScanFile()
    {
        $this->socket->expects($this->once())->method('selectRead')->willReturn(true);
        $this->socket->expects($this->any())->method('read')->will(
            $this->returnValue("/tmp/EICAR: Eicar-Test-Signature FOUND\n")
        );

        $result = $this->quahog->scanFile('/tmp/EICAR');

        $this->assertSame(
            array('filename' => '/tmp/EICAR', 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'),
            $result
        );
    }

    public function testMultiscanFile()
    {
        $this->socket->expects($this->once())->method('selectRead')->willReturn(true);
        $this->socket->expects($this->any())->method('read')->will(
            $this->returnValue("/tmp/quahog/EICAR: Eicar-Test-Signature FOUND\n")
        );

        $result = $this->quahog->multiscanFile('/tmp/quahog');

        $this->assertSame('Eicar-Test-Signature', $result['reason']);
        $this->assertSame('FOUND', $result['status']);
    }

    public function testContScan()
    {
        $this->socket->expects($this->once())->method('selectRead')->willReturn(true);
        $this->socket->expects($this->any())->method('read')->will(
            $this->returnValue("/tmp/quahog/EICAR: Eicar-Test-Signature FOUND\n")
        );

        $result = $this->quahog->contScan('/tmp/quahog');

        $this->assertSame(
            ['filename' => '/tmp/quahog/EICAR', 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'],
            $result
        );
    }

    public function testScanLocalFile()
    {
        $file = vfsStream::newFile('EICAR')
            ->withContent('/tmp/EICAR: Eicar-Test-Signature FOUND')
            ->at($this->root);

        $this->socket->expects($this->once())->method('selectRead')->willReturn(true);
        $this->socket->expects($this->any())->method('read')->will(
            $this->returnValue($file->url() . ": Eicar-Test-Signature FOUND\n")
        );

        $result = $this->quahog->scanLocalFile($file->url());

        $this->assertSame(
            ['filename' => $file->url(), 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'],
            $result
        );
    }

    public function testScanStream()
    {
        $this->socket->expects($this->once())->method('selectRead')->willReturn(true);
        $this->socket->expects($this->any())->method('read')->will(
            $this->returnValue("stream: Eicar-Test-Signature FOUND\n")
        );

        $result = $this->quahog->scanStream('stream');

        $this->assertSame(
            ['filename' => 'stream', 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'],
            $result
        );
    }

    public function testShutdown()
    {
        $this->socket->expects($this->once())->method('selectRead')->willReturn(true);
        $this->socket->expects($this->any())->method('read')->will($this->returnValue(''));
        $result = $this->quahog->shutdown();

        $this->assertSame('', $result);
    }

    public function testSession() {
        $this->socket->expects($this->any())->method('close')->willThrowException(new \Exception("Closed connection!"));
        $this->socket->expects($this->any())->method('selectRead')->will($this->onConsecutiveCalls(true, true, true, true, false));
        $this->socket->expects($this->any())->method('send')
            ->withConsecutive([$this->equalTo("nIDSESSION\n"), $this->anything()],
                [$this->equalTo("nVERSION\n"), $this->anything()],
                [$this->equalTo("nSTATS\n"), $this->anything()]);
        $this->socket->expects($this->any())->method('read')->will($this->onConsecutiveCalls("1: bla\n", "2: bla\n", "bla\n", "END\n"));

        $this->quahog->startSession();

        self::assertEquals('bla', $this->quahog->version());
        self::assertEquals("bla\nbla\nEND", $this->quahog->stats());

        $this->quahog->endSession();
    }
}
