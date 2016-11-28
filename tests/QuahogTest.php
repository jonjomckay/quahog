<?php

namespace Blurgroup\Quahog\Tests;

use Blurgroup\Quahog\Client;
use org\bovigo\vfs\vfsStream;
use org\bovigo\vfs\vfsStreamDirectory;

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
        $this->socket = $this->getMockBuilder('Socket\Raw\Socket')->disableOriginalConstructor()->getMock();
        $this->quahog = new Client($this->socket);
        $this->root = vfsStream::setup('tmp');
    }

    public function testPingOK()
    {
        $this->socket->expects($this->any())->method('read')->will($this->returnValue('PONG'));

        $result = $this->quahog->ping();

        $this->assertTrue($result);
    }

    public function testPingFail()
    {
        $this->setExpectedException('Blurgroup\Quahog\Exception\ConnectionException');

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
            $this->returnValue('/tmp/EICAR: Eicar-Test-Signature FOUND')
        );

        $result = $this->quahog->scanFile('/tmp/EICAR');

        $this->assertSame(
            array('filename' => '/tmp/EICAR', 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'),
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
            ['filename' => '/tmp/quahog/EICAR', 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'],
            $result
        );
    }

    public function testScanLocalFile()
    {
        $file = vfsStream::newFile('EICAR')
            ->withContent('/tmp/EICAR: Eicar-Test-Signature FOUND')
            ->at($this->root);

        $this->socket->expects($this->any())->method('read')->will(
            $this->returnValue($file->url() . ': Eicar-Test-Signature FOUND')
        );

        $result = $this->quahog->scanLocalFile($file->url());

        $this->assertSame(
            ['filename' => $file->url(), 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'],
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
            ['filename' => 'stream', 'reason' => 'Eicar-Test-Signature', 'status' => 'FOUND'],
            $result
        );
    }

    public function testShutdown()
    {
        $result = $this->quahog->shutdown();

        $this->assertSame('', $result);
    }
}
