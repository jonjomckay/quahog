<?php
namespace Quahog;


use Quahog\Exception\ConnectionException;
use Socket\Raw\Factory;

class Quahog
{

    private $_socket;

    /**
     * @param string $location
     * @throws Exception\ConnectionException
     */
    public function __construct($location)
    {
        $factory = new Factory();

        try {
            $this->_socket = $factory->createClient($location);
        } catch (\Exception $e) {
            throw new ConnectionException('Could not connect to to socket at: ' . $location);
        }
    }

    /**
     * @throws Exception\ConnectionException
     * @return bool
     */
    public function ping()
    {
        $this->_sendCommand('PING');

        if ($this->_receiveResponse() === 'PONG') {
            return true;
        }

        throw new ConnectionException('Could not ping clamd');
    }

    /**
     * @return string
     */
    public function version()
    {
        $this->_sendCommand('VERSION');

        return $this->_receiveResponse();
    }

    /**
     * @return string
     */
    public function stats()
    {
        $this->_sendCommand('STATS');

        return $this->_receiveResponse();
    }

    /**
     * @return string
     */
    public function reload()
    {
        $this->_sendCommand('RELOAD');

        return $this->_receiveResponse();
    }

    /**
     * @return string
     */
    public function shutdown()
    {
        $this->_sendCommand('SHUTDOWN');

        return $this->_receiveResponse();
    }

    /**
     * @param string $file
     * @return string
     */
    public function scanFile($file)
    {
        $this->_sendCommand('SCAN ' . $file);

        return $this->_receiveResponse();
    }

    /**
     * @param string $file
     * @return string
     */
    public function multiscanFile($file)
    {
        $this->_sendCommand('MULTISCAN ' . $file);

        return $this->_receiveResponse();
    }

    /**
     * @param string $file
     * @return string
     */
    public function contScan($file)
    {
        $this->_sendCommand('CONTSCAN ' . $file);

        return $this->_receiveResponse();
    }

    /**
     * @param $stream
     * @param int $maxChunkSize
     * @return string
     */
    public function scanStream($stream, $maxChunkSize = 1024)
    {
        $this->_sendCommand("INSTREAM");

        $chunksLeft = $stream;

        while (strlen($chunksLeft) > 0) {
            $chunk = substr($chunksLeft, 0, $maxChunkSize);
            $chunksLeft = substr($chunksLeft, $maxChunkSize);

            $size = pack('N', strlen($chunk));

            $this->_socket->send($size, MSG_DONTROUTE);
            $this->_socket->send($chunk, MSG_DONTROUTE);
        }

        $this->_socket->send(pack('N', 0), MSG_DONTROUTE);

        return $this->_receiveResponse();
    }

    /**
     * @param string $command
     */
    private function _sendCommand($command)
    {
        $this->_socket->send("n$command\n", MSG_DONTROUTE);
    }

    /**
     * @return string
     */
    private function _receiveResponse()
    {
        $result = $this->_socket->read(4096);

        $this->_socket->close();

        return trim($result);
    }
} 