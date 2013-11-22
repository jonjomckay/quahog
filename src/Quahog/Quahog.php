<?php
namespace Quahog;


use Socket\Raw\Factory;

class Quahog
{

    const UNIX_SOCKET = 0;
    const NETWORK_SOCKET = 1;

    private $_socket;

    /**
     * @param int $socketType
     * @param string $location
     */
    public function __construct($socketType = self::UNIX_SOCKET, $location)
    {
        $factory = new Factory();

        switch ($socketType) {
            case self::UNIX_SOCKET:
                // TODO: Need to work this out
                break;
            case self::NETWORK_SOCKET:
                break;
            default:
                break;
        }

        $this->_socket = $factory->createClient($location);
    }

    /**
     * @return string
     */
    public function ping()
    {
        $this->_sendCommand('PING');

        return $this->_receiveResponse();
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
     * TODO: Doesn't work - need to find out why
     *
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