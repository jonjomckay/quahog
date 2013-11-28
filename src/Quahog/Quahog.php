<?php
namespace Quahog;


use Quahog\Exception\ConnectionException;
use Socket\Raw\Factory;

/**
 * Class Quahog
 * @package Quahog
 */
class Quahog
{

    /**
     * @var \Socket\Raw\Socket
     */
    private $_socket;

    /**
     * Instantiate a Quahog\Quahog instance
     *
     * @param string $location The hostname and port, or socket location to connect to clamd
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
     * Ping clamd to see if we get a response
     *
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
     * Retrieve the running ClamAV version information
     *
     * @return string
     */
    public function version()
    {
        $this->_sendCommand('VERSION');

        return $this->_receiveResponse();
    }

    /**
     * Fetch stats for the ClamAV scan queue
     *
     * @return string
     */
    public function stats()
    {
        $this->_sendCommand('STATS');

        return $this->_receiveResponse();
    }

    /**
     * Reload the ClamAV virus definition database
     *
     * @return string
     */
    public function reload()
    {
        $this->_sendCommand('RELOAD');

        return $this->_receiveResponse();
    }

    /**
     * Shutdown clamd cleanly
     *
     * @return string
     */
    public function shutdown()
    {
        $this->_sendCommand('SHUTDOWN');

        return $this->_receiveResponse();
    }

    /**
     * Scan a single file
     *
     * @param string $file The location of the file to scan
     * @return string
     */
    public function scanFile($file)
    {
        $this->_sendCommand('SCAN ' . $file);

        return $this->_receiveResponse();
    }

    /**
     * Scan a file or directory recursively using multiple threads
     *
     * @param string $file The location of the file or directory to scan
     * @return string
     */
    public function multiscanFile($file)
    {
        $this->_sendCommand('MULTISCAN ' . $file);

        return $this->_receiveResponse();
    }

    /**
     * Scan a file or directory recursively
     *
     * @param string $file The location of the file or directory to scan
     * @return string
     */
    public function contScan($file)
    {
        $this->_sendCommand('CONTSCAN ' . $file);

        return $this->_receiveResponse();
    }

    /**
     * Scan a stream
     *
     * @param string $stream A file stream in string form
     * @param int $maxChunkSize The maximum chunk size in bytes to send to clamd at a time
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
     * A wrapper to send a command to clamd
     *
     * @param string $command
     */
    private function _sendCommand($command)
    {
        $this->_socket->send("n$command\n", MSG_DONTROUTE);
    }

    /**
     * A wrapper to cleanly read a response from clamd
     *
     * @return string
     */
    private function _receiveResponse()
    {
        $result = $this->_socket->read(4096);

        $this->_socket->close();

        return trim($result);
    }
} 