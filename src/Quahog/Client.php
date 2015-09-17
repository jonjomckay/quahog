<?php
namespace Quahog;

use InvalidArgumentException;
use Quahog\Exception\ConnectionException;
use Socket\Raw\Socket;

/**
 * Class Client
 * @package Quahog
 */
class Client
{

    /**
     * @var Socket
     */
    private $socket;

    /**
     * Instantiate a Quahog\Client instance
     *
     * @param Socket $socket An instance of \Socket\Raw\Socket which points to clamd
     */
    public function __construct(Socket $socket)
    {
        $this->socket = $socket;
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

        $response = $this->_receiveResponse();

        return $this->_parseResponse($response);
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

        $response = $this->_receiveResponse();

        return $this->_parseResponse($response);
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

        $response = $this->_receiveResponse();

        return $this->_parseResponse($response);
    }

    /**
     * Scan a stream
     *
     * @param resource $stream A file stream in string form
     * @param int $maxChunkSize The maximum chunk size in bytes to send to clamd at a time
     * @return string
     * @throws InvalidArgumentException
     */
    public function scanResourceStream($stream, $maxChunkSize = 1024)
    {
        if (!is_resource($stream)) {
            throw new InvalidArgumentException('Passed stream is not a resource!');
        }

        $this->_sendCommand("INSTREAM");

        while ($chunk = fread($stream, $maxChunkSize)) {
            $size = pack('N', strlen($chunk));
            $this->socket->send($size, MSG_DONTROUTE);
            $this->socket->send($chunk, MSG_DONTROUTE);
        }

        $this->socket->send(pack('N', 0), MSG_DONTROUTE);

        $response = $this->_receiveResponse();

        return $this->_parseResponse($response);
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

            $this->socket->send($size, MSG_DONTROUTE);
            $this->socket->send($chunk, MSG_DONTROUTE);
        }

        $this->socket->send(pack('N', 0), MSG_DONTROUTE);

        $response = $this->_receiveResponse();

        return $this->_parseResponse($response);
    }

    /**
     * A wrapper to send a command to clamd
     *
     * @param string $command
     */
    private function _sendCommand($command)
    {
        $this->socket->send("n$command\n", MSG_DONTROUTE);
    }

    /**
     * A wrapper to cleanly read a response from clamd
     *
     * @return string
     */
    private function _receiveResponse()
    {
        $result = $this->socket->read(4096);

        $this->socket->close();

        return trim($result);
    }

    /**
     * Parse the received response into a structured array ($filename, $reason, $status)
     *
     * @param string $response
     * @return array
     */
    private function _parseResponse($response)
    {
        $splitResponse = explode(': ', $response);

        $filename = $splitResponse[0];
        $message = $splitResponse[1];

        if ($message === 'OK') {
            return array('filename' => $filename, 'reason' => null, 'status' => 'OK');
        } else {
            $parts = explode(' ', $message);
            $status = array_pop($parts);
            $reason = implode(' ', $parts);

            return array('filename' => $filename, 'reason' => $reason, 'status' => $status);
        }
    }
} 