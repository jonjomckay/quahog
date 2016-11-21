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
    const RESULT_OK = 'OK';
    const RESULT_FOUND = 'FOUND';
    const RESULT_ERROR = 'ERROR';

    /** @var Socket $_socket */
    private $_socket;

    /** @var bool $_inSession Has the current connection a Session? */
    private $_inSession = false;


    /**
     * Instantiate a Quahog\Client instance.
     *
     * @param Socket $socket An instance of \Socket\Raw\Socket which points to clamd
     */
    public function __construct(Socket $socket)
    {
        $this->_socket = $socket;

    }


    /**
     * Ping clamd to see if we get a response.
     *
     * @throws ConnectionException
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
     * Retrieve the running ClamAV version information.
     *
     * @return string
     */
    public function version()
    {
        $this->_sendCommand('VERSION');

        return $this->_receiveResponse();
    }


    /**
     * Fetch stats for the ClamAV scan queue.
     *
     * @return string
     */
    public function stats()
    {
        $this->_sendCommand('STATS');

        return $this->_receiveResponse();
    }


    /**
     * Reload the ClamAV virus definition database.
     *
     * @return string
     */
    public function reload()
    {
        $this->_sendCommand('RELOAD');

        return $this->_receiveResponse();
    }


    /**
     * Shutdown clamd cleanly.
     *
     * @return string
     */
    public function shutdown()
    {
        $this->_sendCommand('SHUTDOWN');

        return $this->_receiveResponse();
    }


    /**
     * Disconnect the client.
     *
     * @return bool
     */
    public function disconnect()
    {
        return $this->_closeConnection();
    }


    /**
     * Scan a single file.
     *
     * @param string $file The location of the file to scan.
     *
     * @return string
     */
    public function scanFile($file)
    {
        $this->_sendCommand('SCAN ' . $file);

        $response = $this->_receiveResponse();

        return $this->_parseResponse($response);
    }


    /**
     * Scan a file or directory recursively using multiple threads.
     *
     * @param string $file The location of the file or directory to scan.
     *
     * @return string
     */
    public function multiscanFile($file)
    {
        $this->_sendCommand('MULTISCAN ' . $file);

        $response = $this->_receiveResponse();

        return $this->_parseResponse($response);
    }


    /**
     * Scan a file or directory recursively.
     *
     * @param string $file The location of the file or directory to scan.
     *
     * @return string
     */
    public function contScan($file)
    {
        $this->_sendCommand('CONTSCAN ' . $file);

        $response = $this->_receiveResponse();

        return $this->_parseResponse($response);
    }


    /**
     * Scan a local file via a stream.
     *
     * @param string $file The location of the file to scan.
     * @param int    $maxChunkSize The maximum chunk size in bytes to send to clamd at a time.
     *
     * @return string
     */
    public function scanLocalFile($file, $maxChunkSize = 1024)
    {
        return $this->scanStream(file_get_contents($file), $maxChunkSize);
    }


    /**
     * Scan a stream.
     *
     * @param resource $stream A file stream in string form.
     * @param int      $maxChunkSize The maximum chunk size in bytes to send to clamd at a time.
     *
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
            $this->_socket->send($size, MSG_DONTROUTE);
            $this->_socket->send($chunk, MSG_DONTROUTE);
        }

        $this->_socket->send(pack('N', 0), MSG_DONTROUTE);

        $response = $this->_receiveResponse();

        return $this->_parseResponse($response);
    }


    /**
     * Scan a stream.
     *
     * @param string $stream A file stream in string form.
     * @param int    $maxChunkSize The maximum chunk size in bytes to send to clamd at a time.
     *
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

        $response = $this->_receiveResponse();

        return $this->_parseResponse($response);
    }


    public function startSession()
    {
        $this->_inSession = true;

        $this->_sendCommand('IDSESSION');
    }


    public function endSession()
    {
        $this->_sendCommand('END');

        $this->_inSession = false;
    }


    /**
     * A wrapper to send a command to clamd.
     *
     * @param string $command
     */
    private function _sendCommand($command)
    {
        $this->_socket->send("n$command\n", MSG_DONTROUTE);
    }


    /**
     * A wrapper to cleanly read a response from clamd.
     *
     * @return string
     */
    private function _receiveResponse()
    {
        $result = $this->_socket->read(4096);

        if (!$this->_inSession) {
            $this->_closeConnection();
        }

        return trim($result);
    }


    /**
     * Explicitly close the current socket's connection.
     *
     * @return bool
     *
     * @throws ConnectionException  If the socket fails to close.
     */
    private function _closeConnection()
    {
        try {
            $this->_socket->close();

            return true;
        } catch (ConnectionException $e) {
            throw $e;
        }
    }


    /**
     * Parse the received response into a structured array ($filename, $reason, $status).
     *
     * @param string $response
     *
     * @return array
     */
    private function _parseResponse($response)
    {
        $splitResponse = explode(': ', $response);

        $idReturn = [];
        if (!$this->_inSession) {
            $filename = $splitResponse[0];
            $message = $splitResponse[1];
        }
        else {
            $idReturn = ['id' => $splitResponse[0]];
            $filename = $splitResponse[1];
            $message = $splitResponse[2];
        }

        if ($message === self::RESULT_OK) {
            return $idReturn + ['filename' => $filename, 'reason' => null, 'status' => self::RESULT_OK];
        } else {
            $parts = explode(' ', $message);
            $status = array_pop($parts);
            $reason = implode(' ', $parts);

            return $idReturn + ['filename' => $filename, 'reason' => $reason, 'status' => $status];
        }
    }
}
