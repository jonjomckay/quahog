<?php

declare(strict_types=1);

namespace Xenolope\Quahog;

use InvalidArgumentException;
use Socket\Raw\Socket;
use Xenolope\Quahog\Exception\ConnectionException;

use function array_pop;
use function assert;
use function explode;
use function file_get_contents;
use function fread;
use function implode;
use function is_resource;
use function is_string;
use function pack;
use function preg_replace;
use function sprintf;
use function strcmp;
use function strlen;
use function substr;
use function trim;

use const MSG_DONTROUTE;
use const PHP_EOL;
use const PHP_NORMAL_READ;

class Client
{
    private const RESULT_OK = 'OK';

    /** Has the current connection a Session? */
    private bool $inSession = false;

    /** Read timeout */
    private int $timeout;

    /** Read timeout */
    private int $mode;

    /**
     * Instantiate a Quahog\Client instance.
     */
    public function __construct(private Socket $socket, int $timeout = 30, int $mode = PHP_NORMAL_READ)
    {
        $this->mode    = $mode;
        $this->timeout = $timeout;
    }

    /**
     * Ping clamd to see if we get a response.
     *
     * @throws ConnectionException
     */
    public function ping(): bool
    {
        $this->sendCommand('PING');

        if ($this->receiveResponse(true) === 'PONG') {
            return true;
        }

        throw new ConnectionException('Could not ping clamd');
    }

    /**
     * Retrieve the running ClamAV version information.
     */
    public function version(): string
    {
        $this->sendCommand('VERSION');

        return $this->receiveResponse(true);
    }

    /**
     * Fetch stats for the ClamAV scan queue.
     */
    public function stats(): string
    {
        $this->sendCommand('STATS');

        return $this->receiveResponse(true, "END\n");
    }

    /**
     * Reload the ClamAV virus definition database.
     */
    public function reload(): string
    {
        $this->sendCommand('RELOAD');

        return $this->receiveResponse();
    }

    /**
     * Shutdown clamd cleanly.
     */
    public function shutdown(): string
    {
        $this->sendCommand('SHUTDOWN');

        return $this->receiveResponse();
    }

    /**
     * Disconnect the client.
     */
    public function disconnect(): void
    {
        $this->socket->close();
    }

    /**
     * Scan a single file.
     *
     * @param string $file The location of the file to scan.
     */
    public function scanFile(string $file): Result
    {
        $this->sendCommand('SCAN ' . $file);

        $response = $this->receiveResponse();

        return $this->parseResponse($response);
    }

    /**
     * Scan a file or directory recursively using multiple threads.
     *
     * @param string $file The location of the file or directory to scan.
     */
    public function multiscanFile(string $file): Result
    {
        $this->sendCommand('MULTISCAN ' . $file);

        $response = $this->receiveResponse();

        return $this->parseResponse($response);
    }

    /**
     * Scan a file or directory recursively.
     *
     * @param string $file The location of the file or directory to scan.
     */
    public function contScan(string $file): Result
    {
        $this->sendCommand('CONTSCAN ' . $file);

        $response = $this->receiveResponse();

        return $this->parseResponse($response);
    }

    /**
     * Scan a local file via a stream.
     *
     * @param string $file         The location of the file to scan.
     * @param int    $maxChunkSize The maximum chunk size in bytes to send to clamd at a time.
     */
    public function scanLocalFile(string $file, int $maxChunkSize = 1024): Result
    {
        $fileContent = file_get_contents($file);
        assert($fileContent !== false);

        return $this->scanStream($fileContent, $maxChunkSize);
    }

    /**
     * Scan a stream.
     *
     * @param resource    $stream       A file stream
     * @param int<0, max> $maxChunkSize The maximum chunk size in bytes to send to clamd at a time.
     *
     * @throws InvalidArgumentException
     */
    public function scanResourceStream($stream, int $maxChunkSize = 1024): Result
    {
        if (! is_resource($stream)) {
            throw new InvalidArgumentException('Passed stream is not a resource!');
        }

        $this->sendCommand('INSTREAM');

        while ($chunk = fread($stream, $maxChunkSize)) {
            $size = pack('N', strlen($chunk));
            $this->socket->send($size, MSG_DONTROUTE);
            $this->socket->send($chunk, MSG_DONTROUTE);
        }

        $this->socket->send(pack('N', 0), MSG_DONTROUTE);

        $response = $this->receiveResponse();

        return $this->parseResponse($response);
    }

    /**
     * Scan a stream.
     *
     * @param string $stream       A file stream in string form.
     * @param int    $maxChunkSize The maximum chunk size in bytes to send to clamd at a time.
     */
    public function scanStream(string $stream, int $maxChunkSize = 1024): Result
    {
        $this->sendCommand('INSTREAM');

        $chunksLeft = $stream;

        while (strlen($chunksLeft) > 0) {
            $chunk      = substr($chunksLeft, 0, $maxChunkSize);
            $chunksLeft = substr($chunksLeft, $maxChunkSize);

            $size = pack('N', strlen($chunk));

            $this->socket->send($size, MSG_DONTROUTE);
            $this->socket->send($chunk, MSG_DONTROUTE);
        }

        $this->socket->send(pack('N', 0), MSG_DONTROUTE);

        $response = $this->receiveResponse();

        return $this->parseResponse($response);
    }

    public function startSession(): void
    {
        $this->inSession = true;

        $this->sendCommand('IDSESSION');
    }

    public function endSession(): void
    {
        $this->sendCommand('END');

        $this->inSession = false;
    }

    /**
     * A wrapper to send a command to clamd.
     */
    private function sendCommand(string $command): void
    {
        $this->socket->send(sprintf('n%s%s', $command, PHP_EOL), MSG_DONTROUTE);
    }

    /**
     * A wrapper to cleanly read a response from clamd.
     *
     * @throws ConnectionException
     */
    private function receiveResponse(bool $removeId = false, string $readUntil = PHP_EOL): string
    {
        $result       = '';
        $readUntilLen = strlen($readUntil);
        do {
            if ($this->socket->selectRead($this->timeout)) {
                $rt = $this->socket->read(4096, $this->mode);
                if ($rt === '') {
                    break;
                }

                $result .= $rt;
                if (strcmp(substr($result, 0 - $readUntilLen), $readUntil) === 0) {
                    break;
                }
            } elseif ($this->mode === PHP_NORMAL_READ) {
                throw new ConnectionException('Timeout waiting to read response');
            }

            break;
        } while (true);

        if (! $this->inSession) {
            $this->disconnect();
        } elseif ($removeId) {
            $result = preg_replace('/^\d+: /', '', $result, 1);
            assert(is_string($result));
        }

        return trim($result);
    }

    /**
     * Parse the received response into a structured array ($filename, $reason, $status).
     */
    private function parseResponse(string $response): Result
    {
        $splitResponse = explode(': ', $response);

        $id = null;
        if (! $this->inSession) {
            $filename = $splitResponse[0];
            $message  = $splitResponse[1];
        } else {
            $id       = $splitResponse[0];
            $filename = $splitResponse[1];
            $message  = $splitResponse[2];
        }

        if ($message === self::RESULT_OK) {
            return new Result(self::RESULT_OK, $filename, null, $id);
        }

        $parts  = explode(' ', $message);
        $status = array_pop($parts);
        $reason = implode(' ', $parts);

        return new Result($status, $filename, $reason, $id);
    }
}
