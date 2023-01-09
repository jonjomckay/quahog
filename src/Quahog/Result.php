<?php

declare(strict_types=1);

namespace Xenolope\Quahog;

class Result
{
    private const RESULT_OK    = 'OK';
    private const RESULT_FOUND = 'FOUND';
    private const RESULT_ERROR = 'ERROR';

    public function __construct(private string $status, private string $filename, private string|null $reason = null, private string|null $id = null)
    {
    }

    /**
     * Returns a result id of a session was used.
     */
    public function getId(): string|null
    {
        return $this->id;
    }

    /**
     * Returns the filename of the scanned file.
     */
    public function getFilename(): string
    {
        return $this->filename;
    }

    /**
     * Returns an explanation in case the scan found a virus or an error.
     */
    public function getReason(): string|null
    {
        return $this->reason;
    }

    /**
     * Returns true if no errors and no virus are found.
     */
    public function isOk(): bool
    {
        return $this->status === self::RESULT_OK;
    }

    /**
     * Returns true if errors or a virus are found.
     */
    public function hasFailed(): bool
    {
        return $this->status !== self::RESULT_OK;
    }

    /**
     * Returns true if a virus was found.
     */
    public function isFound(): bool
    {
        return $this->status === self::RESULT_FOUND;
    }

    /**
     * Returns true if an error was found.
     */
    public function isError(): bool
    {
        return $this->status === self::RESULT_ERROR;
    }
}
