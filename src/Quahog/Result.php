<?php

declare(strict_types = 1);

namespace Xenolope\Quahog;

class Result
{
    private const RESULT_OK    = 'OK';
    private const RESULT_FOUND = 'FOUND';
    private const RESULT_ERROR = 'ERROR';

    /**
     * @var string
     */
    private $id;

    /**
     * @var string
     */
    private $filename;

    /**
     * @var string|null
     */
    private $reason;

    /**
     * @var string
     */
    private $status;

    /**
     * @param string      $status
     * @param string      $filename
     * @param null|string $reason
     * @param null|string $id
     */
    public function __construct(string $status, string $filename, ?string $reason, ?string $id)
    {
        $this->status   = $status;
        $this->filename = $filename;
        $this->reason   = $reason;
        $this->id       = $id;
    }

    /**
     * Returns a result id of a session was used.
     *
     * @return null|string
     */
    public function getId(): ?string
    {
        return $this->id;
    }

    /**
     * Returns the filename of the scanned file.
     *
     * @return string
     */
    public function getFilename(): string
    {
        return $this->filename;
    }

    /**
     * Returns an explanation in case the scan found a virus or an error.
     *
     * @return null|string
     */
    public function getReason(): ?string
    {
        return $this->reason;
    }

    /**
     * Returns true if no errors and no virus are found.
     *
     * @return bool
     */
    public function isOk(): bool
    {
        return $this->status === self::RESULT_OK;
    }

    /**
     * Returns true if errors or a virus are found.
     *
     * @return bool
     */
    public function hasFailed(): bool
    {
        return $this->status !== self::RESULT_OK;
    }

    /**
     * Returns true if a virus was found.
     *
     * @return bool
     */
    public function isFound(): bool
    {
        return $this->status === self::RESULT_FOUND;
    }

    /**
     * Returns true if an error was found.
     *
     * @return bool
     */
    public function isError(): bool
    {
        return $this->status === self::RESULT_ERROR;
    }
}