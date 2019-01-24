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

    public function __construct(string $status, string $filename, ?string $reason, ?string $id)
    {
        $this->status   = $status;
        $this->filename = $filename;
        $this->reason   = $reason;
        $this->id       = $id;
    }

    /**
     * @return string
     */
    public function getId(): ?string
    {
        return $this->id;
    }

    /**
     * @return string
     */
    public function getFilename(): string
    {
        return $this->filename;
    }

    /**
     * @return null|string
     */
    public function getReason(): ?string
    {
        return $this->reason;
    }

    /**
     * @return bool
     */
    public function ok(): bool
    {
        return $this->status === self::RESULT_OK;
    }

    /**
     * @return bool
     */
    public function failed(): bool
    {
        return $this->status !== self::RESULT_OK;
    }

    /**
     * @return bool
     */
    public function found(): bool
    {
        return $this->status === self::RESULT_FOUND;
    }

    /**
     * @return bool
     */
    public function error(): bool
    {
        return $this->status === self::RESULT_ERROR;
    }
}