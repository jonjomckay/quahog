Quahog
======


[![Build Status](https://github.com/jonjomckay/quahog/workflows/Quahog%20Tests/badge.svg)](https://github.com/jonjomckay/quahog/actions)

Quahog is a simple PHP library to interface with the clamd anti-virus daemon. It was written as all of the libraries out
there for interfacing with ClamAV from PHP use ```exec('clamscan')```, which isn't exactly an ideal solution, as
```clamscan``` loads the entire database into memory each time it is run - this doesn't, so it scans a lot (lot!) faster.

## Installation

It is recommended to install Quahog through [composer](http://getcomposer.org).

```JSON
{
    "require": {
        "xenolope/quahog": "3.*"
    }
}
```

## Usage

```php
// Create a new socket instance
$socket = (new \Socket\Raw\Factory())->createClient('unix:///var/run/clamav/clamd.ctl'); # Using a UNIX socket
$socket = (new \Socket\Raw\Factory())->createClient('tcp://192.168.1.1:3310'); # Using a TCP socket

// Create a new instance of the Client
$quahog = new \Xenolope\Quahog\Client($socket);

// Scan a file
$result = $quahog->scanFile('/tmp/virusfile');

// Scan a file or directory recursively
$result = $quahog->contScan('/tmp/virusdirectory');

// Scan a file or directory recursively using multiple threads
$result = $quahog->multiscanFile('/tmp/virusdirectory');

// Scan a stream, and optionally pass the maximum chunk size in bytes
$result = $quahog->scanStream(file_get_contents('/tmp/virusfile'), 1024);

// Scan multiple files in a row
$quahog->startSession();
$result = $quahog->scanFile('/tmp/virusfile');
$result2 = $quahog->scanFile('/tmp/virusfile2');
$quahog->endSession();

// Ping clamd
$result = $quahog->ping();

// Get ClamAV version details
$result = $quahog->version();

// View statistics about the ClamAV scan queue
$result = $quahog->stats();

// Reload the virus database
$quahog->reload();

// Shutdown clamd cleanly
$quahog->shutdown();

```

### Working with the result

``` php
// Result is an instance of \Xenolope\Quahog\Result.
$result = $quahog->scanFile('/tmp/virusfile');

// A result id of a session that was used.
$result->getId();

// The file name of the scanned file.
$result->getFilename();

// The reason why a scan resulted in a failure. Returns null if the scan was successful.
$result->getReason();

// A boolean value that is true, in case the scan was successful.
$result->isOk();

// A boolean value that is true, in case the scan failed. This is the opposite of isOk().
$result->hasFailed();

// A boolean value that is true, if a virus was found.
$result->isFound();

// A boolean value that is true, if an error happened.
$result->isError();
```

## Testing

To run the test suite you will need PHPUnit installed. Go to the project root and run:
````bash
$ phpunit
````

## License

Quahog is released under the [MIT License](http://www.opensource.org/licenses/MIT)
