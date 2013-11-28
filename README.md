Quahog
======

Quahog is a simple PHP library to interface with the clamd anti-virus daemon. It was written as all of the libraries out
there for interfacing with ClamAV from PHP use ```exec('clamscan')```, which isn't exactly an ideal solution, as
```clamscan``` loads the entire database into memory each time it is run - this doesn't, so it scans a lot (lot!) faster.

## Installation

It is recommended to install Quahog through [composer](http://getcomposer.org).

```JSON
{
    "require": {
        "blurgroup/quahog": "0.*"
    }
}
```

## Usage

```php
$quahog = new \Quahog\Quahog();

// Scanning a file
$result = $quahog->scanFile('/tmp/virusfile');

// $result will contain "/tmp/virusfile: OK" if clean or "/tmp/virusfile: Virus-Information" if infected
```

## Testing

To run the test suite you will need PHPUnit installed. Go to the project root and run:
````bash
$ phpunit
````