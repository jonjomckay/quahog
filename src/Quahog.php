<?php
namespace Quahog;


use Socket\Raw\Factory;

class Quahog
{

    const UNIX_SOCKET = 0;
    const NETWORK_SOCKET = 1;

    private $_socket;

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

    public function ping()
    {
        $this->_sendCommand('PING');

        return $this->_receiveResponse();
    }

    public function version()
    {
        $this->_sendCommand('VERSION');

        return $this->_receiveResponse();
    }

    // TODO: Doesn't work - need to find out why
    public function stats()
    {
        $this->_sendCommand('STATS');

        return $this->_receiveResponse();
    }

    public function reload()
    {
        $this->_sendCommand('RELOAD');

        return $this->_receiveResponse();
    }

    private function _sendCommand($command)
    {
        $this->_socket->send($command, MSG_EOR);
    }

    private function _receiveResponse()
    {
        $result = $this->_socket->read(4096);

        $this->_socket->close();

        return $result;
    }
} 