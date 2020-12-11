pragma solidity ^0.5.16;

import './TownCrier.sol';

contract Application {
    // event TestApp(bytes4 callback, bytes32[] req_data, uint msg_value, uint tc_fee);
    event TestApp(uint msg_value);
    event DebugApp(string msg);
    event Request(int64 requestId, address requester, uint dataLength, bytes32[] data); // log for requests
    // event Response(int64 requestId, address requester, uint64 error, bytes32[] data); // log for responses
    event Response(int64 requestId, address requester, uint64 error, bytes32 data); // log for responses
    event Cancel(uint64 requestId, address requester, bool success); // log for cancellations

    uint constant MIN_GAS = 30000 + 20000; // minimum gas required for a query
    uint constant GAS_PRICE = 5 * 10 ** 10;
    uint constant TC_FEE = MIN_GAS * GAS_PRICE;
    uint constant CANCELLATION_FEE = 25000 * GAS_PRICE;

    // (DCMMC) response 函数的签名，i.e., 0x91ba4ee0
    // bytes4 constant TC_CALLBACK_FID = bytes4(keccak256("response(uint64,uint64,bytes32[])"));
    bytes4 constant TC_CALLBACK_FID = bytes4(keccak256("response(uint64,uint64,bytes32)"));

    TownCrier public TC_CONTRACT;
    address owner; // creator of this contract
    mapping(uint => address) requesters;
    mapping(uint => uint) fee;

    function() external payable {} // must be payable

    constructor(TownCrier tcCont) public {
        TC_CONTRACT = tcCont; // storing the address of the TownCrier Contract
        owner = msg.sender;
    }

    function request(uint8 requestType, bytes32[] memory requestData) public payable {
        if (msg.value < TC_FEE) {
            // The requester paid less fee than required.
            // Reject the request and refund the requester.
            (bool ret,) = msg.sender.call.value(msg.value)("");
            assert(ret);
            emit Request(-1, msg.sender, requestData.length, requestData);
            return;
        }

        int requestId = TC_CONTRACT.request.value(msg.value)(requestType, address(this), TC_CALLBACK_FID, 0, requestData); // calling request() in the TownCrier Contract
        if (requestId <= 0) {
            // The request fails.
            // Refund the requester.
            (bool ret,) = msg.sender.call.value(msg.value)("");
            assert(ret);
            emit Request(-2, msg.sender, requestData.length, requestData);
            return;
        }

        // Successfully sent a request to TC.
        // Record the request.
        requesters[uint(requestId)] = msg.sender;
        fee[uint(requestId)] = msg.value;
        emit Request(int64(requestId), msg.sender, requestData.length, requestData);
    }

    // function response(uint64 requestId, uint64 error, bytes32[] memory respData) public {
    function response(uint64 requestId, uint64 error, bytes32 respData) public {
        /* emit DebugApp("enter response"); */
        if (msg.sender != address(TC_CONTRACT)) {
            // If the message sender is not the TownCrier Contract,
            // discard the response.
            // bytes32[] memory empty;
            bytes32 empty = 0;
            emit Response(-1, msg.sender, 0, empty);
            return;
        }

        address requester = requesters[requestId];
        requesters[requestId] = address(0); // set the request as responded

        if (error < 2) {
            emit Response(int64(requestId), requester, error, respData);
        } else {
            (bool ret,) = requester.call.value(fee[requestId])(""); // refund the requester if error exists in TC
            assert(ret);
            // bytes32[] memory empty;
            bytes32 empty = 0;
            emit Response(int64(requestId), msg.sender, error, empty);
        }
        /* emit DebugApp("response done"); */
    }

    function cancel(uint64 requestId) public {
        if (requestId == 0 || requesters[requestId] != msg.sender) {
            // If the requestId is invalid or the requester is not the message sender,
            // cancellation fails.
            emit Cancel(requestId, msg.sender, false);
            return;
        }

        int tcCancel = TC_CONTRACT.cancel(requestId); // calling cancel() in the TownCrier Contract
        if (tcCancel == 1) {
            // Successfully cancels the request in the TownCrier Contract,
            // then refund the requester with (fee - cancellation fee).
            requesters[requestId] = address(0);
            (bool ret,) = msg.sender.call.value(fee[requestId] - CANCELLATION_FEE)("");
            assert(ret);
            emit Cancel(requestId, msg.sender, true);
        } else {
            // Cancellation in the TownCrier Contract fails.
            emit Cancel(requestId, msg.sender, false);
        }
    }

    function test(bytes32[] memory req) public payable {
        // emit TestApp(TC_CALLBACK_FID, req, msg.value, TC_FEE);
        emit TestApp(msg.value);
    }
}

